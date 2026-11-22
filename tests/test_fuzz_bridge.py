"""
Hermetic Unit & Integration Tests for AIxCC Upgrade #3 (`engine/fuzz_bridge.py`).
================================================================================
Covers:
1. Multi-language repo & build-target detection (Rust, C/C++, Python, JS/TS, Java, polyglot)
2. Harness, initial seed corpus, and libFuzzer/AFL++ dictionary generation with Cairn HINT absorption
3. Optional LLM/arbiter synthesis + deterministic AST/grammar fallback
4. Isolated Docker container argument hardening (`--network=none`, `--cap-drop=ALL`, `shell=False`,
   bounded CPU/RAM/PIDs, zero shell metacharacter / mount-escape injection)
5. Real sanitizer crash log & coverage-plateau parsing (ASan, UBSan, Rust panic, Atheris, Jazzer JVM/JS,
   AFL++, LibAFL) -> deduplicated Cairn Blackboard `FACT` & `INTENT` persistence in SQLite `blackboard_nodes`
6. Clean skip provenance (`skipped_docker_unavailable`, `skipped_toolchain_unavailable`) & CLI hook safety
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from database import Database
from engine.fuzz_bridge import (
    DEFAULT_DOCKER_IMAGES,
    FuzzBridgeConfig,
    FuzzLanguage,
    LLMFuzzBridge,
    detect_coverage_plateau,
    detect_repo_fuzz_targets,
    parse_coverage_progression,
    parse_sanitizer_output,
    run_fuzz_bridge_scan,
    validate_docker_fuzz_command,
)


# ---------------------------------------------------------------------------
# Sample Repository Builders (Real Multi-Language Source Trees)
# ---------------------------------------------------------------------------

def _create_rust_repo(base: Path) -> Path:
    repo = base / "rust_parser_crate"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "Cargo.toml").write_text(
        '[package]\nname = "http_frame_rs"\nversion = "0.1.0"\nedition = "2021"\n',
        encoding="utf-8",
    )
    (repo / "src" / "lib.rs").write_text(
        'pub fn parse_chunk_header(input: &[u8]) -> Option<usize> {\n'
        '    if input.starts_with(b"Transfer-Encoding") {\n'
        '        return Some(input.len());\n'
        '    }\n'
        '    None\n'
        '}\n'
        'pub fn helper_version() -> &\'static str { "HTTP/1.1" }\n',
        encoding="utf-8",
    )
    return repo


def _create_cpp_repo(base: Path) -> Path:
    repo = base / "cpp_codec_repo"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\nproject(WireCodec)\nadd_library(wirecodec src/decoder.cpp)\n",
        encoding="utf-8",
    )
    (repo / "Makefile").write_text("all:\n\t$(CXX) -c src/decoder.cpp\n", encoding="utf-8")
    (repo / "src" / "decoder.cpp").write_text(
        '#include <cstddef>\n#include <cstdint>\n'
        'int parse_wire_packet(const uint8_t *buf, size_t len) {\n'
        '    const char *magic = "WIRE_HDR_V2";\n'
        '    return (len > 4 && buf[0] == magic[0]) ? 1 : 0;\n'
        '}\n',
        encoding="utf-8",
    )
    return repo


def _create_python_repo(base: Path) -> Path:
    repo = base / "py_rfc_pkg"
    (repo / "rfcparser").mkdir(parents=True, exist_ok=True)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "rfcparser"\nversion = "0.2.0"\n',
        encoding="utf-8",
    )
    (repo / "rfcparser" / "__init__.py").write_text("", encoding="utf-8")
    (repo / "rfcparser" / "framing.py").write_text(
        'MAGIC_HDR = "Content-Length"\n'
        'CHUNK_TOKEN = "chunked"\n\n'
        'def parse_http_frame(raw_data: bytes) -> dict:\n'
        '    text = raw_data.decode("utf-8", errors="ignore")\n'
        '    if MAGIC_HDR in text and CHUNK_TOKEN in text:\n'
        '        return {"conflict": True}\n'
        '    return {"conflict": False}\n\n'
        'def _internal_helper(x: int) -> int:\n'
        '    return x + 1\n',
        encoding="utf-8",
    )
    return repo


def _create_js_ts_repo(base: Path) -> Path:
    repo = base / "ts_gateway_repo"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "package.json").write_text(
        json.dumps({"name": "gateway-parser", "version": "1.0.0", "main": "src/index.js"}),
        encoding="utf-8",
    )
    (repo / "tsconfig.json").write_text('{"compilerOptions": {"strict": true}}\n', encoding="utf-8")
    (repo / "src" / "index.ts").write_text(
        'export function decodeRequestHeader(payload: string): boolean {\n'
        '  return payload.includes("X-Forwarded-Proto") || payload.includes("Upgrade");\n'
        '}\n'
        'export const normalizePath = (p: string) => p.trim();\n',
        encoding="utf-8",
    )
    return repo


def _create_java_repo(base: Path) -> Path:
    repo = base / "java_proxy_repo"
    src_dir = repo / "src" / "main" / "java" / "com" / "acme" / "proxy"
    src_dir.mkdir(parents=True, exist_ok=True)
    (repo / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><artifactId>acme-http-proxy</artifactId></project>\n",
        encoding="utf-8",
    )
    (src_dir / "FrameParser.java").write_text(
        "package com.acme.proxy;\n\n"
        "public class FrameParser {\n"
        "    public static int parseHeaderLine(String line) {\n"
        '        if (line != null && line.contains("Proxy-Connection")) {\n'
        "            return line.length();\n"
        "        }\n"
        "        return 0;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return repo


def _create_polyglot_repo(base: Path) -> Path:
    repo = base / "polyglot_monorepo"
    (repo / "rust" / "src").mkdir(parents=True, exist_ok=True)
    (repo / "rust" / "Cargo.toml").write_text('[package]\nname = "poly_rs"\nversion = "0.1.0"\n', encoding="utf-8")
    (repo / "rust" / "src" / "lib.rs").write_text("pub fn decode_rust(b: &[u8]) -> usize { b.len() }\n", encoding="utf-8")

    (repo / "cpp").mkdir(parents=True, exist_ok=True)
    (repo / "cpp" / "CMakeLists.txt").write_text("project(PolyCpp)\n", encoding="utf-8")
    (repo / "cpp" / "parser.c").write_text("int parse_c_buf(const char *s) { return s != 0; }\n", encoding="utf-8")

    (repo / "py").mkdir(parents=True, exist_ok=True)
    (repo / "py" / "codec.py").write_text("def decode_py(data: bytes):\n    return len(data)\n", encoding="utf-8")

    (repo / "web").mkdir(parents=True, exist_ok=True)
    (repo / "web" / "package.json").write_text('{"name":"poly-web","main":"index.js"}', encoding="utf-8")
    (repo / "web" / "index.js").write_text("exports.parseJs = function(s) { return s.length; };\n", encoding="utf-8")

    (repo / "jvm").mkdir(parents=True, exist_ok=True)
    (repo / "jvm" / "build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
    (repo / "jvm" / "Parser.java").write_text(
        "public class Parser { public static void parseJava(String s) {} }\n", encoding="utf-8"
    )

    # Ignored directories must not pollute results
    (repo / "node_modules" / "dep").mkdir(parents=True, exist_ok=True)
    (repo / "node_modules" / "dep" / "ignored.py").write_text("def should_not_appear(): pass\n", encoding="utf-8")
    return repo


# ---------------------------------------------------------------------------
# 1. Multi-Language Detection Tests
# ---------------------------------------------------------------------------

def test_detect_languages_across_all_five_ecosystems(tmp_path: Path) -> None:
    rust_targets = detect_repo_fuzz_targets(_create_rust_repo(tmp_path))
    assert len(rust_targets) == 1
    assert rust_targets[0].language == FuzzLanguage.RUST.value
    assert rust_targets[0].backend == "cargo-fuzz"
    assert rust_targets[0].engine == "libFuzzer"
    assert rust_targets[0].package_name == "http_frame_rs"
    assert "parse_chunk_header" in rust_targets[0].entry_symbols
    assert "Transfer-Encoding" in rust_targets[0].extracted_tokens

    cpp_targets = detect_repo_fuzz_targets(_create_cpp_repo(tmp_path), cpp_backend="afl++")
    assert len(cpp_targets) == 1
    assert cpp_targets[0].language == FuzzLanguage.C_CPP.value
    assert cpp_targets[0].backend == "afl++"
    assert cpp_targets[0].build_system == "cmake"
    assert cpp_targets[0].package_name == "WireCodec"
    assert "parse_wire_packet" in cpp_targets[0].entry_symbols
    assert "address" in cpp_targets[0].sanitizers and "undefined" in cpp_targets[0].sanitizers

    cpp_libafl = detect_repo_fuzz_targets(tmp_path / "cpp_codec_repo", cpp_backend="libafl")
    assert cpp_libafl[0].backend == "libafl"
    assert cpp_libafl[0].engine == "LibAFL"

    py_targets = detect_repo_fuzz_targets(_create_python_repo(tmp_path))
    assert len(py_targets) == 1
    assert py_targets[0].language == FuzzLanguage.PYTHON.value
    assert py_targets[0].backend == "atheris"
    assert py_targets[0].package_name == "rfcparser"
    assert py_targets[0].entry_symbols[0].endswith(":parse_http_frame")
    assert "Content-Length" in py_targets[0].extracted_tokens

    js_targets = detect_repo_fuzz_targets(_create_js_ts_repo(tmp_path))
    assert len(js_targets) == 1
    assert js_targets[0].language == FuzzLanguage.JS_TS.value
    assert js_targets[0].backend == "jazzer.js"
    assert js_targets[0].engine == "Jazzer"
    assert js_targets[0].package_name == "gateway_parser"
    assert "decodeRequestHeader" in js_targets[0].entry_symbols

    java_targets = detect_repo_fuzz_targets(_create_java_repo(tmp_path))
    assert len(java_targets) == 1
    assert java_targets[0].language == FuzzLanguage.JAVA.value
    assert java_targets[0].backend == "jazzer"
    assert java_targets[0].build_system == "maven"
    assert java_targets[0].package_name == "acme_http_proxy"
    assert "com.acme.proxy.FrameParser#parseHeaderLine" in java_targets[0].entry_symbols


def test_detect_polyglot_repo_skips_vendor_dirs_and_respects_filter(tmp_path: Path) -> None:
    poly = _create_polyglot_repo(tmp_path)
    all_targets = detect_repo_fuzz_targets(poly)
    assert [t.language for t in all_targets] == ["rust", "c_cpp", "python", "js_ts", "java"]
    py_target = next(t for t in all_targets if t.language == "python")
    assert all("node_modules" not in sf for sf in py_target.source_files)
    assert all("should_not_appear" not in sym for sym in py_target.entry_symbols)

    filtered = detect_repo_fuzz_targets(poly, languages_filter=["rust", "java"])
    assert [t.language for t in filtered] == ["rust", "java"]


# ---------------------------------------------------------------------------
# 2. Harness, Seed, Dictionary Synthesis & Cairn HINT Absorption Tests
# ---------------------------------------------------------------------------

def test_synthesize_artifacts_with_cairn_hint_absorption_and_deterministic_fallback(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "cairn_hints.db"), encrypt_at_rest=False)
    try:
        hint_id_1 = db.add_hint(
            'Explore obs-fold before "Transfer-Encoding: chunked" and hex magic 0xdeadbeef in parse_http_frame',
            task_id="fuzz-task-1",
            domain="fuzz:python",
            source_agent="dream_rsi_agent",
            payload={
                "cue": "obs-fold TE smuggling",
                "tokens": ["X-Custom-Smuggle", "0;ext=1\r\n\r\n"],
                "seeds": ["POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"],
                "target_symbol": "parse_http_frame",
            },
        )
        hint_id_2 = db.add_hint(
            'Global hint: test "Content-Length: 0" boundary',
            task_id="fuzz-task-1",
            domain="global",
            source_agent="cli",
        )

        repo = _create_python_repo(tmp_path)
        work = tmp_path / "work_out"
        bridge = LLMFuzzBridge(db=db, task_id="fuzz-task-1")
        targets = bridge.detect_languages(repo)
        artifacts = bridge.synthesize_artifacts(targets[0], work, task_id="fuzz-task-1")

        assert artifacts.source_mode == "deterministic"
        assert hint_id_1 in artifacts.absorbed_hint_ids
        assert hint_id_2 in artifacts.absorbed_hint_ids
        assert Path(artifacts.harness_path).exists()
        assert Path(artifacts.dictionary_path).exists()
        assert Path(artifacts.corpus_dir).is_dir()
        assert len(artifacts.seed_paths) >= 4

        harness_txt = Path(artifacts.harness_path).read_text(encoding="utf-8")
        assert "import atheris" in harness_txt
        assert "FuzzedDataProvider" in harness_txt
        assert "parse_http_frame" in harness_txt
        assert hint_id_1 in harness_txt

        dict_txt = Path(artifacts.dictionary_path).read_text(encoding="utf-8")
        assert "kw_hint_" in dict_txt
        assert "X-Custom-Smuggle" in dict_txt
        assert "Transfer-Encoding: chunked" in dict_txt

        seed_names = {Path(p).name for p in artifacts.seed_paths}
        assert any(name.startswith("seed_hint_") for name in seed_names)
        assert any(Path(p).read_bytes() == bytes.fromhex("deadbeef") for p in artifacts.seed_paths)
    finally:
        db.close()


def test_synthesize_all_five_language_harnesses_and_llm_callback_merge(tmp_path: Path) -> None:
    poly = _create_polyglot_repo(tmp_path)
    work = tmp_path / "poly_work"

    prompts_seen: List[str] = []

    def fake_llm_callback(prompt: str) -> str:
        prompts_seen.append(prompt)
        if '"language": "rust"' in prompt:
            return json.dumps(
                {
                    "harness_code": (
                        "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n"
                        "fuzz_target!(|data: &[u8]| { let _ = data.len(); });\n"
                    ),
                    "seeds": ["LLM_RUST_SEED_ALPHA", "base64:Rk9PQkFS"],
                    "dictionary_tokens": ["LLM_MAGIC_RS"],
                }
            )
        # Return malformed output for other languages to verify deterministic fallback
        return "not valid json {{"

    bridge = LLMFuzzBridge(llm_callback=fake_llm_callback)
    targets = bridge.detect_languages(poly)
    assert len(targets) == 5

    by_lang = {t.language: bridge.synthesize_artifacts(t, work) for t in targets}
    assert len(prompts_seen) == 5

    # Rust used valid LLM harness + seeds + dict token
    rs_art = by_lang["rust"]
    assert rs_art.source_mode == "llm"
    assert "LLM_MAGIC_RS" in Path(rs_art.dictionary_path).read_text(encoding="utf-8")
    assert Path(rs_art.build_manifest_path).name == "Cargo.toml"
    assert any(Path(p).read_bytes() == b"FOOBAR" for p in rs_art.seed_paths)

    # C/C++, Python, JS/TS, Java cleanly fell back to deterministic harnesses
    cpp_art = by_lang["c_cpp"]
    assert cpp_art.source_mode == "deterministic"
    cpp_src = Path(cpp_art.harness_path).read_text(encoding="utf-8")
    assert "LLVMFuzzerTestOneInput" in cpp_src
    assert "__AFL_LOOP" in cpp_src
    assert "-fsanitize=address,undefined" in Path(cpp_art.build_manifest_path).read_text(encoding="utf-8")

    js_src = Path(by_lang["js_ts"].harness_path).read_text(encoding="utf-8")
    assert "@jazzer.js/core" in js_src and "module.exports.fuzz" in js_src

    java_src = Path(by_lang["java"].harness_path).read_text(encoding="utf-8")
    assert "FuzzedDataProvider" in java_src and "fuzzerTestOneInput" in java_src


# ---------------------------------------------------------------------------
# 3. Docker Container Argument Hardening Tests
# ---------------------------------------------------------------------------

def test_docker_command_hardening_across_languages(tmp_path: Path) -> None:
    poly = _create_polyglot_repo(tmp_path)
    work = tmp_path / "hardened_work"
    bridge = LLMFuzzBridge(config=FuzzBridgeConfig(memory_limit="768m", cpu_limit=1.5, pids_limit=128))
    targets = bridge.detect_languages(poly)

    for target in targets:
        art = bridge.synthesize_artifacts(target, work)
        cmd = bridge.build_docker_command(target, art, poly, work, docker_binary="docker")

        assert isinstance(cmd, list)
        assert cmd[0] == "docker" and cmd[1] == "run"
        assert "--rm" in cmd
        assert "--network=none" in cmd
        assert "--cap-drop=ALL" in cmd
        assert "--security-opt=no-new-privileges:true" in cmd
        assert "--memory=768m" in cmd
        assert "--cpus=1.5" in cmd
        assert "--pids-limit=128" in cmd
        assert any(tok.endswith(":/workspace/src:ro") for tok in cmd)
        assert any(tok.endswith(":/workspace/fuzz:rw") for tok in cmd)

        if target.language == "c_cpp":
            assert any("-fsanitize=address,undefined" in tok for tok in cmd)
            assert "AFL_USE_ASAN=1" in cmd
            assert "AFL_USE_UBSAN=1" in cmd

        ok, reason = validate_docker_fuzz_command(cmd, shell=False)
        assert ok, f"Expected valid Docker command for {target.language}, failed with: {reason}"


@pytest.mark.parametrize(
    "bad_cmd,shell_flag,expected_fragment",
    [
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            True,
            "shell=True",
        ),
        (
            "docker run --rm --network=none aflplusplus/aflplusplus:latest",
            False,
            "sequence",
        ),
        (
            [
                "docker", "run", "--rm", "--network=host", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "isolation escape",
        ),
        (
            [
                "docker", "run", "--rm", "--network=bridge", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "--network=none",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--privileged", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "--privileged",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL", "--cap-add=SYS_PTRACE",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "--cap-add",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0", "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "--cap-drop=ALL",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "Unsafe volume mount",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0",
                "-v/etc:/workspace/src:ro",
                "aflplusplus/aflplusplus:latest", "afl-fuzz",
            ],
            False,
            "Unsafe volume mount",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0",
                "aflplusplus/aflplusplus:latest", "afl-fuzz", "; rm -rf /",
            ],
            False,
            "Shell metacharacter",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0",
                "aflplusplus/aflplusplus:latest", "sh", "-c", "id",
            ],
            False,
            "Nested shell wrapper",
        ),
        (
            [
                "docker", "run", "--rm", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory=512m", "--cpus=1.0",
                "alpine:latest", "afl-fuzz",
            ],
            False,
            "Generic shell/OS base image",
        ),
    ],
)
def test_validate_docker_fuzz_command_rejects_unsafe_inputs(
    bad_cmd: Any, shell_flag: bool, expected_fragment: str
) -> None:
    ok, reason = validate_docker_fuzz_command(bad_cmd, shell=shell_flag)
    assert not ok
    assert expected_fragment.lower() in reason.lower()


def test_config_rejects_shell_injection_in_image_and_memory() -> None:
    with pytest.raises(ValueError):
        FuzzBridgeConfig(images={"afl++": "aflplusplus/aflplusplus:latest;whoami"})
    with pytest.raises(ValueError):
        FuzzBridgeConfig(memory_limit="512m --privileged")
    with pytest.raises(ValueError):
        FuzzBridgeConfig(memory_limit="64g")


# ---------------------------------------------------------------------------
# 4. Sanitizer Crash & Coverage Plateau Parsing + Cairn Blackboard Persistence
# ---------------------------------------------------------------------------

ASAN_AND_PLATEAU_LOG = """\
#2\tINITED cov: 34 ft: 51 corp: 4/120b lim: 4 exec/s: 0 rss: 32Mb
#64\tNEW    cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 64 rss: 34Mb
#128\tpulse  cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 128 rss: 35Mb
#256\tpulse  cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 256 rss: 35Mb
#512\tpulse  cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 512 rss: 35Mb
#1024\tpulse  cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 512 rss: 36Mb
#2048\tpulse  cov: 58 ft: 92 corp: 7/312b lim: 4 exec/s: 512 rss: 36Mb
=================================================================
==4219==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x55d8f012 bp 0x7ffc10 sp 0x7ffc00
READ of size 8 at 0x602000000014 thread T0
    #0 0x55d8f012 in parse_wire_packet /workspace/src/decoder.cpp:42:9
    #1 0x55d8f400 in LLVMFuzzerTestOneInput /workspace/fuzz/c_cpp/fuzz_WireCodec.cpp:19:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /workspace/src/decoder.cpp:42:9 in parse_wire_packet
artifact_prefix='/workspace/fuzz/c_cpp/'; Test unit written to /workspace/fuzz/c_cpp/crash-aabbccddeeff0011
"""

UBSAN_LOG = """\
/workspace/src/decoder.cpp:71:18: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x55d8f120 in parse_wire_packet /workspace/src/decoder.cpp:71:18
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /workspace/src/decoder.cpp:71:18
"""

ATHERIS_LOG = """\
#10\tNEW    cov: 20 ft: 35 corp: 3/90b lim: 4 exec/s: 50 rss: 40Mb
=== Uncaught Python exception: ===
IndexError: list index out of range
Traceback (most recent call last):
  File "/workspace/fuzz/python/fuzz_rfcparser.py", line 33, in TestOneInput
    fn(raw_bytes)
  File "/workspace/src/rfcparser/framing.py", line 18, in parse_http_frame
    return parts[9]
Test unit written to /workspace/fuzz/python/crash-py12345
"""

JAZZER_JVM_LOG = """\
==1122== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
\tat com.acme.proxy.FrameParser.parseHeaderLine(FrameParser.java:29)
\tat FuzzAcmeHttpProxy.fuzzerTestOneInput(FuzzAcmeHttpProxy.java:14)
DEDUP_TOKEN: 7f8e9a0b1c2d3e4f
Test unit written to /workspace/fuzz/java/crash-java999
"""

RUST_PANIC_LOG = """\
thread 'main' panicked at src/lib.rs:24:17:
byte index 16 is out of bounds of `GET`
   0: http_frame_rs::parse_chunk_header
             at ./src/lib.rs:24:17
   1: fuzz_http_frame_rs::rust_fuzzer_test_input
             at ./fuzz/fuzz_http_frame_rs.rs:12:5
Test unit written to /workspace/fuzz/rust/crash-rs777
"""

AFL_STATS_LOG = """\
execs_done        : 450000
execs_per_sec     : 2150.50
corpus_count      : 42
edges_found       : 189
bitmap_cvg        : 12.40%
saved_crashes     : 2
cycles_done       : 9
cycles_wo_finds   : 6
"""


def test_parse_real_sanitizer_traces_across_all_backends() -> None:
    asan = parse_sanitizer_output(ASAN_AND_PLATEAU_LOG, language="c_cpp", target_name="WireCodec", backend="afl++")
    assert len(asan) == 1
    assert asan[0].sanitizer == "asan"
    assert asan[0].crash_type == "heap-buffer-overflow"
    assert asan[0].severity == "critical"
    assert asan[0].artifact_path.endswith("crash-aabbccddeeff0011")
    assert len(asan[0].stack_frames) == 2
    assert asan[0].stack_frames[0].function == "parse_wire_packet"
    assert asan[0].stack_frames[0].line == 42

    ubsan = parse_sanitizer_output(UBSAN_LOG, language="c_cpp", target_name="WireCodec", backend="afl++")
    assert len(ubsan) == 1
    assert ubsan[0].sanitizer == "ubsan"
    assert ubsan[0].crash_type == "signed-integer-overflow"

    atheris = parse_sanitizer_output(ATHERIS_LOG, language="python", target_name="rfcparser", backend="atheris")
    assert len(atheris) == 1
    assert atheris[0].sanitizer == "atheris"
    assert atheris[0].crash_type == "IndexError"
    assert any(f.function == "parse_http_frame" for f in atheris[0].stack_frames)

    jazzer = parse_sanitizer_output(JAZZER_JVM_LOG, language="java", target_name="acme_http_proxy", backend="jazzer")
    assert len(jazzer) == 1
    assert jazzer[0].sanitizer == "jazzer"
    assert jazzer[0].severity == "critical"
    assert jazzer[0].dedup_token == "7f8e9a0b1c2d3e4f"
    assert jazzer[0].stack_frames[0].line == 29

    rust_c = parse_sanitizer_output(RUST_PANIC_LOG, language="rust", target_name="http_frame_rs", backend="cargo-fuzz")
    assert len(rust_c) == 1
    assert rust_c[0].sanitizer == "rust_panic"
    assert rust_c[0].stack_frames[0].line == 24

    afl_c = parse_sanitizer_output(AFL_STATS_LOG, language="c_cpp", target_name="WireCodec", backend="afl++")
    assert len(afl_c) == 1
    assert afl_c[0].sanitizer == "afl++"
    assert afl_c[0].occurrences == 2


def test_parse_coverage_and_detect_plateau_vs_active_growth() -> None:
    samples = parse_coverage_progression(ASAN_AND_PLATEAU_LOG)
    assert len(samples) == 7
    assert samples[0].edges == 34
    assert samples[-1].edges == 58

    plateau = detect_coverage_plateau(
        samples,
        language="c_cpp",
        target_name="WireCodec",
        backend="afl++",
        plateau_steps=5,
        recommended_tokens=["WIRE_HDR_V2"],
    )
    assert plateau is not None
    assert plateau.stagnant_steps == 5
    assert plateau.peak_edges == 58
    assert plateau.peak_features == 92
    assert "WIRE_HDR_V2" in plateau.stuck_hint

    # Continuously growing coverage must NOT trigger a plateau
    growing_log = "\n".join(
        f"#{i * 100}\tNEW    cov: {10 + i * 5} ft: {20 + i * 8} corp: {i}/100b lim: 4 exec/s: 500 rss: 30Mb"
        for i in range(1, 8)
    )
    growing_samples = parse_coverage_progression(growing_log)
    assert detect_coverage_plateau(
        growing_samples, language="rust", target_name="http_frame_rs", plateau_steps=4
    ) is None

    # AFL++ cycles_wo_finds stagnation detection
    afl_samples = parse_coverage_progression(AFL_STATS_LOG)
    assert len(afl_samples) == 1 and afl_samples[0].edges == 189
    afl_plateau = detect_coverage_plateau(
        afl_samples,
        language="c_cpp",
        target_name="WireCodec",
        backend="afl++",
        plateau_steps=5,
        log_text=AFL_STATS_LOG,
    )
    assert afl_plateau is not None
    assert afl_plateau.stagnant_steps == 6


def test_end_to_end_isolated_run_ingests_deduplicated_cairn_facts_and_intents(tmp_path: Path) -> None:
    repo = _create_cpp_repo(tmp_path)
    out_dir = tmp_path / "reports"
    db = Database(str(tmp_path / "cairn_fuzz.db"), encrypt_at_rest=False)
    observed_calls: List[Dict[str, Any]] = []

    def fake_docker_runner(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        observed_calls.append({"cmd": list(cmd), "shell": kwargs.get("shell", False)})
        assert kwargs.get("shell", False) is False
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, stdout="27.3.1\n", stderr="")
        if cmd[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="[]\n", stderr="")
        if cmd[1] == "run":
            assert "--network=none" in cmd
            assert "--cap-drop=ALL" in cmd
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=ASAN_AND_PLATEAU_LOG)
        raise AssertionError(f"Unexpected command: {cmd}")

    try:
        bridge = LLMFuzzBridge(
            db=db,
            config=FuzzBridgeConfig(docker_binary="docker", plateau_steps=5, timeout_sec=30.0),
            task_id="campaign-fuzz-42",
            subprocess_runner=fake_docker_runner,
        )
        report = bridge.run(repo, output_dir=out_dir, task_id="campaign-fuzz-42")

        assert report.status == "completed_with_crashes"
        assert report.detected_languages == ["c_cpp"]
        assert len(report.crashes) == 1
        assert len(report.plateaus) == 1
        assert len(report.blackboard_fact_ids) == 2
        assert len(report.blackboard_intent_ids) == 2

        # Verify SQLite blackboard_nodes persistence
        facts = db.get_facts(task_id="campaign-fuzz-42")
        intents = db.list_intents(task_id="campaign-fuzz-42", status="PENDING")
        assert len(facts) == 2
        assert len(intents) == 2

        fact_kinds = {f["payload"].get("kind") for f in facts}
        assert fact_kinds == {"fuzz_sanitizer_crash", "fuzz_coverage_plateau"}
        intent_actions = {i["payload"].get("action") for i in intents}
        assert intent_actions == {"triage_and_minimize_crash", "synthesize_branch_unlock_seeds"}

        # Every intent links back to its parent FACT node
        fact_id_set = {f["node_id"] for f in facts}
        assert all(i["parent_node_id"] in fact_id_set for i in intents)

        # Re-ingesting the same crash & plateau MUST deduplicate via canonical node_id (zero duplicates)
        bridge.ingest_results_to_blackboard(
            report.crashes, report.plateaus, task_id="campaign-fuzz-42", domain="fuzz:c_cpp"
        )
        assert len(db.get_facts(task_id="campaign-fuzz-42")) == 2
        assert len(db.list_intents(task_id="campaign-fuzz-42", status="PENDING")) == 2

        # Verify report JSON was persisted cleanly with UTF-8 and zero control chars/U+FFFD
        report_json = Path(report.provenance["report_path"])
        assert report_json.exists()
        raw_txt = report_json.read_text(encoding="utf-8")
        assert "\ufffd" not in raw_txt
        parsed = json.loads(raw_txt)
        assert parsed["status"] == "completed_with_crashes"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 5. Clean Skip Provenance When Docker or Toolchains Are Absent
# ---------------------------------------------------------------------------

def test_clean_skip_when_docker_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _create_rust_repo(tmp_path)
    out_dir = tmp_path / "skip_docker_out"
    monkeypatch.setattr("engine.fuzz_bridge.shutil.which", lambda _name: None)

    result = run_fuzz_bridge_scan(repo, output_dir=out_dir, task_id="skip-docker-task")
    assert result["status"] == "skipped_docker_unavailable"
    assert result["detected_languages"] == ["rust"]
    assert len(result["generated_artifacts"]) == 1
    harness_path = Path(result["generated_artifacts"][0]["harness_path"])
    corpus_dir = Path(result["generated_artifacts"][0]["corpus_dir"])
    dict_path = Path(result["generated_artifacts"][0]["dictionary_path"])
    assert harness_path.exists()
    assert corpus_dir.is_dir()
    assert dict_path.exists()
    assert result["provenance"]["docker_available"] is False
    assert result["provenance"]["detected_languages"] == ["rust"]
    assert result["provenance"]["harness_paths"]["rust"] == str(harness_path)
    assert result["provenance"]["corpus_dirs"]["rust"] == str(corpus_dir)


def test_clean_skip_when_toolchain_image_unavailable(tmp_path: Path) -> None:
    repo = _create_java_repo(tmp_path)
    out_dir = tmp_path / "skip_toolchain_out"

    def docker_without_images(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell", False) is False
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, stdout="27.3.1\n", stderr="")
        if cmd[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such image")
        raise AssertionError(f"Should not execute container when image is missing: {cmd}")

    bridge = LLMFuzzBridge(
        config=FuzzBridgeConfig(docker_binary="docker"),
        subprocess_runner=docker_without_images,
    )
    report = bridge.run(repo, output_dir=out_dir, task_id="skip-image-task")
    assert report.status == "skipped_toolchain_unavailable"
    assert report.detected_languages == ["java"]
    assert DEFAULT_DOCKER_IMAGES["jazzer"] in report.docker_preflight.missing_images
    assert DEFAULT_DOCKER_IMAGES["jazzer"] in report.provenance["missing_images"]
    assert len(report.generated_artifacts) == 1
    assert Path(report.generated_artifacts[0].harness_path).exists()
    assert Path(report.generated_artifacts[0].corpus_dir).is_dir()


def test_empty_repo_returns_no_targets_without_crashing(tmp_path: Path) -> None:
    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    (empty_repo / "README.md").write_text("# Docs only\n", encoding="utf-8")

    result = run_fuzz_bridge_scan(empty_repo, output_dir=tmp_path / "empty_out")
    assert result["status"] == "no_targets_detected"
    assert result["detected_languages"] == []


def test_jazzer_js_and_libafl_parsers_and_arbiter_integration(tmp_path: Path) -> None:
    jazzer_js_log = (
        "==991== Caught exception: FuzzerSecurityIssueHigh: Path Traversal\n"
        "    at decodeRequestHeader (/workspace/src/index.ts:44:11)\n"
        "    at fuzz (/workspace/fuzz/js_ts/fuzz_gateway_parser.js:22:7)\n"
        "DEDUP_TOKEN: jsdeadbeef42\n"
    )
    js_crashes = parse_sanitizer_output(
        jazzer_js_log, language="js_ts", target_name="gateway_parser", backend="jazzer.js"
    )
    assert len(js_crashes) == 1
    assert js_crashes[0].sanitizer == "jazzer_js"
    assert js_crashes[0].severity == "high"
    assert js_crashes[0].dedup_token == "jsdeadbeef42"
    assert js_crashes[0].stack_frames[0].function == "decodeRequestHeader"

    libafl_log = "\n".join(
        [
            "[Stats #0] corpus: 12, objectives: 0, executions: 1000, exec/sec: 500.0, edges: 140/2048 (6.84%)",
            "[Stats #1] corpus: 12, objectives: 0, executions: 2000, exec/sec: 510.0, edges: 140/2048 (6.84%)",
            "[Stats #2] corpus: 12, objectives: 0, executions: 3000, exec/sec: 505.0, edges: 140/2048 (6.84%)",
            "[Stats #3] corpus: 12, objectives: 0, executions: 4000, exec/sec: 495.0, edges: 140/2048 (6.84%)",
        ]
    )
    la_samples = parse_coverage_progression(libafl_log)
    assert len(la_samples) == 4
    assert la_samples[0].edges == 140
    la_plateau = detect_coverage_plateau(
        la_samples, language="c_cpp", target_name="WireCodec", backend="libafl", plateau_steps=3
    )
    assert la_plateau is not None
    assert la_plateau.stagnant_steps == 3

    class StubArbiter:
        def arbitrate_structured_json(self, prompt: str, schema_hint: str = "") -> Dict[str, Any]:
            assert schema_hint == "fuzz_harness"
            return {
                "seeds": ["ARBITER_SEED_1"],
                "dictionary_tokens": ["ARBITER_TOKEN_XYZ"],
            }

    repo = _create_js_ts_repo(tmp_path)
    bridge = LLMFuzzBridge(arbiter=StubArbiter())
    targets = bridge.detect_languages(repo)
    art = bridge.synthesize_artifacts(targets[0], tmp_path / "arbiter_work")
    assert art.source_mode == "llm+deterministic"
    assert "ARBITER_TOKEN_XYZ" in Path(art.dictionary_path).read_text(encoding="utf-8")


def test_timeout_partial_polyglot_and_multitask_blackboard_isolation(tmp_path: Path) -> None:
    poly = _create_polyglot_repo(tmp_path)
    db = Database(str(tmp_path / "multitask.db"), encrypt_at_rest=False)

    def partial_runner(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        assert kwargs.get("shell", False) is False
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, stdout="27.3.1\n", stderr="")
        if cmd[1:3] == ["image", "inspect"]:
            # Only Python Atheris image is locally available; Rust image is missing
            if cmd[3] == DEFAULT_DOCKER_IMAGES["atheris"]:
                return subprocess.CompletedProcess(cmd, 0, stdout="[]\n", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No such image")
        if cmd[1] == "run":
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=5.0, output=b"", stderr=ATHERIS_LOG.encode("utf-8"))
        raise AssertionError(f"Unexpected cmd: {cmd}")

    try:
        bridge = LLMFuzzBridge(
            db=db,
            config=FuzzBridgeConfig(docker_binary="docker", timeout_sec=5.0),
            subprocess_runner=partial_runner,
        )
        rep_a = bridge.run(poly, output_dir=tmp_path / "out_a", task_id="task-A", languages=["rust", "python"])
        rep_b = bridge.run(poly, output_dir=tmp_path / "out_b", task_id="task-B", languages=["python"])

        assert rep_a.status == "completed_with_crashes"
        by_lang = {r.language: r for r in rep_a.target_results}
        assert by_lang["rust"].status == "skipped_toolchain_unavailable"
        assert by_lang["python"].status == "completed_with_crashes"
        assert len(by_lang["python"].crashes) == 1

        # Multi-task isolation: task-A and task-B both preserve their own crash FACT rows
        assert len(db.get_facts(task_id="task-A")) == 1
        assert len(db.get_facts(task_id="task-B")) == 1
        assert rep_b.crashes[0].crash_hash == rep_a.crashes[0].crash_hash
        assert db.get_facts(task_id="task-A")[0]["node_id"] != db.get_facts(task_id="task-B")[0]["node_id"]
    finally:
        db.close()

