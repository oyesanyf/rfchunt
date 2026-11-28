"""
Tier 1 E2E Tests: PE & .NET Code Integrity Auditor, CLI, `--all`, and MCP (Features #12-#17).

Covers 5 distinct opaque-box test cases per feature (30 total tests):
- F12: CLR Data Directory #14 `+ 4` offset fix & preserved PE/Magika classification
- F13: UMCI / `SEC_COMMIT` flat memory fallback heuristics
- F14: Defensive YARA rule generation, syntax validation, and matching
- F15: Pure-Python host patch-level auditing (`KB5127694` & VirtualBox `7.2.18+`)
- F16: CLI, `--all`, and MCP wiring for PE & .NET Code Integrity Anomaly Auditor
- F17: End-to-end `--all` pipeline, `main.py` shim parity, `swarm_cli_board`, & SARIF contracts
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import struct
import subprocess
from typing import Any, Dict, List, Optional

import pytest

pytestmark = pytest.mark.tier1


def _pe_mod():
    return importlib.import_module("engine.pe_magika_classifier")


def _build_full_dotnet_pe(
    *,
    is_64bit: bool = True,
    characteristics: int = 0x2002,
    section_alignment: int = 0x2000,
    file_alignment: int = 0x200,
    size_of_image: int = 0x4000,
    size_of_headers: int = 0x200,
    entry_point: int = 0,
    subsystem: int = 3,
    include_clr: bool = True,
    clr_dir_size: int = 72,
    cor20_cb: int = 72,
    cor20_flags: int = 0x00000001,
    section_chars: int = 0x60000020,
    bsjb_version: str = "v4.0.30319",
) -> bytes:
    """Constructs a full spec-compliant PE32/PE32+ or .NET assembly with COR20 + BSJB."""
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)
    buf[lfanew : lfanew + 4] = b"PE\x00\x00"

    machine = 0x8664 if is_64bit else 0x014C
    opt_hdr_size = 240 if is_64bit else 224
    struct.pack_into(
        "<HHIIIHH",
        buf,
        lfanew + 4,
        machine,
        1,
        0,
        0,
        0,
        opt_hdr_size,
        characteristics,
    )

    opt_off = lfanew + 24
    magic = 0x020B if is_64bit else 0x010B
    struct.pack_into("<H", buf, opt_off, magic)
    struct.pack_into("<I", buf, opt_off + 16, entry_point)
    struct.pack_into("<II", buf, opt_off + 32, section_alignment, file_alignment)
    struct.pack_into("<II", buf, opt_off + 56, size_of_image, size_of_headers)
    struct.pack_into("<HH", buf, opt_off + 68, subsystem, 0x8540)

    rva_count_off = opt_off + (108 if is_64bit else 92)
    struct.pack_into("<I", buf, rva_count_off, 16)
    if include_clr:
        com_off = rva_count_off + 4 + (14 * 8)
        struct.pack_into("<II", buf, com_off, 0x2000, clr_dir_size)

    sec_off = opt_off + opt_hdr_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        sec_off,
        b".text\x00\x00\x00",
        0x300,
        0x2000,
        0x400,
        0x200,
        0,
        0,
        0,
        0,
        section_chars,
    )

    if include_clr:
        cor_off = 0x200
        struct.pack_into(
            "<IHHIIIIIIIIIIIIIIII",
            buf,
            cor_off,
            cor20_cb,
            2,
            5,
            0x2080,
            64,
            cor20_flags,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        ver_bytes = bsjb_version.encode("ascii")
        ver_len = (len(ver_bytes) + 3) & ~3
        bsjb = bytearray()
        bsjb.extend(b"BSJB")
        bsjb.extend(struct.pack("<HHI", 1, 1, 0))
        bsjb.extend(struct.pack("<I", ver_len))
        bsjb.extend(ver_bytes.ljust(ver_len, b"\x00"))
        bsjb.extend(struct.pack("<HH", 0, 2))
        bsjb.extend(struct.pack("<II", 0x100, 0x200))
        bsjb.extend(b"#~\x00\x00")
        bsjb.extend(struct.pack("<II", 0x300, 0x400))
        bsjb.extend(b"#Strings\x00\x00\x00\x00")
        buf[0x280 : 0x280 + len(bsjb)] = bsjb

    return bytes(buf)


def _find_pe_dotnet_mcp_tool(tools: List[Dict[str, Any]]) -> Optional[str]:
    for t in tools:
        name = str(t.get("name") or "")
        low = name.lower()
        desc = str(t.get("description") or "").lower()
        if any(tok in low for tok in ("pe_dotnet", "pe-dotnet", "pe_audit", "dotnet_audit")) or (
            "pe" in low and ("dotnet" in low or "umci" in desc or "sec_commit" in desc)
        ):
            return name
    return None


def _run_offline_all_args(e2e_workspace, loopback_ollama, script_name: str, extra: Optional[List[str]] = None) -> List[str]:
    args = [
        script_name,
        "--all",
        "--repo",
        str(e2e_workspace.repo),
        "--output-dir",
        str(e2e_workspace.output_dir),
        "--db",
        str(e2e_workspace.db_path),
        "--depth",
        "20",
        "--mantis-mode",
        "fast",
        "--no-include-models",
        "--no-external-scanners",
        "--no-preflight",
        "--no-auto-install",
        "--json",
    ]
    if extra:
        args.extend(extra)
    return args


# =============================================================================
# F12: CLR Data Directory +4 Offset Fix & Preserved PE/Magika Checks (5 tests)
# =============================================================================


def test_t1_f12_clr_offset_pe32_without_bsjb(pe_builder) -> None:
    pe_mod = _pe_mod()
    pe32_clr = pe_builder.build_pe(
        is_64bit=False,
        characteristics=pe_builder.IMAGE_FILE_EXECUTABLE_IMAGE | pe_builder.IMAGE_FILE_DLL,
        include_clr_dir=True,
        clr_rva=0x2000,
        clr_size=72,
        include_bsjb=False,
    )
    report = pe_mod.inspect_pe_binary(pe32_clr, "Pe32ClrOnly.dll")
    assert report.is_pe is True
    assert report.dot_net.is_dot_net is True
    assert report.dot_net.clr_header_rva == 0x2000
    assert report.dot_net.clr_header_size == 72
    assert report.dot_net.has_bsjb_root is False


def test_t1_f12_clr_offset_pe32plus_without_bsjb(pe_builder) -> None:
    pe_mod = _pe_mod()
    pe64_clr = pe_builder.build_pe(
        is_64bit=True,
        characteristics=pe_builder.IMAGE_FILE_EXECUTABLE_IMAGE | pe_builder.IMAGE_FILE_DLL,
        include_clr_dir=True,
        clr_rva=0x2000,
        clr_size=72,
        include_bsjb=False,
    )
    report = pe_mod.inspect_pe_binary(pe64_clr, "Pe64ClrOnly.dll")
    assert report.is_pe is True
    assert report.dot_net.is_dot_net is True
    assert report.dot_net.clr_header_rva == 0x2000
    assert report.dot_net.clr_header_size == 72
    d = report.to_dict()
    assert d["dot_net"]["clr_header_rva"] == 0x2000
    assert d["dot_net"]["clr_header_size"] == 72


def test_t1_f12_clean_dotnet_assembly_preserved(pe_builder) -> None:
    pe_mod = _pe_mod()
    clean_net = pe_builder.build_clean_dotnet(is_64bit=True, include_bsjb=True)
    report = pe_mod.inspect_pe_binary(clean_net, "LegitimateAssembly.dll")
    assert report.is_pe is True
    assert report.is_executable_image is True
    assert report.is_dll is True
    assert report.dot_net.is_dot_net is True
    assert report.dot_net.has_bsjb_root is True
    assert report.dot_net.runtime_version == "v4.0.30319"
    assert report.has_forshaw_cve_2026_108398_anomaly is False


def test_t1_f12_cve_2026_108398_cleared_exec_flag_dotnet(pe_builder) -> None:
    pe_mod = _pe_mod()
    bypass_net = pe_builder.build_cve_2026_108398_dotnet(is_64bit=True, include_bsjb=True)
    report = pe_mod.inspect_pe_binary(bypass_net, "BypassAssembly.dll")
    assert report.is_pe is True
    assert report.is_executable_image is False
    assert report.dot_net.is_dot_net is True
    assert report.has_forshaw_cve_2026_108398_anomaly is True
    assert any("CVE-2026-108398" in a for a in report.anomalies)


def test_t1_f12_extension_masquerading_and_non_pe_baseline(pe_builder, e2e_workspace) -> None:
    pe_mod = _pe_mod()
    pdf_pe = pe_builder.build_masqueraded_pe(e2e_workspace.repo, "statement.pdf")
    txt_pe = pe_builder.build_masqueraded_pe(e2e_workspace.repo, "readme.txt")

    rep_pdf = pe_mod.inspect_pe_binary(pdf_pe.read_bytes(), pdf_pe)
    rep_txt = pe_mod.inspect_pe_binary(txt_pe.read_bytes(), txt_pe)
    assert rep_pdf.is_pe is True and rep_pdf.is_masqueraded is True and rep_pdf.declared_extension == ".pdf"
    assert rep_txt.is_pe is True and rep_txt.is_masqueraded is True and rep_txt.declared_extension == ".txt"

    elf_rep = pe_mod.inspect_pe_binary(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60, "sample.elf")
    json_rep = pe_mod.inspect_pe_binary(b'{"status":"ok"}', "config.json")
    assert elf_rep.is_pe is False and elf_rep.magika_identity.label == "elf"
    assert json_rep.is_pe is False and json_rep.magika_identity.label == "json"


# =============================================================================
# F13: UMCI / SEC_COMMIT Flat Memory Fallback Heuristics (5 tests)
# =============================================================================


def test_t1_f13_umci_alignment_mismatch_triggers_sec_commit_risk() -> None:
    pe_mod = _pe_mod()
    bad_align = _build_full_dotnet_pe(section_alignment=0x200, file_alignment=0x1000)
    report = pe_mod.inspect_pe_binary(bad_align, "BadAlign.dll")
    assert getattr(report, "umci_fallback_risk", False) is True
    umci_list = getattr(report, "umci_anomalies", None) or report.anomalies
    assert any("UMCI" in a or "SEC_COMMIT" in a or "Alignment" in a for a in umci_list)


def test_t1_f13_umci_size_of_image_and_header_overlap() -> None:
    pe_mod = _pe_mod()
    bad_soi = _build_full_dotnet_pe(size_of_image=0x2500, size_of_headers=0x2600)
    report = pe_mod.inspect_pe_binary(bad_soi, "HeaderOverlap.dll")
    assert getattr(report, "umci_fallback_risk", False) is True
    assert len(report.anomalies) >= 1


def test_t1_f13_umci_cor20_header_flag_contradictions() -> None:
    pe_mod = _pe_mod()
    # ILONLY | NATIVE_ENTRYPOINT contradiction + invalid cb
    bad_cor = _build_full_dotnet_pe(cor20_cb=64, cor20_flags=0x00000001 | 0x00000010)
    rep_cor = pe_mod.inspect_pe_binary(bad_cor, "BadCor20.dll")
    assert getattr(rep_cor, "umci_fallback_risk", False) is True

    # 32BITREQUIRED on 64-bit PE32+
    bad_32 = _build_full_dotnet_pe(is_64bit=True, cor20_flags=0x00000001 | 0x00000002)
    rep_32 = pe_mod.inspect_pe_binary(bad_32, "Bad32Bit.dll")
    assert getattr(rep_32, "umci_fallback_risk", False) is True


def test_t1_f13_umci_rwx_section_and_sec_commit_builder(pe_builder) -> None:
    pe_mod = _pe_mod()
    rwx_pe = _build_full_dotnet_pe(section_chars=0xE0000020)
    rep_rwx = pe_mod.inspect_pe_binary(rwx_pe, "RwxSection.dll")
    assert any("RWX" in a for a in rep_rwx.anomalies)

    sec_commit_pe = pe_builder.build_umci_sec_commit_pe()
    rep_sc = pe_mod.inspect_pe_binary(sec_commit_pe, "SecCommitBypass.dll")
    assert getattr(rep_sc, "umci_fallback_risk", False) is True
    assert rep_sc.has_forshaw_cve_2026_108398_anomaly is True


def test_t1_f13_umci_zero_false_positive_on_clean_dotnet_pe() -> None:
    pe_mod = _pe_mod()
    clean_64 = _build_full_dotnet_pe(is_64bit=True, characteristics=0x2002)
    clean_32 = _build_full_dotnet_pe(is_64bit=False, characteristics=0x2002)
    for buf, name in ((clean_64, "Clean64.dll"), (clean_32, "Clean32.dll")):
        rep = pe_mod.inspect_pe_binary(buf, name)
        assert getattr(rep, "umci_fallback_risk", False) is False
        assert getattr(rep, "umci_anomalies", []) == []
        assert rep.anomalies == []
        assert rep.has_forshaw_cve_2026_108398_anomaly is False


# =============================================================================
# F14: Defensive YARA Rule Generation & Validation (5 tests)
# =============================================================================


def test_t1_f14_generate_and_validate_yara_rules_syntax() -> None:
    pe_mod = _pe_mod()
    gen_fn = getattr(pe_mod, "generate_pe_dotnet_yara_rules")
    val_fn = getattr(pe_mod, "validate_yara_rules")

    sc_rules = gen_fn(include_extension_external=False)
    res_sc = val_fn(sc_rules)
    assert res_sc["valid"] is True
    assert res_sc["rule_count"] >= 4
    assert "PE_DotNet_CVE_2026_108398_ExecutableFlag_Cleared" in res_sc["rule_names"]
    assert "PE_UMCI_SecCommit_Alignment_Bypass" in res_sc["rule_names"]

    ext_rules = gen_fn(include_extension_external=True)
    res_ext = val_fn(ext_rules)
    assert res_ext["valid"] is True
    assert "PE_Extension_Masquerading" in res_ext["rule_names"]


def test_t1_f14_yara_matches_cve_2026_108398_dotnet(pe_builder) -> None:
    pe_mod = _pe_mod()
    match_fn = getattr(pe_mod, "match_pe_dotnet_yara")
    cve_pe = pe_builder.build_cve_2026_108398_dotnet(is_64bit=True, include_bsjb=True)
    res = match_fn(cve_pe, file_path="exploit.dll")
    assert res["matched"] is True
    assert "PE_DotNet_CVE_2026_108398_ExecutableFlag_Cleared" in res["rule_names"]


def test_t1_f14_yara_matches_umci_sec_commit_anomaly() -> None:
    pe_mod = _pe_mod()
    match_fn = getattr(pe_mod, "match_pe_dotnet_yara")
    umci_pe = _build_full_dotnet_pe(section_alignment=0x200, file_alignment=0x1000)
    res = match_fn(umci_pe, file_path="umci_sec_commit.dll")
    assert res["matched"] is True
    assert "PE_UMCI_SecCommit_Alignment_Bypass" in res["rule_names"]


def test_t1_f14_yara_matches_extension_masqueraded_pe(pe_builder, e2e_workspace) -> None:
    pe_mod = _pe_mod()
    match_fn = getattr(pe_mod, "match_pe_dotnet_yara")
    masq_path = pe_builder.build_masqueraded_pe(e2e_workspace.repo, "invoice.pdf")
    res_masq = match_fn(masq_path.read_bytes(), file_path=masq_path)
    assert res_masq["matched"] is True
    assert "PE_Extension_Masquerading" in res_masq["rule_names"]

    polyglot = b"%PDF-1.7\n" + _build_full_dotnet_pe()
    res_poly = match_fn(polyglot, file_path="polyglot.pdf")
    assert res_poly["matched"] is True
    assert "PE_Extension_Masquerading_Polyglot" in res_poly["rule_names"]


def test_t1_f14_yara_zero_false_positives_on_clean_pe_and_benign_files() -> None:
    pe_mod = _pe_mod()
    match_fn = getattr(pe_mod, "match_pe_dotnet_yara")
    clean_exe = _build_full_dotnet_pe(is_64bit=True, characteristics=0x0002, entry_point=0x2000, include_clr=False)
    clean_dll = _build_full_dotnet_pe(is_64bit=True, characteristics=0x2002)

    for data, fname in (
        (clean_exe, "CleanNative.exe"),
        (clean_dll, "CleanDotNet.dll"),
        (b"Just a benign README text file.\n", "README.txt"),
        (b'{"ok": true, "items": [1, 2, 3]}', "manifest.json"),
    ):
        res = match_fn(data, file_path=fname)
        assert res["matched"] is False, f"False positive YARA hit on {fname}: {res['rule_names']}"
        assert res["rule_names"] == []


# =============================================================================
# F15: Host Patch-Level Auditing (`KB5127694` & VirtualBox 7.2.18+) (5 tests)
# =============================================================================


def test_t1_f15_host_audit_missing_kb5127694_flagged() -> None:
    pe_mod = _pe_mod()
    audit_host = getattr(pe_mod, "audit_host_patch_levels")
    res = audit_host(
        host_snapshot={
            "platform": "win32",
            "windows": {
                "current_build": 26300,
                "ubr": 9000,
                "dotnet_v4_installed": True,
                "cbs_enumerated": True,
                "cbs_packages": [],
                "hotfixes": [],
            },
            "virtualbox": {"installed": False},
        }
    )
    assert res["kb5127694"]["status"] == "vulnerable"
    assert any(f["rule_id"] == "HOST-PATCH-KB5127694" for f in res["findings"])


def test_t1_f15_host_audit_present_kb5127694_compliant() -> None:
    pe_mod = _pe_mod()
    audit_host = getattr(pe_mod, "audit_host_patch_levels")
    res = audit_host(
        host_snapshot={
            "platform": "win32",
            "windows": {
                "current_build": 26300,
                "ubr": 10008,
                "dotnet_v4_installed": True,
                "cbs_enumerated": True,
                "cbs_packages": [{"name": "Package_for_KB5127694~amd64~~26300.10008", "current_state": 112}],
            },
            "virtualbox": {"installed": False},
        }
    )
    assert res["kb5127694"]["status"] == "patched"
    assert res["findings"] == []


def test_t1_f15_host_audit_virtualbox_7_2_16_vulnerable() -> None:
    pe_mod = _pe_mod()
    audit_host = getattr(pe_mod, "audit_host_patch_levels")
    res = audit_host(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
            "virtualbox": {"installed": True, "registry_version": "7.2.16", "binary_version": "7.2.16.0"},
        }
    )
    assert res["virtualbox"]["status"] == "vulnerable"
    assert any(f["rule_id"] == "HOST-PATCH-VBOX-7218" for f in res["findings"])


def test_t1_f15_host_audit_virtualbox_7_2_18_compliant() -> None:
    pe_mod = _pe_mod()
    audit_host = getattr(pe_mod, "audit_host_patch_levels")
    res = audit_host(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
            "virtualbox": {"installed": True, "registry_version": "7.2.18", "binary_version": "7.2.18.0"},
        }
    )
    assert res["virtualbox"]["status"] == "patched"
    assert res["findings"] == []


def test_t1_f15_live_host_audit_structured_without_shell_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    pe_mod = _pe_mod()
    audit_host = getattr(pe_mod, "audit_host_patch_levels")

    def _forbid(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Shell/subprocess execution is forbidden in pure-Python host patch audit")

    monkeypatch.setattr(subprocess, "run", _forbid)
    monkeypatch.setattr(subprocess, "Popen", _forbid)
    monkeypatch.setattr(subprocess, "check_output", _forbid)

    res = audit_host()
    assert res["kb5127694"]["status"] in pe_mod.HOST_PATCH_STATUSES
    assert res["virtualbox"]["status"] in pe_mod.HOST_PATCH_STATUSES
    assert isinstance(res["findings"], list)
    assert json.dumps(res)


# =============================================================================
# F16: CLI, `--all`, and MCP Wiring for PE & .NET Auditor (5 tests)
# =============================================================================


def test_t1_f16_audit_pe_dotnet_target_dir_scan(pe_builder, e2e_workspace) -> None:
    pe_mod = _pe_mod()
    audit_target = getattr(pe_mod, "audit_pe_dotnet_target")

    (e2e_workspace.repo / "clean.dll").write_bytes(_build_full_dotnet_pe())
    (e2e_workspace.repo / "cve_bypass.dll").write_bytes(pe_builder.build_cve_2026_108398_dotnet())
    pe_builder.build_masqueraded_pe(e2e_workspace.repo, "brochure.pdf")

    res = audit_target(
        e2e_workspace.repo,
        include_host_audit=True,
        include_yara=True,
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": True},
            "virtualbox": {"installed": False},
        },
    )
    assert res["status"] == "completed"
    assert res["files_scanned"] == 3
    assert res["cve_2026_108398_count"] == 1
    assert res["masqueraded_files_count"] == 1
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "PE-DOTNET-CVE-2026-108398" in rule_ids
    assert "PE-MASQUERADE-001" in rule_ids
    for f in res["findings"]:
        assert f["evidence_lane"] == "DETERMINISTIC_STATIC"
        assert f["poe_level"] == 2


def test_t1_f16_cli_parser_exposes_pe_audit_mode_or_flag() -> None:
    swarm = importlib.import_module("rfc_hunt_swarm")
    parser = swarm.build_swarm_parser()
    option_strings = {opt for act in parser._actions for opt in act.option_strings}
    modes = set(getattr(swarm, "ALL_MODES", []))

    has_pe_flag = any(
        any(tok in opt.lower() for tok in ("pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet"))
        for opt in option_strings
    )
    has_pe_mode = any(
        any(tok in m.lower() for tok in ("pe-audit", "pe_audit", "pe-dotnet", "pe_dotnet", "peaudit"))
        for m in modes
    )
    assert has_pe_flag or has_pe_mode, (
        "M4: rfc_hunt_swarm.py CLI parser/ALL_MODES does not yet expose a PE & .NET auditor flag or mode"
    )


def test_t1_f16_run_unified_all_scans_wires_pe_dotnet_auditor_and_sarif(
    pe_builder, e2e_workspace, loopback_ollama, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    e2e_workspace.write_repo_file("app.py", "def f(x):\n    return eval(x)\n")
    (e2e_workspace.repo / "bypass.dll").write_bytes(pe_builder.build_cve_2026_108398_dotnet())

    db_mod = importlib.import_module("database")
    mantis_mod = importlib.import_module("engine.mantis_integrator")
    db = db_mod.Database(db_path=str(e2e_workspace.db_path))
    try:
        res = mantis_mod.run_unified_all_scans(
            repo=str(e2e_workspace.repo),
            depth=20,
            mantis_mode="fast",
            db=db,
            reports_dir=str(e2e_workspace.output_dir),
            artex_rounds=0,
            enable_external_scanners=False,
            enable_rea=False,
            enable_h2_desync=False,
            enable_verification_inversion=False,
            enable_arxiv_detect=False,
            enable_last30days_skills=False,
            enable_preflight=False,
            quiet=True,
        )
    finally:
        db.close()

    engines = res.get("engines") or {}
    assert "pe_dotnet_auditor" in engines, (
        f"M4: run_unified_all_scans missing engines['pe_dotnet_auditor']; keys={list(engines.keys())}"
    )
    det_findings = res.get("deterministic_static_findings") or []
    assert any(str(f.get("rule_id") or "").startswith("PE-") for f in det_findings), (
        f"Expected PE-* findings in deterministic_static_findings, got {[f.get('rule_id') for f in det_findings]}"
    )

    sarif_path = Path(res["report_files"]["combined_sarif"])
    sarif_doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    sarif_rules = {r["ruleId"] for r in sarif_doc["runs"][0]["results"]}
    assert any(rid.startswith("PE-") for rid in sarif_rules)


def test_t1_f16_mcp_server_tools_list_and_call_pe_dotnet_auditor(
    pe_builder, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(e2e_workspace.repo))
    (e2e_workspace.repo / "bypass.dll").write_bytes(pe_builder.build_cve_2026_108398_dotnet())

    mcp_mod = importlib.import_module("mcp_server")
    server = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))
    list_resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = list_resp["result"]["tools"]
    tool_name = _find_pe_dotnet_mcp_tool(tools)
    assert tool_name is not None, (
        f"M4: TerminatorMCPServer tools/list missing PE & .NET auditor tool; got {[t['name'] for t in tools]}"
    )

    call_resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": {"target_path": str(e2e_workspace.repo), "include_host_audit": False},
            },
        }
    )
    assert "error" not in call_resp, f"Unexpected MCP error: {call_resp}"
    payload = json.loads(call_resp["result"]["content"][0]["text"])
    assert payload.get("cve_2026_108398_count", 0) >= 1 or any(
        str(f.get("rule_id") or "").startswith("PE-") for f in (payload.get("findings") or [])
    )


def test_t1_f16_mcp_server_run_all_scans_includes_pe_dotnet_findings(
    pe_builder, e2e_workspace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RFCHUNT_OFFLINE", "1")
    monkeypatch.setenv("RFCHUNT_WORKSPACE_ROOT", str(e2e_workspace.repo))
    e2e_workspace.write_repo_file("vuln.py", "def f(x):\n    return eval(x)\n")
    (e2e_workspace.repo / "bypass.dll").write_bytes(pe_builder.build_cve_2026_108398_dotnet())

    mcp_mod = importlib.import_module("mcp_server")
    server = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))
    resp = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "run_all_scans",
                "arguments": {
                    "repo": str(e2e_workspace.repo),
                    "output_dir": str(e2e_workspace.output_dir),
                    "depth": 20,
                    "mantis_mode": "fast",
                    "enable_rea": False,
                    "enable_external_scanners": False,
                },
            },
        }
    )
    assert "error" not in resp
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert "pe_dotnet_auditor" in (payload.get("engines") or {}), (
        f"M4: MCP run_all_scans missing engines['pe_dotnet_auditor']: {list((payload.get('engines') or {}).keys())}"
    )
    assert any(
        str(f.get("rule_id") or "").startswith("PE-")
        for f in (payload.get("deterministic_static_findings") or payload.get("findings") or [])
    )


# =============================================================================
# F17: End-to-End `--all` Pipeline & Dry-Run Contracts (5 tests)
# =============================================================================


def test_t1_f17_cli_all_dry_run_json_contract(cli_runner, e2e_workspace) -> None:
    e2e_workspace.write_repo_file("app.py", "print('hello')\n")
    proc = cli_runner(
        [
            "rfc_hunt_swarm.py",
            "--all",
            "--repo",
            str(e2e_workspace.repo),
            "--output-dir",
            str(e2e_workspace.output_dir),
            "--db",
            str(e2e_workspace.db_path),
            "--dry-run",
            "--json",
        ],
        timeout=45,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    data = json.loads(proc.stdout)
    assert data["status"] == "dry_run_plan_ready"
    assert data["dry_run"] is True
    assert data["side_effects"]["network_packets_sent"] == 0
    assert data["side_effects"]["filesystem_mutations"] == 0
    assert data["planned_modules"]


def test_t1_f17_cli_all_json_writes_sarif_and_summary_with_loopback_ollama(
    cli_runner, e2e_workspace, loopback_ollama, pe_builder
) -> None:
    e2e_workspace.write_repo_file("vuln.py", "import subprocess\ndef run(c):\n    return subprocess.run(c, shell=True)\n")
    (e2e_workspace.repo / "bypass.dll").write_bytes(pe_builder.build_cve_2026_108398_dotnet())

    def _ollama_handler(path: str, body: Dict[str, Any], headers: Dict[str, str]):
        model_name = str(body.get("model") or "qwen2.5:14b")
        user_msg = "\n".join(
            str(m.get("content") or "")
            for m in (body.get("messages") or [])
            if m.get("role") == "user"
        )
        if "Mantis Threat Modeling" in user_msg or "threat surface summary" in user_msg:
            payload: Any = {"summary": "Threat model analyzed cleanly.", "threat_actors": ["Attacker"]}
        elif "Prioritize the fenced candidate hypotheses" in user_msg:
            payload = [{"id": "HYP-1", "priority_note": "High risk"}]
        elif "Mantis Zero-Day Vulnerability Synthesis" in user_msg or "Synthesize zero-day hypotheses" in user_msg:
            payload = {"hypotheses": []}
        elif "ARTEX Dynamic Chain Planner" in user_msg or "dual_graph_snapshot" in user_msg:
            payload = {"intents": []}
        else:
            payload = {"executive_summary": "Audit completed cleanly."}
        return 200, {
            "model": model_name,
            "message": {"role": "assistant", "content": json.dumps(payload)},
            "done": True,
        }

    loopback_ollama.set_handler(_ollama_handler)
    proc = cli_runner(
        _run_offline_all_args(
            e2e_workspace,
            loopback_ollama,
            "rfc_hunt_swarm.py",
            extra=[
                "--no-h2-desync",
                "--no-arxiv-detect",
                "--no-last30days-skills",
                "--no-verification-inversion",
                "--no-rea-cli",
            ],
        ),
        env_overrides={
            "OLLAMA_ENDPOINT": loopback_ollama.url,
            "LOCAL_OLLAMA_ENDPOINT": loopback_ollama.url,
            "RFCHUNT_OFFLINE": "0",
            "RFCHUNT_FORCE_OLLAMA": "1",
            "PYTEST_CURRENT_TEST": None,
            "CI": None,
            "GITHUB_ACTIONS": None,
        },
        timeout=60,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    data = json.loads(proc.stdout)
    assert "combined_report.sarif" in (data.get("report_files") or {}).get("combined_sarif", "")
    assert (e2e_workspace.output_dir / "combined_report.sarif").is_file()
    assert (e2e_workspace.output_dir / "combined_audit_summary.json").is_file()
    assert loopback_ollama.get_requests("/api/chat"), "Expected live loopback /api/chat calls when PYTEST_CURRENT_TEST is cleared"
    assert loopback_ollama.get_requests("/api/generate") == []


def test_t1_f17_main_py_all_shim_parity(cli_runner, e2e_workspace, loopback_ollama) -> None:
    e2e_workspace.write_repo_file("calc.py", "def f(x):\n    return eval(x)\n")
    proc = cli_runner(
        _run_offline_all_args(e2e_workspace, loopback_ollama, "main.py"),
        env_overrides={
            "OLLAMA_ENDPOINT": loopback_ollama.url,
            "LOCAL_OLLAMA_ENDPOINT": loopback_ollama.url,
            "RFCHUNT_OFFLINE": "1",
        },
        timeout=60,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    data = json.loads(proc.stdout)
    assert data["total_aggregated_findings"] >= 1
    assert (e2e_workspace.output_dir / "combined_report.sarif").is_file()
    assert (e2e_workspace.output_dir / "combined_audit_summary.json").is_file()


def test_t1_f17_swarm_cli_board_renders_and_tracks_pe_auditor() -> None:
    board_mod = importlib.import_module("engine.swarm_cli_board")
    board = board_mod.create_all_scan_board("repo_e2e", plain=True)
    task_names = set(getattr(board, "tasks", {}).keys())
    has_pe_task = any("pe" in k.lower() or "dotnet" in k.lower() for k in task_names)
    assert has_pe_task, f"M4: create_all_scan_board missing PE/.NET auditor task; tasks={sorted(task_names)}"

    board_mod.update_all_board_from_result(
        board,
        {
            "mantis": {"status": "completed", "total_findings": 1},
            "pe_dotnet_auditor": {"status": "completed", "total_findings": 2},
        },
    )
    rendered = board.render(plain=True, width=100)
    assert "RFCHunt --all" in rendered
    assert "pe" in rendered.lower() or "dotnet" in rendered.lower()


def test_t1_f17_build_sarif_document_schema_validity(e2e_workspace) -> None:
    mantis_mod = importlib.import_module("engine.mantis_integrator")
    findings = [
        {
            "rule_id": "PE-DOTNET-CVE-2026-108398",
            "title": ".NET Assembly with 0x0002 Cleared",
            "severity": "HIGH",
            "cwe": "CWE-693",
            "file_path": str(e2e_workspace.repo / "bypass.dll"),
            "line_number": 1,
            "description": "Triggers SEC_COMMIT fallback",
            "evidence": "Characteristics=0x2000",
            "sink": "PE:COFF.Characteristics",
            "remediation": "Set 0x0002 and install KB5127694",
            "scanner": "Module-PE-DotNet-Auditor",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "poe_level": 2,
        },
        {
            "rule_id": "MANTIS-EVAL-002",
            "title": "Arbitrary eval sink",
            "severity": "CRITICAL",
            "cwe": "CWE-95",
            "file_path": str(e2e_workspace.repo / "app.py"),
            "line_number": 12,
            "description": "eval(user_input)",
            "evidence": "eval(x)",
            "sink": "eval",
            "remediation": "Use ast.literal_eval",
            "scanner": "Module-20-Mantis",
            "evidence_lane": "DETERMINISTIC_STATIC",
            "poe_level": 2,
        },
    ]
    sarif = mantis_mod.build_sarif_document(
        tool_name="RFCHunt-Unified-All-Scans",
        tool_uri="https://example.local/rfchunt",
        target_root=str(e2e_workspace.repo),
        findings=findings,
    )
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    rule_ids_driver = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rule_ids_driver == {"PE-DOTNET-CVE-2026-108398", "MANTIS-EVAL-002"}
    assert len(run["results"]) == 2
    for res in run["results"]:
        assert res["ruleId"] in rule_ids_driver
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] in ("bypass.dll", "app.py")
        assert loc["region"]["startLine"] >= 1
