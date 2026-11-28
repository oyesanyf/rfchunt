"""
Tier 2 E2E Tests: Boundary, Corner & Error Cases for PE/.NET, CLI, & MCP (Features #12-#17).

Covers 5 distinct boundary/corner/error tests per feature (30 total tests):
- F12: Truncated/malformed PE headers (<64B, e_lfanew OOB, opt_hdr_size=40, RvaCount=0/>16, corrupt BSJB)
- F13: UMCI/SEC_COMMIT boundary heuristics (0/120 sections, truncated section table, overlapping sections, COR20 boundaries, clean native DLL)
- F14: YARA boundary/error cases (empty buffer, 1-byte file, 2MB non-PE, malformed rule validation, clean native DLL)
- F15: Host patch-level boundaries (VirtualBox 7.2.17 vs 7.2.18 vs 7.2.19, 7.0.20, binary vs registry mismatch, malformed version, empty/case-insensitive KBs, staged state 64, non-Windows)
- F16: MCP HTTP/stdio boundary & auth cases (missing target, Bearer 401, Origin 403, invalid params -32602, unknown method -32601 / parse error -32700)
- F17: CLI `--all` & SARIF boundary cases (missing repo, unauthorized non-loopback target exit 1, negative ARTEX budget exit 1, --export-sarif traversal, NaN/NUL SARIF sanitization)
"""

from __future__ import annotations

import http.client
import importlib
import json
from pathlib import Path
import struct
from typing import Any, Dict, Tuple

import pytest

pytestmark = pytest.mark.tier2


def _pe_mod():
    return importlib.import_module("engine.pe_magika_classifier")


def _build_pe_with_rsrc_version(version_tuple: Tuple[int, int, int, int]) -> bytes:
    pe_mod = _pe_mod()
    major, minor, patch, build = version_tuple
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)
    buf[lfanew : lfanew + 4] = b"PE\x00\x00"

    opt_hdr_size = 240
    struct.pack_into("<HHIIIHH", buf, lfanew + 4, 0x8664, 1, 0, 0, 0, opt_hdr_size, pe_mod.IMAGE_FILE_EXECUTABLE_IMAGE)
    opt_off = lfanew + 24
    struct.pack_into("<H", buf, opt_off, 0x020B)
    struct.pack_into("<II", buf, opt_off + 32, 0x2000, 0x200)
    struct.pack_into("<II", buf, opt_off + 56, 0x4000, 0x200)
    struct.pack_into("<HH", buf, opt_off + 68, 3, 0)
    rva_off = opt_off + 108
    struct.pack_into("<I", buf, rva_off, 16)
    struct.pack_into("<II", buf, rva_off + 4 + (2 * 8), 0x2000, 0x180)

    sec_off = opt_off + opt_hdr_size
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off, b".rsrc\x00\x00\x00", 0x180, 0x2000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)

    rb = 0x200
    struct.pack_into("<IIHHHH", buf, rb + 0x00, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rb + 0x10, 16, 0x80000000 | 0x18)
    struct.pack_into("<IIHHHH", buf, rb + 0x18, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rb + 0x28, 1, 0x80000000 | 0x30)
    struct.pack_into("<IIHHHH", buf, rb + 0x30, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rb + 0x40, 0x0409, 0x48)
    struct.pack_into("<IIII", buf, rb + 0x48, 0x2060, 64, 1200, 0)
    fv_ms = (major << 16) | minor
    fv_ls = (patch << 16) | build
    struct.pack_into("<13I", buf, rb + 0x68, 0xFEEF04BD, 0x00010000, fv_ms, fv_ls, fv_ms, fv_ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    return bytes(buf)


def _build_spec_pe(
    *,
    is_64bit: bool = True,
    characteristics: int = 0x2002,
    section_alignment: int = 0x2000,
    file_alignment: int = 0x200,
    size_of_image: int = 0x4000,
    size_of_headers: int = 0x200,
    include_clr: bool = True,
    cor20_flags: int = 0x00000001,
    strong_name_rva: int = 0,
    strong_name_size: int = 0,
    extra_sections: int = 0,
) -> bytes:
    buf = bytearray(0x600 + extra_sections * 0x200)
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)
    buf[lfanew : lfanew + 4] = b"PE\x00\x00"
    machine = 0x8664 if is_64bit else 0x014C
    opt_hdr_size = 240 if is_64bit else 224
    struct.pack_into("<HHIIIHH", buf, lfanew + 4, machine, 1 + extra_sections, 0, 0, 0, opt_hdr_size, characteristics)

    opt_off = lfanew + 24
    struct.pack_into("<H", buf, opt_off, 0x020B if is_64bit else 0x010B)
    struct.pack_into("<II", buf, opt_off + 32, section_alignment, file_alignment)
    struct.pack_into("<II", buf, opt_off + 56, size_of_image, size_of_headers)
    struct.pack_into("<HH", buf, opt_off + 68, 3, 0x8540)

    rva_off = opt_off + (108 if is_64bit else 92)
    struct.pack_into("<I", buf, rva_off, 16)
    if include_clr:
        struct.pack_into("<II", buf, rva_off + 4 + (14 * 8), 0x2000, 72)

    sec_off = opt_off + opt_hdr_size
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off, b".text\x00\x00\x00", 0x300, 0x2000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020)

    if include_clr:
        struct.pack_into(
            "<IHHIIIIIIIIIIIIIIII",
            buf,
            0x200,
            72,
            2,
            5,
            0x2080,
            64,
            cor20_flags,
            0,
            0,
            0,
            strong_name_rva,
            strong_name_size,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        bsjb = bytearray(b"BSJB")
        bsjb.extend(struct.pack("<HHI", 1, 1, 0))
        bsjb.extend(struct.pack("<I", 12))
        bsjb.extend(b"v4.0.30319\x00\x00")
        bsjb.extend(struct.pack("<HH", 0, 2))
        bsjb.extend(struct.pack("<II", 0x100, 0x200))
        bsjb.extend(b"#~\x00\x00")
        bsjb.extend(struct.pack("<II", 0x300, 0x400))
        bsjb.extend(b"#Strings\x00\x00\x00\x00")
        buf[0x280 : 0x280 + len(bsjb)] = bsjb
    return bytes(buf)


# =============================================================================
# F12 Boundaries: Truncated / Malformed PE & BSJB Headers (5 tests)
# =============================================================================


def test_t2_f12_truncated_pe_under_64_bytes(pe_builder) -> None:
    pe_mod = _pe_mod()
    for raw, name in (
        (b"", "empty.exe"),
        (b"MZ", "two_bytes.exe"),
        (pe_builder.build_truncated_pe("short_mz"), "short_mz.exe"),
        (b"MZ" + b"\x00" * 61, "63bytes.dll"),
    ):
        rep = pe_mod.inspect_pe_binary(raw, name)
        assert rep.is_pe is False
        assert rep.dot_net.is_dot_net is False


def test_t2_f12_out_of_bounds_lfanew(pe_builder) -> None:
    pe_mod = _pe_mod()
    bad_high = pe_builder.build_truncated_pe("bad_lfanew")
    rep_high = pe_mod.inspect_pe_binary(bad_high, "bad_high.exe")
    assert rep_high.is_pe is True
    assert rep_high.umci_fallback_risk is True
    assert any("e_lfanew" in a for a in rep_high.anomalies)

    bad_low = bytearray(128)
    bad_low[0:2] = b"MZ"
    struct.pack_into("<I", bad_low, 0x3C, 0x10)
    rep_low = pe_mod.inspect_pe_binary(bytes(bad_low), "bad_low.exe")
    assert rep_low.umci_fallback_risk is True
    assert any("e_lfanew" in a for a in rep_low.anomalies)


def test_t2_f12_short_optional_header_size_40(pe_builder) -> None:
    pe_mod = _pe_mod()
    short_opt = pe_builder.build_truncated_pe("short_opt")
    rep = pe_mod.inspect_pe_binary(short_opt, "short_opt.exe")
    assert rep.is_pe is True
    assert rep.umci_fallback_risk is True
    assert any("OptionalHeader" in a for a in rep.anomalies)


def test_t2_f12_number_of_rva_and_sizes_zero_and_gt_16(pe_builder) -> None:
    pe_mod = _pe_mod()
    base = bytearray(
        pe_builder.build_pe(
            is_64bit=True,
            characteristics=pe_builder.IMAGE_FILE_EXECUTABLE_IMAGE | pe_builder.IMAGE_FILE_DLL,
            include_clr_dir=True,
            include_bsjb=False,
        )
    )
    # NumberOfRvaAndSizes = 0 -> must ignore DataDirectory[14]
    zero_rva = bytearray(base)
    struct.pack_into("<I", zero_rva, 0x80 + 24 + 108, 0)
    rep_zero = pe_mod.inspect_pe_binary(bytes(zero_rva), "ZeroRva.dll")
    assert rep_zero.dot_net.is_dot_net is False
    assert rep_zero.dot_net.clr_header_rva == 0

    # NumberOfRvaAndSizes = 99 -> triggers UMCI anomaly safely without OOB read
    huge_rva = bytearray(base)
    struct.pack_into("<I", huge_rva, 0x80 + 24 + 108, 99)
    rep_huge = pe_mod.inspect_pe_binary(bytes(huge_rva), "HugeRva.dll")
    assert rep_huge.is_pe is True
    assert rep_huge.dot_net.is_dot_net is True


def test_t2_f12_corrupt_bsjb_magic_and_bad_version() -> None:
    pe_mod = _pe_mod()
    # Corrupt magic
    bad_magic = b"MZ" + b"\x00" * 100 + b"BSJX\x01\x00\x01\x00\x00\x00\x00\x00\x0c\x00\x00\x00v4.0.30319\x00\x00"
    assert pe_mod.find_valid_dotnet_bsjb_header(bad_magic) is None

    # Reserved != 0 and invalid ver_len
    bad_reserved = b"BSJB" + struct.pack("<HHI", 1, 1, 99) + struct.pack("<I", 12) + b"v4.0.30319\x00\x00" + b"\x00" * 32
    assert pe_mod.find_valid_dotnet_bsjb_header(bad_reserved) is None

    bad_ver = b"BSJB" + struct.pack("<HHI", 1, 1, 0) + struct.pack("<I", 12) + b"x4.0.30319\x00\x00" + b"\x00" * 32
    assert pe_mod.find_valid_dotnet_bsjb_header(bad_ver) is None


# =============================================================================
# F13 Boundaries: UMCI / SEC_COMMIT Edge Cases (5 tests)
# =============================================================================


def test_t2_f13_umci_zero_and_excessive_section_count() -> None:
    pe_mod = _pe_mod()
    buf_zero = bytearray(_build_spec_pe())
    struct.pack_into("<H", buf_zero, 0x80 + 6, 0)
    rep_zero = pe_mod.inspect_pe_binary(bytes(buf_zero), "ZeroSec.dll")
    assert rep_zero.umci_fallback_risk is True
    assert any("NumberOfSections=0" in a for a in rep_zero.anomalies)

    buf_many = bytearray(_build_spec_pe())
    struct.pack_into("<H", buf_many, 0x80 + 6, 120)
    rep_many = pe_mod.inspect_pe_binary(bytes(buf_many), "ManySec.dll")
    assert rep_many.umci_fallback_risk is True
    assert any("NumberOfSections=120" in a for a in rep_many.anomalies)


def test_t2_f13_umci_truncated_section_table_and_oob_raw_data() -> None:
    pe_mod = _pe_mod()
    buf_trunc = bytearray(_build_spec_pe())
    struct.pack_into("<H", buf_trunc, 0x80 + 6, 40)  # 40*40 bytes exceeds len(buf)
    rep_trunc = pe_mod.inspect_pe_binary(bytes(buf_trunc), "TruncSecTable.dll")
    assert rep_trunc.umci_fallback_risk is True

    buf_oob = bytearray(_build_spec_pe())
    struct.pack_into("<I", buf_oob, 0x80 + 24 + 240 + 16, 0x10000)  # SizeOfRawData > len
    rep_oob = pe_mod.inspect_pe_binary(bytes(buf_oob), "OobRaw.dll")
    assert rep_oob.umci_fallback_risk is True


def test_t2_f13_umci_overlapping_and_non_ascending_sections() -> None:
    pe_mod = _pe_mod()
    buf = bytearray(_build_spec_pe(extra_sections=1))
    sec1 = 0x80 + 24 + 240 + 40
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        sec1,
        b".rdata\x00\x00",
        0x200,
        0x2100,  # overlaps .text [0x2000, 0x2300)
        0x200,
        0x200,   # overlaps .text raw range [0x200, 0x600)
        0,
        0,
        0,
        0,
        0x40000040,
    )
    rep = pe_mod.inspect_pe_binary(bytes(buf), "Overlap.dll")
    assert rep.umci_fallback_risk is True


def test_t2_f13_umci_cor20_boundary_flags() -> None:
    pe_mod = _pe_mod()
    # STRONGNAMESIGNED without StrongNameSignature RVA/Size
    sn_bad = _build_spec_pe(cor20_flags=0x00000001 | 0x00000008, strong_name_rva=0, strong_name_size=0)
    assert pe_mod.inspect_pe_binary(sn_bad, "BadStrongName.dll").umci_fallback_risk is True

    # 32BITPREFERRED without 32BITREQUIRED on 32-bit PE
    pref_bad = _build_spec_pe(is_64bit=False, cor20_flags=0x00000001 | 0x00020000)
    assert pe_mod.inspect_pe_binary(pref_bad, "BadPref.dll").umci_fallback_risk is True


def test_t2_f13_umci_clean_delay_signed_and_clean_native_dll() -> None:
    pe_mod = _pe_mod()
    delay_signed = _build_spec_pe(
        is_64bit=True,
        cor20_flags=0x00000001,  # ILONLY only; STRONGNAMESIGNED cleared for delay signing
        strong_name_rva=0x2100,
        strong_name_size=128,
    )
    rep_ds = pe_mod.inspect_pe_binary(delay_signed, "DelaySigned.dll")
    assert rep_ds.umci_fallback_risk is False
    assert rep_ds.anomalies == []

    native_dll = _build_spec_pe(is_64bit=True, characteristics=0x2002, include_clr=False)
    rep_native = pe_mod.inspect_pe_binary(native_dll, "CleanNative.dll")
    assert rep_native.umci_fallback_risk is False
    assert rep_native.dot_net.is_dot_net is False
    assert rep_native.anomalies == []


# =============================================================================
# F14 Boundaries: YARA Edge Cases (5 tests)
# =============================================================================


def test_t2_f14_yara_empty_buffer_and_one_byte_file() -> None:
    pe_mod = _pe_mod()
    for raw, fname in ((b"", "empty.bin"), (b"M", "onebyte.bin")):
        res = pe_mod.match_pe_dotnet_yara(raw, file_path=fname)
        assert res["matched"] is False
        assert res["rule_names"] == []


def test_t2_f14_yara_oversized_2mb_non_pe_buffer() -> None:
    pe_mod = _pe_mod()
    big_non_pe = b"A" * (2 * 1024 * 1024)
    res = pe_mod.match_pe_dotnet_yara(big_non_pe, file_path="large.bin")
    assert res["matched"] is False
    assert res["rule_names"] == []


def test_t2_f14_yara_corrupted_rules_fail_validation() -> None:
    pe_mod = _pe_mod()
    bad_rules = (
        "",
        "   \n\t ",
        'rule no_cond { strings: $a = "MZ" }',
        "rule unclosed { condition: true ",
        'rule missing_str { strings: $a = "x" condition: $nope }',
        'rule bad_hex { strings: $h = { GG } condition: $h }',
        "rule dup { condition: true }\nrule dup { condition: false }",
    )
    for src in bad_rules:
        res = pe_mod.validate_yara_rules(src)
        assert res["valid"] is False, f"Expected invalid YARA rule to fail: {src!r}"
        assert res["errors"]


def test_t2_f14_yara_clean_native_dll_without_clr() -> None:
    pe_mod = _pe_mod()
    native_dll = _build_spec_pe(is_64bit=True, characteristics=0x2002, include_clr=False)
    res = pe_mod.match_pe_dotnet_yara(native_dll, file_path="NativeClean.dll")
    assert res["matched"] is False
    assert res["rule_names"] == []


def test_t2_f14_yara_match_returns_invalid_on_malformed_custom_rule() -> None:
    pe_mod = _pe_mod()
    res = pe_mod.match_pe_dotnet_yara(b"MZ\x00\x00", rules_text="rule broken { condition: ", file_path="x.dll")
    assert res["matched"] is False
    assert res["validation"]["valid"] is False
    assert res["validation"]["errors"]


# =============================================================================
# F15 Boundaries: Host Patch-Level Boundary Versions & States (5 tests)
# =============================================================================


def test_t2_f15_virtualbox_version_boundary_7_2_17_vs_18_vs_19() -> None:
    pe_mod = _pe_mod()
    for ver, expected_status in (("7.2.17", "vulnerable"), ("7.2.18", "patched"), ("7.2.19", "patched")):
        res = pe_mod.audit_host_patch_levels(
            host_snapshot={
                "platform": "win32",
                "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
                "virtualbox": {"installed": True, "registry_version": ver, "binary_version": f"{ver}.0"},
            }
        )
        assert res["virtualbox"]["status"] == expected_status, f"VirtualBox {ver} -> {res['virtualbox']}"


def test_t2_f15_virtualbox_legacy_7_0_20_and_binary_vs_registry_mismatch() -> None:
    pe_mod = _pe_mod()
    legacy = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
            "virtualbox": {"installed": True, "registry_version": "7.0.20"},
        }
    )
    assert legacy["virtualbox"]["status"] == "vulnerable"

    # Binary 7.2.17.0 overrides registry claim 7.2.18
    old_bin = _build_pe_with_rsrc_version((7, 2, 17, 0))
    spoofed = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
            "virtualbox": {"installed": True, "registry_version": "7.2.18", "binary_bytes": old_bin},
        }
    )
    assert spoofed["virtualbox"]["status"] == "vulnerable"
    assert any(f["rule_id"] == "HOST-PATCH-VBOX-7218" for f in spoofed["findings"])


def test_t2_f15_virtualbox_malformed_or_missing_version_string() -> None:
    pe_mod = _pe_mod()
    res = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": False},
            "virtualbox": {"installed": True, "registry_version": "unknown-build", "binary_version": None},
        }
    )
    assert res["virtualbox"]["status"] == "unknown"


def test_t2_f15_kb5127694_empty_kbs_vs_case_insensitive_and_staged_64() -> None:
    pe_mod = _pe_mod()
    empty_res = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 22631, "ubr": 4000, "dotnet_v4_installed": True, "cbs_enumerated": True, "cbs_packages": [], "hotfixes": []},
            "virtualbox": {"installed": False},
        }
    )
    assert empty_res["kb5127694"]["status"] == "vulnerable"

    lower_res = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 22631, "ubr": 4000, "dotnet_v4_installed": True, "hotfixes": ["kb5127694"]},
            "virtualbox": {"installed": False},
        }
    )
    assert lower_res["kb5127694"]["status"] == "patched"

    staged_res = pe_mod.audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {
                "current_build": 26300,
                "ubr": 9000,
                "dotnet_v4_installed": True,
                "cbs_enumerated": True,
                "cbs_packages": [{"name": "Package_for_KB5127694~amd64~~26300.10008", "current_state": 64}],
            },
            "virtualbox": {"installed": False},
        }
    )
    assert staged_res["kb5127694"]["status"] == "vulnerable"
    assert staged_res["kb5127694"]["pending_reboot"] is True


def test_t2_f15_non_windows_and_corrupt_rsrc_vs_fixedfileinfo() -> None:
    pe_mod = _pe_mod()
    non_win = pe_mod.audit_host_patch_levels(host_snapshot={"platform": "darwin"})
    assert non_win["kb5127694"]["status"] == "not_applicable"
    assert non_win["virtualbox"]["status"] == "not_applicable"
    assert non_win["findings"] == []

    assert pe_mod.extract_pe_fixed_file_info(b"NOT_A_PE") is None
    assert pe_mod.extract_pe_fixed_file_info(b"MZ" + b"\x00" * 30) is None


# =============================================================================
# F16 Boundaries: MCP HTTP/Stdio & PE Auditor Target Error Cases (5 tests)
# =============================================================================


def test_t2_f16_audit_pe_dotnet_target_missing_dir_and_nul_byte(e2e_workspace) -> None:
    pe_mod = _pe_mod()
    res = pe_mod.audit_pe_dotnet_target(e2e_workspace.root / "missing_dir", include_host_audit=False)
    assert res["status"] == "target_not_found"
    assert res["files_scanned"] == 0

    with pytest.raises(ValueError):
        pe_mod.audit_pe_dotnet_target("bad\x00path.dll", include_host_audit=False)


def test_t2_f16_mcp_http_server_rejects_unauthenticated_bearer_401(e2e_workspace) -> None:
    mcp_mod = importlib.import_module("mcp_server")
    srv = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))
    http_srv = mcp_mod.MCPHttpServer(srv, host="127.0.0.1", port=0, bearer_token="top-secret-token")
    host, port = http_srv.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
        conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
        resp1 = conn.getresponse()
        resp1.read()
        assert resp1.status == 401

        conn.request(
            "POST",
            "/mcp",
            body=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer wrong-token"},
        )
        resp2 = conn.getresponse()
        resp2.read()
        assert resp2.status == 401
        conn.close()
    finally:
        http_srv.stop()


def test_t2_f16_mcp_http_server_rejects_disallowed_origin_403(e2e_workspace) -> None:
    mcp_mod = importlib.import_module("mcp_server")
    srv = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))
    http_srv = mcp_mod.MCPHttpServer(srv, host="127.0.0.1", port=0, bearer_token="tok-403")
    host, port = http_srv.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}})
        conn.request(
            "POST",
            "/mcp",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer tok-403",
                "Origin": "https://attacker.example.com",
            },
        )
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 403
        conn.close()
    finally:
        http_srv.stop()


def test_t2_f16_mcp_server_invalid_params_returns_minus_32602(e2e_workspace) -> None:
    mcp_mod = importlib.import_module("mcp_server")
    srv = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))
    resp = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "run_all_scans",
                "arguments": {"repo": str(e2e_workspace.repo), "depth": "not_an_int"},
            },
        }
    )
    assert resp["error"]["code"] == -32602

    resp2 = srv.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "run_all_scans",
                "arguments": {"repo": str(e2e_workspace.repo), "approval_mode": "allow_everything_bogus"},
            },
        }
    )
    assert resp2["error"]["code"] == -32602


def test_t2_f16_mcp_server_unknown_method_and_malformed_json(e2e_workspace) -> None:
    mcp_mod = importlib.import_module("mcp_server")
    srv = mcp_mod.TerminatorMCPServer(db_path=str(e2e_workspace.db_path))

    r_unknown = srv.handle_request({"jsonrpc": "2.0", "id": 10, "method": "nonexistent/method", "params": {}})
    assert r_unknown["error"]["code"] == -32601

    r_bad_req = srv.handle_request([])  # type: ignore[arg-type]
    assert r_bad_req["error"]["code"] == -32600

    http_srv = mcp_mod.MCPHttpServer(srv, host="127.0.0.1", port=0, bearer_token=None)
    host, port = http_srv.start()
    try:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/mcp", body="{bad json", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        payload = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 400
        assert payload["error"]["code"] == -32700

        conn.request("POST", "/mcp", body="[]", headers={"Content-Type": "application/json"})
        resp_batch_empty = conn.getresponse()
        payload_batch_empty = json.loads(resp_batch_empty.read().decode("utf-8"))
        assert resp_batch_empty.status == 400
        assert payload_batch_empty["error"]["code"] == -32600
        conn.close()
    finally:
        http_srv.stop()


# =============================================================================
# F17 Boundaries: CLI `--all` & SARIF Validation Error Cases (5 tests)
# =============================================================================


def test_t2_f17_cli_all_missing_repo_handled_gracefully(cli_runner, e2e_workspace) -> None:
    missing_repo = e2e_workspace.root / "missing_repo_xyz"
    proc = cli_runner(
        [
            "rfc_hunt_swarm.py",
            "--all",
            "--repo",
            str(missing_repo),
            "--output-dir",
            str(e2e_workspace.output_dir),
            "--db",
            str(e2e_workspace.db_path),
            "--depth",
            "10",
            "--mantis-mode",
            "fast",
            "--no-include-models",
            "--no-external-scanners",
            "--no-preflight",
            "--no-auto-install",
            "--json",
        ],
        timeout=45,
    )
    assert "Traceback (most recent call last)" not in proc.stderr
    assert proc.returncode in (0, 1)


def test_t2_f17_cli_all_unauthorized_non_loopback_target_exit_1(cli_runner, e2e_workspace) -> None:
    proc = cli_runner(
        [
            "rfc_hunt_swarm.py",
            "--all",
            "--host",
            "93.184.216.34",
            "--db",
            str(e2e_workspace.db_path),
        ],
        timeout=30,
    )
    assert proc.returncode == 1


def test_t2_f17_cli_all_invalid_artex_budget_exit_1(cli_runner, e2e_workspace) -> None:
    proc = cli_runner(
        [
            "rfc_hunt_swarm.py",
            "--all",
            "--repo",
            str(e2e_workspace.repo),
            "--artex-intent-turns",
            "-5",
            "--db",
            str(e2e_workspace.db_path),
            "--json",
        ],
        timeout=30,
    )
    assert proc.returncode == 1


def test_t2_f17_cli_all_export_sarif_traversal_blocked(cli_runner, e2e_workspace) -> None:
    e2e_workspace.write_repo_file("app.py", "print(1)\n")
    escape_sarif = e2e_workspace.root / "escape.sarif"
    proc = cli_runner(
        [
            "rfc_hunt_swarm.py",
            "--all",
            "--repo",
            str(e2e_workspace.repo),
            "--output-dir",
            str(e2e_workspace.output_dir),
            "--export-sarif",
            "../escape.sarif",
            "--db",
            str(e2e_workspace.db_path),
            "--depth",
            "10",
            "--mantis-mode",
            "fast",
            "--no-include-models",
            "--no-external-scanners",
            "--no-preflight",
            "--no-auto-install",
            "--json",
        ],
        timeout=60,
    )
    assert proc.returncode == 1
    assert not escape_sarif.exists()


def test_t2_f17_build_sarif_document_nan_line_and_nul_filepath(e2e_workspace) -> None:
    mantis_mod = importlib.import_module("engine.mantis_integrator")
    sarif = mantis_mod.build_sarif_document(
        tool_name="RFCHunt",
        tool_uri="https://example.local",
        target_root=str(e2e_workspace.repo),
        findings=[
            {
                "rule_id": "PE-DOTNET-UMCI-001",
                "title": "CONFIRMED: Spoofed speculative title",
                "severity": "HIGH",
                "cwe": "CWE-693",
                "file_path": "../../../../etc/passwd\x00.dll",
                "line_number": float("nan"),
                "poe_level": 1,
                "scanner": "Module-PE-DotNet-Auditor",
            }
        ],
    )
    res = sarif["runs"][0]["results"][0]
    phys = res["locations"][0]["physicalLocation"]
    assert "\x00" not in phys["artifactLocation"]["uri"]
    assert ".." not in phys["artifactLocation"]["uri"]
    assert phys["region"]["startLine"] == 1
    assert "CONFIRMED:" not in res["message"]["text"]
