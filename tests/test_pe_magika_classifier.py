"""
Unit tests for Google Magika PE & .NET Binary Identification & Code Integrity Anomaly Auditor.
"""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import pytest

from engine.pe_magika_classifier import (
    identify_with_magika,
    inspect_pe_binary,
    structural_magika_classify,
    find_valid_dotnet_bsjb_header,
    generate_pe_dotnet_yara_rules,
    validate_yara_rules,
    match_pe_dotnet_yara,
    extract_pe_fixed_file_info,
    audit_host_patch_levels,
    audit_pe_dotnet_target,
    _parse_yara_rules_text,
    _evaluate_parsed_yara_rules,
    _safe_int,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_DLL,
    IMAGE_SUBSYSTEM_NATIVE,
    IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    COMIMAGE_FLAGS_ILONLY,
    COMIMAGE_FLAGS_32BITREQUIRED,
    COMIMAGE_FLAGS_STRONGNAMESIGNED,
    COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,
    COMIMAGE_FLAGS_32BITPREFERRED,
    HOST_PATCH_STATUSES,
)


def _build_synthetic_pe(
    is_64bit: bool = True,
    characteristics: int = IMAGE_FILE_EXECUTABLE_IMAGE,
    include_clr_dir: bool = False,
    include_bsjb: bool = False,
    bsjb_version: str = "v4.0.30319",
) -> bytes:
    """Constructs a deterministic synthetic PE binary for unit testing."""
    buf = bytearray(512)
    # DOS Header
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)

    # PE Signature
    buf[lfanew:lfanew + 4] = b"PE\x00\x00"

    # COFF File Header: Machine, NumSections, TimeDate, PtrSymbols, NumSymbols, SizeOptHdr, Characteristics
    machine = 0x8664 if is_64bit else 0x014C
    opt_hdr_size = 240 if is_64bit else 224
    struct.pack_into(
        "<HHIIIHH",
        buf,
        lfanew + 4,
        machine,
        1,       # 1 section
        0,       # timestamp
        0, 0,
        opt_hdr_size,
        characteristics,
    )

    # Optional Header: Magic
    opt_offset = lfanew + 24
    magic = 0x020B if is_64bit else 0x010B
    struct.pack_into("<H", buf, opt_offset, magic)

    # Number of Rva and Sizes
    rva_count_offset = opt_offset + (108 if is_64bit else 92)
    struct.pack_into("<I", buf, rva_count_offset, 16)

    # Data Directory 14 (COM Descriptor / CLR Header)
    com_offset = rva_count_offset + 4 + (14 * 8)
    if include_clr_dir:
        struct.pack_into("<II", buf, com_offset, 0x2000, 72)  # RVA 0x2000, Size 72

    if include_bsjb:
        # Append valid ECMA-335 BSJB CLR Metadata Root
        ver_bytes = bsjb_version.encode("ascii")
        ver_len = (len(ver_bytes) + 3) & ~3
        # BSJB Header: Signature, Major(1), Minor(1), Reserved(0), Length, VersionString
        buf.extend(b"BSJB")
        buf.extend(struct.pack("<HHI", 1, 1, 0))
        buf.extend(struct.pack("<I", ver_len))
        buf.extend(ver_bytes.ljust(ver_len, b"\x00"))
        # Flags (2 bytes), Streams count (2 bytes)
        buf.extend(struct.pack("<HH", 0, 2))
        # Stream 1: offset (4), size (4), name "#~" (aligned to 4 bytes: '#', '~', 0, pad)
        buf.extend(struct.pack("<II", 0x100, 0x200))
        buf.extend(b"#~\x00\x00")
        # Stream 2: offset (4), size (4), name "#Strings" (aligned: '#', 'S', 't', 'r', 'i', 'n', 'g', 's', 0, pad*3)
        buf.extend(struct.pack("<II", 0x300, 0x400))
        buf.extend(b"#Strings\x00\x00\x00\x00")

    return bytes(buf)


def _build_valid_dotnet_pe(
    *,
    is_64bit: bool = True,
    characteristics: int = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
    section_alignment: int = 0x2000,
    file_alignment: int = 0x200,
    size_of_image: int = 0x4000,
    size_of_headers: int = 0x200,
    entry_point: int = 0,
    subsystem: int = IMAGE_SUBSYSTEM_WINDOWS_CUI,
    dll_characteristics: int = 0x8540,  # DYNAMIC_BASE | NX_COMPAT | NO_SEH | TERMINAL_SERVER_AWARE (no FORCE_INTEGRITY/GUARD_CF)
    include_clr: bool = True,
    clr_dir_size: int = 72,
    cor20_cb: int = 72,
    cor20_major_rt: int = 2,
    cor20_flags: int = COMIMAGE_FLAGS_ILONLY,
    strong_name_rva: int = 0,
    strong_name_size: int = 0,
    section_chars: int = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    bsjb_version: str = "v4.0.30319",
    extra_sections: int = 0,
) -> bytes:
    """Construct a spec-compliant PE32/PE32+ or .NET assembly with full OptionalHeader, Section, and COR20 layout."""
    total_sections = 1 + extra_sections
    buf = bytearray(0x600 + extra_sections * 0x200)
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)
    buf[lfanew:lfanew + 4] = b"PE\x00\x00"

    machine = 0x8664 if is_64bit else 0x014C
    opt_hdr_size = 240 if is_64bit else 224
    struct.pack_into(
        "<HHIIIHH",
        buf,
        lfanew + 4,
        machine,
        total_sections,
        0,
        0,
        0,
        opt_hdr_size,
        characteristics,
    )

    opt_offset = lfanew + 24
    magic = 0x020B if is_64bit else 0x010B
    struct.pack_into("<H", buf, opt_offset, magic)
    struct.pack_into("<I", buf, opt_offset + 16, entry_point)
    struct.pack_into("<II", buf, opt_offset + 32, section_alignment, file_alignment)
    struct.pack_into("<II", buf, opt_offset + 56, size_of_image, size_of_headers)
    struct.pack_into("<HH", buf, opt_offset + 68, subsystem, dll_characteristics)

    rva_count_offset = opt_offset + (108 if is_64bit else 92)
    struct.pack_into("<I", buf, rva_count_offset, 16)

    if include_clr:
        com_offset = rva_count_offset + 4 + (14 * 8)
        struct.pack_into("<II", buf, com_offset, 0x2000, clr_dir_size)

    # Section 0 (.text): VirtualAddress=0x2000, VirtualSize=0x300, RawSize=0x400, RawPtr=0x200
    sec_off = opt_offset + opt_hdr_size
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
        # IMAGE_COR20_HEADER at file offset 0x200 (RVA 0x2000)
        cor_off = 0x200
        meta_rva = 0x2080
        meta_size = 64
        struct.pack_into(
            "<IHHIIIIIIIIIIIIIIII",
            buf,
            cor_off,
            cor20_cb,
            cor20_major_rt,
            5,
            meta_rva,
            meta_size,
            cor20_flags,
            0,
            0, 0,
            strong_name_rva,
            strong_name_size,
            0, 0,
            0, 0,
            0, 0,
            0, 0,
        )

        # Valid ECMA-335 BSJB at file offset 0x280 (RVA 0x2080)
        bsjb_off = 0x280
        ver_bytes = bsjb_version.encode("ascii")
        ver_len = (len(ver_bytes) + 3) & ~3
        bsjb_blob = bytearray()
        bsjb_blob.extend(b"BSJB")
        bsjb_blob.extend(struct.pack("<HHI", 1, 1, 0))
        bsjb_blob.extend(struct.pack("<I", ver_len))
        bsjb_blob.extend(ver_bytes.ljust(ver_len, b"\x00"))
        bsjb_blob.extend(struct.pack("<HH", 0, 2))
        bsjb_blob.extend(struct.pack("<II", 0x100, 0x200))
        bsjb_blob.extend(b"#~\x00\x00")
        bsjb_blob.extend(struct.pack("<II", 0x300, 0x400))
        bsjb_blob.extend(b"#Strings\x00\x00\x00\x00")
        buf[bsjb_off: bsjb_off + len(bsjb_blob)] = bsjb_blob

    return bytes(buf)


def _build_pe_with_version_rsrc(version_tuple=(7, 2, 17, 0)) -> bytes:
    """Construct a synthetic PE32+ binary containing a 3-level .rsrc RT_VERSION VS_FIXEDFILEINFO."""
    major, minor, patch, build = version_tuple
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, lfanew)
    buf[lfanew:lfanew + 4] = b"PE\x00\x00"

    opt_hdr_size = 240
    struct.pack_into("<HHIIIHH", buf, lfanew + 4, 0x8664, 1, 0, 0, 0, opt_hdr_size, IMAGE_FILE_EXECUTABLE_IMAGE)
    opt_off = lfanew + 24
    struct.pack_into("<H", buf, opt_off, 0x020B)
    struct.pack_into("<II", buf, opt_off + 32, 0x2000, 0x200)
    struct.pack_into("<II", buf, opt_off + 56, 0x4000, 0x200)
    struct.pack_into("<HH", buf, opt_off + 68, IMAGE_SUBSYSTEM_WINDOWS_CUI, 0)
    rva_off = opt_off + 108
    struct.pack_into("<I", buf, rva_off, 16)
    # DataDirectory[2] = IMAGE_DIRECTORY_ENTRY_RESOURCE
    struct.pack_into("<II", buf, rva_off + 4 + (2 * 8), 0x2000, 0x180)

    # .rsrc section at file offset 0x200
    sec_off = opt_off + opt_hdr_size
    struct.pack_into("<8sIIIIIIHHI", buf, sec_off, b".rsrc\x00\x00\x00", 0x180, 0x2000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)

    rsrc_base = 0x200
    # Level 1 dir at +0x00: 1 ID entry (16 = RT_VERSION) -> +0x18
    struct.pack_into("<IIHHHH", buf, rsrc_base + 0x00, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rsrc_base + 0x10, 16, 0x80000000 | 0x18)
    # Level 2 dir at +0x18: 1 ID entry (1) -> +0x30
    struct.pack_into("<IIHHHH", buf, rsrc_base + 0x18, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rsrc_base + 0x28, 1, 0x80000000 | 0x30)
    # Level 3 dir at +0x30: 1 ID entry (0x0409) -> DataEntry at +0x48
    struct.pack_into("<IIHHHH", buf, rsrc_base + 0x30, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", buf, rsrc_base + 0x40, 0x0409, 0x48)
    # IMAGE_RESOURCE_DATA_ENTRY at +0x48 -> RVA 0x2060, size 64
    struct.pack_into("<IIII", buf, rsrc_base + 0x48, 0x2060, 64, 1200, 0)
    # VS_FIXEDFILEINFO at +0x68 (inside data block at RVA 0x2060)
    fv_ms = (major << 16) | minor
    fv_ls = (patch << 16) | build
    struct.pack_into(
        "<13I",
        buf,
        rsrc_base + 0x68,
        0xFEEF04BD,
        0x00010000,
        fv_ms,
        fv_ls,
        fv_ms,
        fv_ls,
        0x3F,
        0,
        0x40004,
        1,
        0,
        0,
        0,
    )
    return bytes(buf)


# ---------------------------------------------------------------------------
# Existing 6 Baseline Tests (Preserved)
# ---------------------------------------------------------------------------

def test_magika_structural_pe_classification():
    pe_data = _build_synthetic_pe()
    id_res = structural_magika_classify(None, pe_data)
    assert id_res.label == "pebin"
    assert id_res.group == "executable"
    assert id_res.mime_type == "application/x-dosexec"
    assert id_res.score >= 0.99


def test_inspect_standard_pe_executable():
    pe_data = _build_synthetic_pe(characteristics=IMAGE_FILE_EXECUTABLE_IMAGE)
    report = inspect_pe_binary(pe_data, "test_app.exe")
    assert report.is_pe is True
    assert report.is_executable_image is True
    assert report.is_dll is False
    assert report.is_masqueraded is False
    assert report.has_forshaw_cve_2026_108398_anomaly is False
    assert report.machine_type == "AMD64 (x86_64 64-bit)"


def test_inspect_extension_masquerading():
    # PE executable saved with .pdf extension
    pe_data = _build_synthetic_pe(characteristics=IMAGE_FILE_EXECUTABLE_IMAGE)
    report = inspect_pe_binary(pe_data, "quarterly_financial_report.pdf")
    assert report.is_pe is True
    assert report.is_masqueraded is True
    assert report.declared_extension == ".pdf"
    assert any("Extension Masquerading" in a for a in report.anomalies)


def test_forshaw_cve_2026_108398_dotnet_integrity_bypass_detection():
    # .NET Assembly with IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) CLEARED
    cleared_chars = IMAGE_FILE_DLL  # 0x2000 without 0x0002
    pe_data = _build_synthetic_pe(
        characteristics=cleared_chars,
        include_clr_dir=True,
        include_bsjb=True,
        bsjb_version="v4.0.30319",
    )
    report = inspect_pe_binary(pe_data, "PPL_Bypass_Assembly.dll")
    assert report.is_pe is True
    assert report.dot_net.is_dot_net is True
    assert report.dot_net.has_bsjb_root is True
    assert report.dot_net.runtime_version == "v4.0.30319"
    assert "#~" in report.dot_net.stream_names
    assert "#Strings" in report.dot_net.stream_names
    assert report.is_executable_image is False
    assert report.has_forshaw_cve_2026_108398_anomaly is True
    assert any("CVE-2026-108398 Anomaly" in a for a in report.anomalies)


def test_benign_dotnet_assembly_no_false_positive():
    # Standard benign .NET assembly with IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) set
    valid_chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL
    pe_data = _build_synthetic_pe(
        characteristics=valid_chars,
        include_clr_dir=True,
        include_bsjb=True,
        bsjb_version="v4.0.30319",
    )
    report = inspect_pe_binary(pe_data, "LegitimateLibrary.dll")
    assert report.is_pe is True
    assert report.dot_net.is_dot_net is True
    assert report.is_executable_image is True
    assert report.has_forshaw_cve_2026_108398_anomaly is False


def test_non_pe_classification():
    # ELF
    elf_data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 60
    assert structural_magika_classify(None, elf_data).label == "elf"

    # WASM
    wasm_data = b"\x00asm\x01\x00\x00\x00"
    assert structural_magika_classify(None, wasm_data).label == "wasm"

    # JSON
    json_data = b'{"name": "rfchunt", "version": "1.0"}'
    assert structural_magika_classify(None, json_data).label == "json"


# ---------------------------------------------------------------------------
# Feature #12: CLR Data Directory +4 Offset Fix & Bounds Validation
# ---------------------------------------------------------------------------

def test_feature12_clr_data_directory_offset_pe32_and_pe32plus():
    for is_64 in (True, False):
        pe_data = _build_synthetic_pe(
            is_64bit=is_64,
            characteristics=IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
            include_clr_dir=True,
            include_bsjb=False,
        )
        report = inspect_pe_binary(pe_data, "ClrOnly.dll")
        assert report.dot_net.is_dot_net is True
        assert report.dot_net.clr_header_rva == 0x2000
        assert report.dot_net.clr_header_size == 72

        as_dict = report.to_dict()
        for req_key in (
            "is_pe", "magika_identity", "machine_type", "characteristics",
            "is_executable_image", "is_dll", "is_system_driver", "dot_net",
            "is_masqueraded", "declared_extension", "anomalies",
            "has_forshaw_cve_2026_108398_anomaly", "umci_fallback_risk", "umci_anomalies",
        ):
            assert req_key in as_dict
        assert as_dict["dot_net"]["clr_header_rva"] == 0x2000
        assert as_dict["dot_net"]["clr_header_size"] == 72


def test_feature12_truncated_pe_bounds_and_rva_count_respected():
    # NumberOfRvaAndSizes = 10 -> DataDirectory[14] must NOT be parsed as CLR
    buf = bytearray(_build_synthetic_pe(is_64bit=True, include_clr_dir=True, include_bsjb=False))
    struct.pack_into("<I", buf, 0x80 + 24 + 108, 10)
    report = inspect_pe_binary(bytes(buf), "SmallDirCount.dll")
    assert report.dot_net.is_dot_net is False
    assert report.dot_net.clr_header_rva == 0

    # Invalid e_lfanew < 0x40
    bad_lfanew = bytearray(128)
    bad_lfanew[0:2] = b"MZ"
    struct.pack_into("<I", bad_lfanew, 0x3C, 0x10)
    rep_bad = inspect_pe_binary(bytes(bad_lfanew), "bad_lfanew.exe")
    assert rep_bad.umci_fallback_risk is True
    assert any("e_lfanew" in a for a in rep_bad.anomalies)


# ---------------------------------------------------------------------------
# Feature #13: UMCI / SEC_COMMIT Flat Memory Fallback Heuristics
# ---------------------------------------------------------------------------

def test_feature13_clean_dotnet_framework_core_and_delaysigned_zero_false_positives():
    # 1. Standard .NET Framework 4 DLL (no FORCE_INTEGRITY / GUARD_CF / APPCONTAINER, EP=0)
    clean_fx = _build_valid_dotnet_pe(is_64bit=False, bsjb_version="v4.0.30319")
    rep_fx = inspect_pe_binary(clean_fx, "CleanFx4.dll")
    assert rep_fx.umci_fallback_risk is False
    assert rep_fx.umci_anomalies == []
    assert rep_fx.anomalies == []
    assert rep_fx.cor20_header is not None
    assert rep_fx.cor20_header.cb == 72

    # 2. Standard .NET Core / .NET 8 64-bit EXE (EP inside .text)
    clean_core = _build_valid_dotnet_pe(
        is_64bit=True,
        characteristics=IMAGE_FILE_EXECUTABLE_IMAGE,
        entry_point=0x2000,
        bsjb_version="v4.0.30319",
    )
    rep_core = inspect_pe_binary(clean_core, "CleanNet8.exe")
    assert rep_core.umci_fallback_risk is False
    assert rep_core.anomalies == []

    # 3. Delay-signed .NET assembly (StrongNameSignature RVA/Size populated, STRONGNAMESIGNED flag cleared)
    delay_signed = _build_valid_dotnet_pe(
        is_64bit=True,
        cor20_flags=COMIMAGE_FLAGS_ILONLY,
        strong_name_rva=0x2100,
        strong_name_size=128,
    )
    rep_ds = inspect_pe_binary(delay_signed, "DelaySigned.dll")
    assert rep_ds.umci_fallback_risk is False
    assert rep_ds.anomalies == []


def test_feature13_umci_sec_commit_anomaly_detection():
    # 1. SectionAlignment < FileAlignment
    bad_align = _build_valid_dotnet_pe(section_alignment=0x200, file_alignment=0x1000)
    assert inspect_pe_binary(bad_align, "bad_align.dll").umci_fallback_risk is True

    # 2. Non-power-of-2 SectionAlignment
    non_pow2 = _build_valid_dotnet_pe(section_alignment=0x1500, file_alignment=0x200)
    assert inspect_pe_binary(non_pow2, "non_pow2.dll").umci_fallback_risk is True

    # 3. Unaligned SizeOfImage
    bad_soi = _build_valid_dotnet_pe(size_of_image=0x2500)
    assert inspect_pe_binary(bad_soi, "bad_soi.dll").umci_fallback_risk is True

    # 4. Out-of-bounds section raw data
    oob_raw = bytearray(_build_valid_dotnet_pe())
    struct.pack_into("<I", oob_raw, 0x80 + 24 + 240 + 16, 0x9000)  # SizeOfRawData > len
    assert inspect_pe_binary(bytes(oob_raw), "oob_raw.dll").umci_fallback_risk is True

    # 5. Overlapping / non-ascending sections
    overlap = bytearray(_build_valid_dotnet_pe(extra_sections=1))
    sec1_off = 0x80 + 24 + 240 + 40
    struct.pack_into(
        "<8sIIIIIIHHI",
        overlap,
        sec1_off,
        b".data\x00\x00\x00",
        0x200,
        0x2100,  # overlaps .text [0x2000, 0x2300)
        0x200,
        0x600,
        0, 0, 0, 0,
        IMAGE_SCN_MEM_READ,
    )
    assert inspect_pe_binary(bytes(overlap), "overlap.dll").umci_fallback_risk is True

    # 6. COR20.cb != 72
    bad_cb = _build_valid_dotnet_pe(cor20_cb=64)
    assert inspect_pe_binary(bad_cb, "bad_cb.dll").umci_fallback_risk is True

    # 7. STRONGNAMESIGNED without StrongNameSignature RVA/Size
    bad_sn = _build_valid_dotnet_pe(cor20_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_STRONGNAMESIGNED)
    assert inspect_pe_binary(bad_sn, "bad_sn.dll").umci_fallback_risk is True

    # 8. 32BITREQUIRED on PE32+ (64-bit)
    bad_32 = _build_valid_dotnet_pe(is_64bit=True, cor20_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITREQUIRED)
    assert inspect_pe_binary(bad_32, "bad_32.dll").umci_fallback_risk is True

    # 9. ILONLY | NATIVE_ENTRYPOINT contradiction
    bad_il = _build_valid_dotnet_pe(cor20_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
    assert inspect_pe_binary(bad_il, "bad_il.dll").umci_fallback_risk is True

    # 10. 32BITPREFERRED without 32BITREQUIRED
    bad_pref = _build_valid_dotnet_pe(is_64bit=False, cor20_flags=COMIMAGE_FLAGS_ILONLY | COMIMAGE_FLAGS_32BITPREFERRED)
    assert inspect_pe_binary(bad_pref, "bad_pref.dll").umci_fallback_risk is True

    # 11. IMAGE_SUBSYSTEM_NATIVE on .NET assembly
    bad_sub = _build_valid_dotnet_pe(subsystem=IMAGE_SUBSYSTEM_NATIVE)
    assert inspect_pe_binary(bad_sub, "bad_sub.dll").umci_fallback_risk is True

    # 12. Non-.NET PE with 0x0002 cleared
    bad_native_exec = _build_valid_dotnet_pe(characteristics=0, include_clr=False)
    assert inspect_pe_binary(bad_native_exec, "bad_native.exe").umci_fallback_risk is True

    # 13. RWX section flagged in anomalies without falsely requiring alignment failure
    rwx = _build_valid_dotnet_pe(section_chars=IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
    rep_rwx = inspect_pe_binary(rwx, "rwx.dll")
    assert any("RWX" in a for a in rep_rwx.anomalies)


# ---------------------------------------------------------------------------
# Feature #14: Defensive YARA Rule Generation, Validation & Matching
# ---------------------------------------------------------------------------

def test_feature14_yara_syntax_validation_valid_and_malformed():
    self_contained = generate_pe_dotnet_yara_rules(include_extension_external=False)
    res_sc = validate_yara_rules(self_contained)
    assert res_sc["valid"] is True
    assert res_sc["rule_count"] >= 4
    assert "PE_DotNet_CVE_2026_108398_ExecutableFlag_Cleared" in res_sc["rule_names"]
    assert "PE_UMCI_SecCommit_Alignment_Bypass" in res_sc["rule_names"]

    with_ext = generate_pe_dotnet_yara_rules(include_extension_external=True)
    res_ext = validate_yara_rules(with_ext)
    assert res_ext["valid"] is True
    assert "PE_Extension_Masquerading" in res_ext["rule_names"]

    # Malformed cases must all fail validation
    assert validate_yara_rules("")["valid"] is False
    assert validate_yara_rules('rule missing_cond { strings: $a = "MZ" }')["valid"] is False
    assert validate_yara_rules('rule unclosed { condition: true ')["valid"] is False
    assert validate_yara_rules('rule undef_str { strings: $a = "x" condition: $missing }')["valid"] is False
    assert validate_yara_rules('rule bad_hex { strings: $h = { ZZ } condition: $h }')["valid"] is False


def test_feature14_yara_matching_positive_and_clean_zero_fp():
    clean_pe64 = _build_valid_dotnet_pe(is_64bit=True, characteristics=IMAGE_FILE_EXECUTABLE_IMAGE, entry_point=0x2000, include_clr=False)
    clean_dotnet = _build_valid_dotnet_pe(is_64bit=True)
    clean_stub = _build_synthetic_pe(characteristics=IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL, include_clr_dir=True, include_bsjb=True)

    for clean_buf, fname in (
        (clean_pe64, "clean.exe"),
        (clean_dotnet, "CleanDotNet.dll"),
        (clean_stub, "CleanStub.dll"),
    ):
        m_clean = match_pe_dotnet_yara(clean_buf, file_path=fname)
        assert m_clean["matched"] is False, f"Unexpected YARA match on {fname}: {m_clean['rule_names']}"
        assert m_clean["rule_names"] == []

    # Positive 1: CVE-2026-108398
    cve_buf = _build_synthetic_pe(characteristics=IMAGE_FILE_DLL, include_clr_dir=True, include_bsjb=True)
    m_cve = match_pe_dotnet_yara(cve_buf, file_path="exploit.dll")
    assert m_cve["matched"] is True
    assert "PE_DotNet_CVE_2026_108398_ExecutableFlag_Cleared" in m_cve["rule_names"]

    # Positive 2: UMCI alignment bypass
    align_buf = _build_valid_dotnet_pe(section_alignment=0x200, file_alignment=0x1000)
    m_align = match_pe_dotnet_yara(align_buf, file_path="sec_commit_bypass.dll")
    assert m_align["matched"] is True
    assert "PE_UMCI_SecCommit_Alignment_Bypass" in m_align["rule_names"]

    # Positive 3: Extension masquerading
    m_masq = match_pe_dotnet_yara(clean_pe64, file_path="invoice.pdf")
    assert m_masq["matched"] is True
    assert "PE_Extension_Masquerading" in m_masq["rule_names"]

    # Positive 4: Polyglot %PDF- + PE\0\0 + BSJB
    polyglot = b"%PDF-1.7\n" + clean_dotnet
    m_poly = match_pe_dotnet_yara(polyglot, file_path="polyglot.pdf")
    assert m_poly["matched"] is True
    assert "PE_Extension_Masquerading_Polyglot" in m_poly["rule_names"]

    # Custom rule evaluation check (non-hardcoded engine verification)
    custom_rule = 'rule Custom_Test_Sig { strings: $s = "RFCHUNT_CANARY" ascii condition: $s }'
    assert match_pe_dotnet_yara(b"hello RFCHUNT_CANARY world", rules_text=custom_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"hello clean world", rules_text=custom_rule)["matched"] is False


# ---------------------------------------------------------------------------
# Feature #15: Pure-Python Host Patch Auditing & Directory Auditor
# ---------------------------------------------------------------------------

def test_feature15_host_patch_audit_all_five_states():
    # 1. patched
    res_patched = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {
                "current_build": 26300,
                "ubr": 10008,
                "dotnet_v4_installed": True,
                "cbs_enumerated": True,
                "cbs_packages": [{"name": "Package_for_KB5127694~amd64~~26300.10008", "current_state": 112}],
            },
            "virtualbox": {"installed": True, "registry_version": "7.2.18", "binary_version": "7.2.18.0"},
        }
    )
    assert res_patched["kb5127694"]["status"] == "patched"
    assert res_patched["virtualbox"]["status"] == "patched"
    assert res_patched["findings"] == []

    # 2. vulnerable (pending reboot CBS=64 + VirtualBox 7.2.16)
    res_vuln = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {
                "current_build": 26300,
                "ubr": 9000,
                "dotnet_v4_installed": True,
                "cbs_enumerated": True,
                "cbs_packages": [{"name": "Package_for_KB5127694~amd64~~26300.10008", "current_state": 64}],
            },
            "virtualbox": {"installed": True, "registry_version": "7.2.16", "binary_version": "7.2.16.0"},
        }
    )
    assert res_vuln["kb5127694"]["status"] == "vulnerable"
    assert res_vuln["kb5127694"]["pending_reboot"] is True
    assert res_vuln["virtualbox"]["status"] == "vulnerable"
    assert len(res_vuln["findings"]) == 2
    for f in res_vuln["findings"]:
        assert f["poe_level"] == 2
        assert f["evidence_lane"] == "DETERMINISTIC_STATIC"
        assert f["scanner"] == "Module-PE-DotNet-Auditor"
        assert f["line_number"] == 1
        assert not f["title"].upper().startswith("CONFIRMED:")

    # 3. not_installed
    res_not_inst = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 22631, "ubr": 4000, "dotnet_v4_installed": False, "cbs_enumerated": False},
            "virtualbox": {"installed": False},
        }
    )
    assert res_not_inst["kb5127694"]["status"] == "not_installed"
    assert res_not_inst["virtualbox"]["status"] == "not_installed"
    assert res_not_inst["findings"] == []

    # 4. not_applicable (non-Windows)
    res_na = audit_host_patch_levels(host_snapshot={"platform": "linux"})
    assert res_na["kb5127694"]["status"] == "not_applicable"
    assert res_na["virtualbox"]["status"] == "not_applicable"
    assert res_na["findings"] == []

    # 5. unknown
    res_unk = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"cbs_enumerated": False, "dotnet_v4_installed": None},
            "virtualbox": {"installed": True, "registry_checked": True},
        }
    )
    assert res_unk["kb5127694"]["status"] == "unknown"
    assert res_unk["virtualbox"]["status"] == "unknown"


def test_feature15_virtualbox_vs_fixedfileinfo_pe_resource_parsing(tmp_path: Path):
    vbox_old = _build_pe_with_version_rsrc((7, 2, 17, 0))
    vbox_new = _build_pe_with_version_rsrc((7, 2, 18, 0))

    ffi_old = extract_pe_fixed_file_info(vbox_old)
    assert ffi_old is not None
    assert ffi_old["file_version"] == "7.2.17.0"

    exe_new = tmp_path / "VBoxManage.exe"
    exe_new.write_bytes(vbox_new)
    ffi_new = extract_pe_fixed_file_info(exe_new)
    assert ffi_new is not None
    assert ffi_new["file_version"] == "7.2.18.0"

    # Even if registry claims 7.2.18, on-disk binary 7.2.17 must be flagged vulnerable
    audit_old = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": True},
            "virtualbox": {"installed": True, "registry_version": "7.2.18", "binary_bytes": vbox_old},
        }
    )
    assert audit_old["virtualbox"]["status"] == "vulnerable"
    assert any(f["rule_id"] == "HOST-PATCH-VBOX-7218" for f in audit_old["findings"])

    audit_new = audit_host_patch_levels(
        host_snapshot={
            "platform": "win32",
            "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": True},
            "virtualbox": {"installed": True, "binary_path": str(exe_new)},
        }
    )
    assert audit_new["virtualbox"]["status"] == "patched"


def test_feature15_live_host_audit_zero_subprocess_calls(monkeypatch):
    def _forbid_subprocess(*args, **kwargs):
        raise AssertionError("Subprocess execution is strictly forbidden in pure-Python host patch audit")

    monkeypatch.setattr(subprocess, "run", _forbid_subprocess)
    monkeypatch.setattr(subprocess, "Popen", _forbid_subprocess)
    monkeypatch.setattr(subprocess, "check_output", _forbid_subprocess)

    res = audit_host_patch_levels()
    assert res["kb5127694"]["status"] in HOST_PATCH_STATUSES
    assert res["virtualbox"]["status"] in HOST_PATCH_STATUSES
    if sys.platform != "win32":
        assert res["kb5127694"]["status"] == "not_applicable"
        assert res["virtualbox"]["status"] == "not_applicable"
    json.dumps(res)


def test_audit_pe_dotnet_target_directory_and_json_contract(tmp_path: Path):
    # Create clean assembly, CVE-2026-108398 assembly, masqueraded PDF PE, and ignored .git / __pycache__
    (tmp_path / "clean.dll").write_bytes(_build_valid_dotnet_pe())
    (tmp_path / "bypass.dll").write_bytes(
        _build_synthetic_pe(characteristics=IMAGE_FILE_DLL, include_clr_dir=True, include_bsjb=True)
    )
    (tmp_path / "fake_invoice.pdf").write_bytes(
        _build_valid_dotnet_pe(is_64bit=True, characteristics=IMAGE_FILE_EXECUTABLE_IMAGE, entry_point=0x2000, include_clr=False)
    )
    (tmp_path / "notes.txt").write_text("harmless plain text", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "ignored.dll").write_bytes(
        _build_synthetic_pe(characteristics=IMAGE_FILE_DLL, include_clr_dir=True, include_bsjb=True)
    )

    out_snap = {
        "platform": "win32",
        "windows": {"current_build": 26300, "ubr": 10008, "dotnet_v4_installed": True},
        "virtualbox": {"installed": False},
    }
    res = audit_pe_dotnet_target(tmp_path, include_host_audit=True, include_yara=True, host_snapshot=out_snap)
    assert res["status"] == "completed"
    assert res["files_scanned"] == 3  # clean.dll, bypass.dll, fake_invoice.pdf (notes.txt & .git ignored)
    assert res["pe_files_found"] == 3
    assert res["masqueraded_files_count"] == 1
    assert res["cve_2026_108398_count"] == 1
    assert res["umci_fallback_risk_count"] >= 1
    assert res["total_findings"] >= 3
    rule_ids = {f["rule_id"] for f in res["findings"]}
    assert "PE-DOTNET-CVE-2026-108398" in rule_ids
    assert "PE-MASQUERADE-001" in rule_ids
    for f in res["findings"]:
        assert f["poe_level"] == 2
        assert f["evidence_lane"] == "DETERMINISTIC_STATIC"
        assert f["scanner"] == "Module-PE-DotNet-Auditor"
        assert f["line_number"] >= 1

    # Verify strict JSON serializability
    serialized = json.dumps(res)
    assert isinstance(serialized, str) and len(serialized) > 0

    # Verify missing target handling
    missing_res = audit_pe_dotnet_target(tmp_path / "does_not_exist", include_host_audit=False)
    assert missing_res["status"] == "target_not_found"
    assert missing_res["files_scanned"] == 0


# ---------------------------------------------------------------------------
# Iteration 2 Remediation Tests (Challenges 1-4 & Reviewer Minor Note)
# ---------------------------------------------------------------------------

def test_challenge1_directory_scan_detects_pdf_and_png_polyglots_skips_clean(tmp_path: Path):
    clean_dotnet = _build_valid_dotnet_pe(is_64bit=True)
    (tmp_path / "polyglot.pdf").write_bytes(b"%PDF-1.7\n" + clean_dotnet)
    (tmp_path / "polyglot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + clean_dotnet)
    (tmp_path / "clean.pdf").write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF")
    (tmp_path / "clean.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32)

    res = audit_pe_dotnet_target(tmp_path, include_host_audit=False, include_yara=True)
    assert res["status"] == "completed"
    assert res["files_scanned"] == 2  # polyglot.pdf and polyglot.png admitted; clean.pdf & clean.png skipped
    assert res["yara_matches_count"] == 2
    assert any(
        f["rule_id"] == "PE-YARA-PE_EXTENSION_MASQUERADING_POLYGLOT" and f["file_path"].endswith("polyglot.pdf")
        for f in res["findings"]
    )
    assert any(
        f["rule_id"] == "PE-YARA-PE_EXTENSION_MASQUERADING_POLYGLOT" and f["file_path"].endswith("polyglot.png")
        for f in res["findings"]
    )
    assert not any(f["file_path"].endswith(("clean.pdf", "clean.png")) for f in res["findings"])


def test_challenge2_populated_optional_header_with_zeroed_sections_detected():
    # Minimal zeroed stub must remain clean (no false positive on standard stubs)
    stub = _build_synthetic_pe(
        characteristics=IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
        include_clr_dir=True,
        include_bsjb=True,
    )
    rep_stub = inspect_pe_binary(stub, "minimal_stub.dll")
    assert rep_stub.umci_fallback_risk is False

    # Populated OptionalHeader + zeroed section table must NOT evade EP, section, or COR20 checks
    evade = bytearray(_build_valid_dotnet_pe())
    evade[0x80 + 24 + 240: 0x80 + 24 + 240 + 40] = b"\x00" * 40  # zero out section 0 header
    struct.pack_into("<I", evade, 0x80 + 24 + 16, 0x50)           # AddressOfEntryPoint inside headers
    rep_evade = inspect_pe_binary(bytes(evade), "evade.dll")
    assert rep_evade.umci_fallback_risk is True
    assert any("AddressOfEntryPoint" in a for a in rep_evade.anomalies)
    assert any("VirtualAddress (0x0)" in a for a in rep_evade.anomalies)
    assert any("COM Descriptor RVA" in a for a in rep_evade.anomalies)


def test_challenge3_pure_python_yara_edge_cases(monkeypatch):
    # Force pure-Python YARA path even if yara-python is installed
    import builtins
    real_import = builtins.__import__

    def _block_yara_import(name, *args, **kwargs):
        if name == "yara":
            raise ImportError("forced pure-Python YARA fallback test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_yara_import)

    # 1. Unknown bare IDENT must be rejected
    bad_ident_res = validate_yara_rules("rule bad_ident { condition: nonexistent_ident }")
    assert bad_ident_res["valid"] is False
    assert bad_ident_res["engine"] == "pure_python_yara_validator"

    # 2. `not _YARA_UNDEFINED` (out-of-bounds read) must evaluate falsey (non-match), not True
    undef_rule = "rule UndefNot { condition: not uint32(99999999) }"
    assert validate_yara_rules(undef_rule)["valid"] is True
    assert match_pe_dotnet_yara(b"MZ" + b"\x00" * 64, rules_text=undef_rule)["matched"] is False

    # 3. Section keywords inside meta/strings literals must not trigger Duplicate section errors
    quoted_sec_rule = '''rule QuotedSections {
    meta:
        description = "check condition: here and strings: there"
    strings:
        $a = "meta: fake condition: inside string"
        $r = /condition:\\s*\\d+/
    condition:
        $a or $r
}'''
    assert validate_yara_rules(quoted_sec_rule)["valid"] is True
    assert match_pe_dotnet_yara(b"meta: fake condition: inside string", rules_text=quoted_sec_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"condition: 42", rules_text=quoted_sec_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"completely unrelated", rules_text=quoted_sec_rule)["matched"] is False

    # 4. Anonymous `$` in condition
    anon_rule = 'rule AnonRef { strings: $ = "RFCHUNT_ANON" condition: $ }'
    assert validate_yara_rules(anon_rule)["valid"] is True
    assert match_pe_dotnet_yara(b"prefix RFCHUNT_ANON suffix", rules_text=anon_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"prefix OTHER suffix", rules_text=anon_rule)["matched"] is False

    # 5. `fullword` modifier enforcement
    fw_rule = 'rule FullwordTest { strings: $s = "token" fullword condition: $s }'
    assert match_pe_dotnet_yara(b"a token b", rules_text=fw_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"token", rules_text=fw_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"token123", rules_text=fw_rule)["matched"] is False
    assert match_pe_dotnet_yara(b"my_token", rules_text=fw_rule)["matched"] is False
    assert match_pe_dotnet_yara(b"subtoken", rules_text=fw_rule)["matched"] is False

    # 6. `xor` modifier enforcement (default 0..255 and ranged)
    xor_rule = 'rule XorTest { strings: $s = "SECRET" xor(0x01-0xff) condition: $s }'
    xored_payload = bytes(b ^ 0x5A for b in b"SECRET")
    assert match_pe_dotnet_yara(b"hdr " + xored_payload + b" trl", rules_text=xor_rule)["matched"] is True
    assert match_pe_dotnet_yara(b"hdr SECRET trl", rules_text=xor_rule)["matched"] is False  # key 0 excluded by 0x01-0xff
    parsed = _parse_yara_rules_text('rule XorAll { strings: $s = "SECRET" xor condition: $s }')
    assert len(_evaluate_parsed_yara_rules(parsed, b"SECRET")) == 1


def test_challenge4_small_section_alignment_and_safe_int_leading_zeros():
    # SectionAlignment == FileAlignment == 512 with aligned VirtualAddress=0x200 should be clean
    aligned_512 = bytearray(
        _build_valid_dotnet_pe(
            section_alignment=512,
            file_alignment=512,
            size_of_image=0x2400,
            size_of_headers=0x200,
            include_clr=False,
        )
    )
    rep_ok = inspect_pe_binary(bytes(aligned_512), "aligned512.dll")
    assert not any("is not aligned to SectionAlignment" in a for a in rep_ok.anomalies)

    # Misaligned VirtualAddress = 0x201 under SectionAlignment == 512 must be flagged
    misaligned_512 = bytearray(aligned_512)
    struct.pack_into("<I", misaligned_512, 0x80 + 24 + 240 + 12, 0x201)
    rep_bad = inspect_pe_binary(bytes(misaligned_512), "misaligned512.dll")
    assert rep_bad.umci_fallback_risk is True
    assert any("is not aligned to SectionAlignment (0x200)" in a for a in rep_bad.anomalies)

    # _safe_int leading-zero decimal strings
    assert _safe_int("0100") == 100
    assert _safe_int("0x70") == 112
    assert _safe_int("bad") is None


def test_reviewer_note_early_pe_bailout_no_spurious_0x0002_message():
    # Missing PE\0\0 signature at e_lfanew
    bad_sig = bytearray(512)
    bad_sig[0:2] = b"MZ"
    struct.pack_into("<I", bad_sig, 0x3C, 0x80)
    bad_sig[0x80:0x84] = b"NOPE"
    rep = inspect_pe_binary(bytes(bad_sig), "missing_pe_sig.exe")
    assert rep.umci_fallback_risk is True
    assert any("Missing PE\\0\\0 signature" in a for a in rep.anomalies)
    assert not any("IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) cleared" in a for a in rep.anomalies)

    # Out-of-bounds e_lfanew
    bad_lfanew = bytearray(128)
    bad_lfanew[0:2] = b"MZ"
    struct.pack_into("<I", bad_lfanew, 0x3C, 0x10)
    rep2 = inspect_pe_binary(bytes(bad_lfanew), "bad_lfanew.exe")
    assert any("e_lfanew" in a for a in rep2.anomalies)
    assert not any("IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) cleared" in a for a in rep2.anomalies)


def test_audit_pe_dotnet_target_prunes_directory_junction_and_symlink_escapes(tmp_path: Path, monkeypatch):
    import os
    import sys

    root = tmp_path / "ws_repo"
    outside = tmp_path / "outside_secret"
    root.mkdir()
    outside.mkdir()

    clean_bytes = _build_valid_dotnet_pe(is_64bit=True, bsjb_version="v4.0.30319")
    cve_bytes = _build_synthetic_pe(
        characteristics=IMAGE_FILE_DLL,  # 0x0002 cleared -> CVE-2026-108398
        include_clr_dir=True,
        include_bsjb=True,
        bsjb_version="v4.0.30319",
    )
    (root / "inroot.dll").write_bytes(clean_bytes)
    (outside / "outside_evil.dll").write_bytes(cve_bytes)

    escape_dir = root / "evil_dir"
    created_real_link = False
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            _winapi.CreateJunction(str(outside), str(escape_dir))
            created_real_link = True
        except OSError:
            pass
    if not created_real_link:
        try:
            os.symlink(str(outside), str(escape_dir), target_is_directory=True)
            created_real_link = True
        except OSError:
            pass

    if created_real_link:
        res = audit_pe_dotnet_target(root, include_host_audit=False)
        assert res["files_scanned"] == 1
        assert res["cve_2026_108398_count"] == 0
        assert all("outside_evil.dll" not in str(r.get("file_path", "")) for r in res["file_reports"])
        assert any("Symlink/junction escape skipped" in e for e in res["errors"])

    # Also test cross-Python <=3.11 behavior where Path.is_symlink() is False on NTFS junction
    # but lstat reports FILE_ATTRIBUTE_REPARSE_POINT and os.readlink returns outside path.
    sim_root = tmp_path / "sim_repo"
    sim_root.mkdir()
    (sim_root / "inroot.dll").write_bytes(clean_bytes)
    sim_dir = sim_root / "sim_junction"
    sim_dir.mkdir()
    (sim_dir / "outside_evil.dll").write_bytes(cve_bytes)

    import engine.pe_magika_classifier as pe_mod

    orig_is_symlink = Path.is_symlink
    orig_isjunction = getattr(os.path, "isjunction", None)
    orig_lstat = os.lstat
    orig_readlink = os.readlink

    def _fake_is_symlink(self: Path) -> bool:
        if self.name == "sim_junction":
            return False
        return orig_is_symlink(self)

    def _fake_lstat(p, *args, **kwargs):
        st = orig_lstat(p, *args, **kwargs)
        if Path(p).name == "sim_junction":
            class _FakeStat:
                st_mode = st.st_mode
                st_size = st.st_size
                st_file_attributes = 0x0400  # FILE_ATTRIBUTE_REPARSE_POINT
                st_reparse_tag = 0xA0000003  # IO_REPARSE_TAG_MOUNT_POINT
            return _FakeStat()
        return st

    def _fake_readlink(p):
        if Path(p).name == "sim_junction":
            return str(outside)
        return orig_readlink(p)

    monkeypatch.setattr(Path, "is_symlink", _fake_is_symlink)
    if orig_isjunction is not None:
        monkeypatch.setattr(os.path, "isjunction", lambda p: False)
    monkeypatch.setattr(os, "lstat", _fake_lstat)
    monkeypatch.setattr(os, "readlink", _fake_readlink)
    monkeypatch.setattr(os, "name", "nt")

    assert pe_mod._is_symlink_or_reparse(sim_dir) is True
    res_sim = audit_pe_dotnet_target(sim_root, include_host_audit=False)
    assert res_sim["files_scanned"] == 1
    assert res_sim["cve_2026_108398_count"] == 0
    assert all("outside_evil.dll" not in str(r.get("file_path", "")) for r in res_sim["file_reports"])
    assert any("Symlink/junction escape skipped" in e for e in res_sim["errors"])

    # workspace_root confinement rejects out-of-root target_path
    import pytest
    with pytest.raises(PermissionError):
        audit_pe_dotnet_target(outside, include_host_audit=False, workspace_root=root)


def test_audit_pe_dotnet_target_ws_none_direct_and_intermediate_junction_rejected(
    tmp_path: Path, monkeypatch
) -> None:
    import os
    import sys
    import pytest

    ws = tmp_path / "ws_nows"
    outside = tmp_path / "outside_nows"
    ws.mkdir()
    outside.mkdir()
    cve_bytes = _build_synthetic_pe(
        characteristics=IMAGE_FILE_DLL,
        include_clr_dir=True,
        include_bsjb=True,
        bsjb_version="v4.0.30319",
    )
    (outside / "evil.dll").write_bytes(cve_bytes)

    junc_dir = ws / "junc_out"
    created = False
    if sys.platform == "win32":
        try:
            import _winapi  # type: ignore[attr-defined]
            _winapi.CreateJunction(str(outside), str(junc_dir))
            created = True
        except OSError:
            pass
    if not created:
        try:
            os.symlink(str(outside), str(junc_dir), target_is_directory=True)
            created = True
        except OSError:
            pass

    if created:
        with pytest.raises(PermissionError):
            audit_pe_dotnet_target(junc_dir, include_host_audit=False, include_yara=False, workspace_root=None)
        with pytest.raises(PermissionError):
            audit_pe_dotnet_target(junc_dir / "evil.dll", include_host_audit=False, include_yara=False, workspace_root=None)

        dead_target = tmp_path / "dead_pe_target"
        dead_target.mkdir()
        broken_junc = ws / "broken_junc"
        broken_created = False
        if sys.platform == "win32":
            try:
                import _winapi  # type: ignore[attr-defined]
                _winapi.CreateJunction(str(dead_target), str(broken_junc))
                broken_created = True
            except OSError:
                pass
        if not broken_created:
            try:
                os.symlink(str(dead_target), str(broken_junc), target_is_directory=True)
                broken_created = True
            except OSError:
                pass
        if broken_created:
            dead_target.rmdir()
            with pytest.raises(PermissionError):
                audit_pe_dotnet_target(broken_junc, include_host_audit=False, include_yara=False, workspace_root=None)
            with pytest.raises(PermissionError):
                audit_pe_dotnet_target(broken_junc / "evil.dll", include_host_audit=False, include_yara=False, workspace_root=None)

    # Simulated <=3.11 reparse point (broken/intermediate) when workspace_root=None
    sim_junc = ws / "sim_broken_junc"
    sim_junc.mkdir()
    (sim_junc / "evil.dll").write_bytes(cve_bytes)

    import engine.execution_policy as pol_mod
    import engine.pe_magika_classifier as pe_mod

    monkeypatch.setattr(pe_mod, "_is_symlink_or_reparse", lambda p: Path(p).name == "sim_broken_junc")
    monkeypatch.setattr(pol_mod, "_is_symlink_or_reparse", lambda p: Path(p).name == "sim_broken_junc")

    with pytest.raises(PermissionError):
        audit_pe_dotnet_target(sim_junc, include_host_audit=False, include_yara=False, workspace_root=None)
    with pytest.raises(PermissionError):
        audit_pe_dotnet_target(sim_junc / "evil.dll", include_host_audit=False, include_yara=False, workspace_root=None)


if __name__ == "__main__":
    test_magika_structural_pe_classification()
    test_inspect_standard_pe_executable()
    test_inspect_extension_masquerading()
    test_forshaw_cve_2026_108398_dotnet_integrity_bypass_detection()
    test_benign_dotnet_assembly_no_false_positive()
    test_non_pe_classification()
    print("ALL BASELINE PE MAGIKA CLASSIFIER TESTS PASSED!")
