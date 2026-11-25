"""
Unit tests for Google Magika PE & .NET Binary Identification Engine.
"""

import struct
from pathlib import Path
import pytest

from engine.pe_magika_classifier import (
    identify_with_magika,
    inspect_pe_binary,
    structural_magika_classify,
    find_valid_dotnet_bsjb_header,
    IMAGE_FILE_EXECUTABLE_IMAGE,
    IMAGE_FILE_DLL,
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
        bsjb_start = len(buf)
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


if __name__ == "__main__":
    test_magika_structural_pe_classification()
    test_inspect_standard_pe_executable()
    test_inspect_extension_masquerading()
    test_forshaw_cve_2026_108398_dotnet_integrity_bypass_detection()
    test_benign_dotnet_assembly_no_false_positive()
    test_non_pe_classification()
    print("ALL 6 PE MAGIKA CLASSIFIER TESTS PASSED!")

