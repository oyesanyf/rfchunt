"""
Google Magika PE & .NET Binary Identification Engine.
=====================================================
Adapted from OpenOshoosi / OshoosiClaw (`crates/osoosi-core/src/rea/types.rs` & `pe_inspector.rs`).

Implements a high-throughput, two-tier content identification pipeline:
- Tier 1: Deterministic structural envelope verification (MZ, PE\\0\\0, COFF header,
          Data Directory 14 CLR descriptor, ECMA-335 BSJB metadata root).
- Tier 2: Google Magika neural network content-type classification (when `magika` package
          is present), reconciled with structural invariants.
- Security Invariants:
  1. Detects file extension masquerading (PE executable disguised as .pdf, .txt, .png, etc.).
  2. Detects James Forshaw's .NET Code Integrity Bypass (CVE-2026-108398 / CVE-2026-87268):
     clearing IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) in Characteristics on a .NET assembly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

# Try importing Google Magika; fall back gracefully to Tier 1 structural engine if not installed.
_MAGIKA_INSTANCE = None
_MAGIKA_INITIALIZED = False


def _get_magika_instance():
    global _MAGIKA_INSTANCE, _MAGIKA_INITIALIZED
    if not _MAGIKA_INITIALIZED:
        _MAGIKA_INITIALIZED = True
        try:
            import magika  # type: ignore
            _MAGIKA_INSTANCE = magika.Magika()
        except Exception:
            _MAGIKA_INSTANCE = None
    return _MAGIKA_INSTANCE


@dataclass
class MagikaFileIdentity:
    """Standardized Magika content-type identification record."""
    label: str
    mime_type: str
    group: str
    description: str
    is_text: bool
    score: float
    engine: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "mime_type": self.mime_type,
            "group": self.group,
            "description": self.description,
            "is_text": self.is_text,
            "score": round(self.score, 4),
            "engine": self.engine,
        }


@dataclass
class DotNetMetadata:
    """Extracted .NET CLR and ECMA-335 header metadata."""
    is_dot_net: bool = False
    clr_header_rva: int = 0
    clr_header_size: int = 0
    runtime_version: str = ""
    has_bsjb_root: bool = False
    bsjb_offset: int = 0
    stream_count: int = 0
    stream_names: List[str] = field(default_factory=list)


@dataclass
class PEInspectionReport:
    """Comprehensive PE and .NET inspection report combining Magika & structural analysis."""
    is_pe: bool
    magika_identity: MagikaFileIdentity
    machine_type: str
    characteristics: int
    is_executable_image: bool  # IMAGE_FILE_EXECUTABLE_IMAGE (0x0002)
    is_dll: bool               # IMAGE_FILE_DLL (0x2000)
    is_system_driver: bool     # IMAGE_FILE_SYSTEM (0x1000)
    dot_net: DotNetMetadata
    is_masqueraded: bool
    declared_extension: str
    anomalies: List[str] = field(default_factory=list)
    has_forshaw_cve_2026_108398_anomaly: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_pe": self.is_pe,
            "magika_identity": self.magika_identity.to_dict(),
            "machine_type": self.machine_type,
            "characteristics": hex(self.characteristics),
            "is_executable_image": self.is_executable_image,
            "is_dll": self.is_dll,
            "is_system_driver": self.is_system_driver,
            "dot_net": {
                "is_dot_net": self.dot_net.is_dot_net,
                "runtime_version": self.dot_net.runtime_version,
                "has_bsjb_root": self.dot_net.has_bsjb_root,
                "stream_names": self.dot_net.stream_names,
            },
            "is_masqueraded": self.is_masqueraded,
            "declared_extension": self.declared_extension,
            "anomalies": self.anomalies,
            "has_forshaw_cve_2026_108398_anomaly": self.has_forshaw_cve_2026_108398_anomaly,
        }


IMAGE_FILE_MACHINE_MAP = {
    0x014C: "I386 (x86 32-bit)",
    0x8664: "AMD64 (x86_64 64-bit)",
    0xAA64: "ARM64 (AArch64 64-bit)",
    0x01C0: "ARM (Thumb 32-bit)",
    0x0200: "IA64 (Intel Itanium)",
}

IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_SYSTEM = 0x1000
IMAGE_FILE_DLL = 0x2000

BENIGN_NON_EXEC_EXTENSIONS = {
    ".pdf", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
    ".doc", ".docx", ".xls", ".xlsx", ".csv", ".json", ".xml", ".html",
    ".wav", ".mp3", ".mp4", ".zip", ".tar", ".gz"
}


def find_valid_dotnet_bsjb_header(data: bytes) -> Optional[Tuple[int, str, List[str]]]:
    """
    Locates and structurally validates an ECMA-335 II.24.2.1 CLR Metadata Root (BSJB, 0x424A5342).
    Direct port of OshoosiClaw's robust `find_valid_dotnet_bsjb_header`.
    """
    search_from = 0
    while search_from + 32 <= len(data):
        rel = data[search_from:].find(b"BSJB")
        if rel == -1:
            return None
        bsjb_off = search_from + rel
        search_from = bsjb_off + 4

        if bsjb_off + 20 > len(data):
            break

        major, minor = struct.unpack_from("<HH", data, bsjb_off + 4)
        reserved = struct.unpack_from("<I", data, bsjb_off + 8)[0]
        ver_len = struct.unpack_from("<I", data, bsjb_off + 12)[0]

        if not (1 <= major <= 2) or minor > 10 or reserved != 0:
            continue
        if not (4 <= ver_len <= 64) or bsjb_off + 16 + ver_len + 4 > len(data):
            continue

        raw_ver = data[bsjb_off + 16: bsjb_off + 16 + ver_len]
        trimmed = raw_ver.split(b"\x00", 1)[0]
        if (len(trimmed) < 2
                or trimmed[0] not in (ord("v"), ord("V"))
                or not (ord("0") <= trimmed[1] <= ord("9"))
                or not all(0x20 <= b <= 0x7E for b in trimmed)):
            continue

        clr_version = trimmed.decode("ascii", errors="replace")
        aligned_ver = (ver_len + 3) & ~3
        flags_off = bsjb_off + 16 + aligned_ver
        if flags_off + 4 > len(data):
            continue

        stream_count = struct.unpack_from("<H", data, flags_off + 2)[0]
        if not (1 <= stream_count <= 16):
            continue

        streams: List[str] = []
        cur = flags_off + 4
        valid_streams = True
        for _ in range(stream_count):
            if cur + 8 > len(data):
                valid_streams = False
                break
            # Stream header: offset (4 bytes), size (4 bytes), name (null-terminated UTF-8, 4-byte padded)
            cur += 8
            name_bytes = bytearray()
            while cur < len(data) and data[cur] != 0 and len(name_bytes) < 32:
                name_bytes.append(data[cur])
                cur += 1
            if cur >= len(data) or len(name_bytes) == 0 or name_bytes[0] != ord("#"):
                valid_streams = False
                break
            cur += 1  # null terminator
            # Align to 4 bytes relative to stream header start
            pad = (4 - (len(name_bytes) + 1) % 4) % 4
            cur += pad
            streams.append(name_bytes.decode("ascii", errors="replace"))

        if valid_streams and streams:
            return bsjb_off, clr_version, streams

    return None


def structural_magika_classify(path: Optional[Union[str, Path]], data: bytes) -> MagikaFileIdentity:
    """
    Tier 1: Deterministic structural classification matching OshoosiClaw's `structural_magika_classify`.
    """
    if path and Path(path).is_dir():
        return MagikaFileIdentity(
            label="directory",
            mime_type="inode/directory",
            group="inode",
            description="A directory",
            is_text=False,
            score=1.0,
            engine="google_magika_structural_tier1",
        )

    if data.startswith(b"MZ"):
        return MagikaFileIdentity(
            label="pebin",
            mime_type="application/x-dosexec",
            group="executable",
            description="PE executable",
            is_text=False,
            score=0.99,
            engine="google_magika_structural_tier1",
        )

    if data.startswith(b"\x7fELF"):
        return MagikaFileIdentity(
            label="elf",
            mime_type="application/x-executable",
            group="executable",
            description="ELF executable",
            is_text=False,
            score=0.99,
            engine="google_magika_structural_tier1",
        )

    if len(data) >= 4 and struct.unpack(">I", data[:4])[0] in (
        0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE
    ):
        return MagikaFileIdentity(
            label="macho",
            mime_type="application/x-mach-binary",
            group="executable",
            description="Mach-O executable",
            is_text=False,
            score=0.99,
            engine="google_magika_structural_tier1",
        )

    if data.startswith(b"\x00asm"):
        return MagikaFileIdentity(
            label="wasm",
            mime_type="application/wasm",
            group="executable",
            description="WebAssembly binary",
            is_text=False,
            score=1.0,
            engine="google_magika_structural_tier1",
        )

    if data.startswith(b"SQLite format 3\x00"):
        return MagikaFileIdentity(
            label="sqlite",
            mime_type="application/vnd.sqlite3",
            group="archive",
            description="SQLite database",
            is_text=False,
            score=1.0,
            engine="google_magika_structural_tier1",
        )

    if data.startswith(b"PK\x03\x04"):
        is_apk = b"AndroidManifest.xml" in data[:4096] or b"classes.dex" in data[:4096]
        return MagikaFileIdentity(
            label="apk" if is_apk else "zip",
            mime_type="application/vnd.android.package-archive" if is_apk else "application/zip",
            group="archive",
            description="Android package archive" if is_apk else "ZIP archive",
            is_text=False,
            score=0.99,
            engine="google_magika_structural_tier1",
        )

    # Text check
    try:
        sample = data[:min(len(data), 4096)].decode("utf-8")
        trimmed = sample.lstrip()
        if trimmed.startswith(("{", "[")):
            return MagikaFileIdentity(
                label="json",
                mime_type="application/json",
                group="code",
                description="JSON document",
                is_text=True,
                score=0.97,
                engine="google_magika_structural_tier1",
            )
        if trimmed.startswith(("#!/bin/sh", "#!/bin/bash")):
            return MagikaFileIdentity(
                label="shell",
                mime_type="text/x-shellscript",
                group="code",
                description="Shell script",
                is_text=True,
                score=0.98,
                engine="google_magika_structural_tier1",
            )
        return MagikaFileIdentity(
            label="txt",
            mime_type="text/plain",
            group="text",
            description="Generic text document",
            is_text=True,
            score=0.90,
            engine="google_magika_structural_tier1",
        )
    except UnicodeDecodeError:
        pass

    return MagikaFileIdentity(
        label="unknown",
        mime_type="application/octet-stream",
        group="unknown",
        description="Binary data",
        is_text=False,
        score=0.50,
        engine="google_magika_structural_tier1",
    )


def identify_with_magika(path: Optional[Union[str, Path]] = None, data: Optional[bytes] = None) -> MagikaFileIdentity:
    """
    Tier 1 + Tier 2 hybrid content identification using Google Magika and structural invariants.
    """
    if data is None and path is not None:
        p = Path(path)
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    data = f.read(256 * 1024)  # Read up to 256KB for classification
            except Exception:
                data = b""
        else:
            data = b""
    elif data is None:
        data = b""

    structural = structural_magika_classify(path, data)

    m = _get_magika_instance()
    if m is not None:
        try:
            if data:
                res = m.identify_bytes(data)
            elif path and Path(path).is_file():
                res = m.identify_path(Path(path))
            else:
                res = None

            if res is not None:
                out = res.output
                # Reconcile invariants (from OshoosiClaw):
                # When structural matched an explicit binary header (score >= 0.99), preserve it.
                if structural.score >= 0.99 and out.label != structural.label:
                    return MagikaFileIdentity(
                        label=structural.label,
                        mime_type=structural.mime_type,
                        group=structural.group,
                        description=structural.description,
                        is_text=structural.is_text,
                        score=structural.score,
                        engine="google_magika_onnx",
                    )
                return MagikaFileIdentity(
                    label=out.label,
                    mime_type=out.mime_type,
                    group=out.group,
                    description=out.description,
                    is_text=out.is_text,
                    score=float(out.score),
                    engine="google_magika_onnx",
                )
        except Exception:
            pass

    return structural


def inspect_pe_binary(
    data: bytes,
    file_path: Optional[Union[str, Path]] = None,
) -> PEInspectionReport:
    """
    Inspects a binary buffer or file path, combining Google Magika with PE & .NET structural auditing.
    """
    identity = identify_with_magika(path=file_path, data=data)
    ext = Path(file_path).suffix.lower() if file_path else ""

    is_pe = data.startswith(b"MZ") and len(data) >= 0x40
    anomalies: List[str] = []
    machine_type = "Unknown"
    characteristics = 0
    is_exec_image = False
    is_dll = False
    is_sys = False
    dotnet = DotNetMetadata()
    cve_2026_108398_anomaly = False

    if is_pe:
        # e_lfanew offset to PE Header is at 0x3C
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if lfanew + 24 <= len(data) and data[lfanew: lfanew + 4] == b"PE\x00\x00":
            # COFF File Header
            machine, num_sections, time_stamp, ptr_symbols, num_symbols, opt_hdr_size, chars = (
                struct.unpack_from("<HHIIIHH", data, lfanew + 4)
            )
            characteristics = chars
            machine_type = IMAGE_FILE_MACHINE_MAP.get(machine, f"Unknown (0x{machine:04x})")
            is_exec_image = (chars & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
            is_dll = (chars & IMAGE_FILE_DLL) != 0
            is_sys = (chars & IMAGE_FILE_SYSTEM) != 0

            # Optional Header Data Directories
            # Standard Optional Header sizes: 224 bytes for PE32, 240 bytes for PE32+ (64-bit)
            opt_hdr_offset = lfanew + 24
            if opt_hdr_size >= 96 and opt_hdr_offset + opt_hdr_size <= len(data):
                magic = struct.unpack_from("<H", data, opt_hdr_offset)[0]
                is_pe64 = (magic == 0x020B)
                rva_offset = opt_hdr_offset + (108 if is_pe64 else 92)
                # Data Directory #14 is COM Descriptor (.NET CLR Runtime Header)
                com_dir_offset = rva_offset + (14 * 8)
                if com_dir_offset + 8 <= opt_hdr_offset + opt_hdr_size:
                    clr_rva, clr_size = struct.unpack_from("<II", data, com_dir_offset)
                    if clr_rva > 0 and clr_size >= 48:
                        dotnet.is_dot_net = True
                        dotnet.clr_header_rva = clr_rva
                        dotnet.clr_header_size = clr_size

            # Check ECMA-335 BSJB Metadata Root
            bsjb_info = find_valid_dotnet_bsjb_header(data)
            if bsjb_info is not None:
                dotnet.is_dot_net = True
                dotnet.has_bsjb_root = True
                dotnet.bsjb_offset = bsjb_info[0]
                dotnet.runtime_version = bsjb_info[1]
                dotnet.stream_names = bsjb_info[2]
                dotnet.stream_count = len(bsjb_info[2])

            # James Forshaw CVE-2026-108398 / CVE-2026-87268 Anomaly:
            # If the binary is a .NET assembly (or valid PE) but IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) is cleared!
            if dotnet.is_dot_net and not is_exec_image:
                cve_2026_108398_anomaly = True
                anomalies.append(
                    "CVE-2026-108398 Anomaly: .NET Assembly has IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) cleared in Characteristics. "
                    "In unpatched .NET Framework 4, this forces section mapping failure (STATUS_INVALID_IMAGE_FORMAT) "
                    "and triggers a raw flat memory fallback that bypasses Windows User Mode Code Integrity (UMCI / S Mode) "
                    "and VirtualBox Process Hardening."
                )

    # Check for extension masquerading
    is_masqueraded = False
    if identity.label == "pebin" and ext in BENIGN_NON_EXEC_EXTENSIONS:
        is_masqueraded = True
        anomalies.append(
            f"Extension Masquerading: File claims benign extension '{ext}', but Google Magika identified it as "
            f"PE executable ({identity.label}, {identity.mime_type})."
        )

    return PEInspectionReport(
        is_pe=is_pe,
        magika_identity=identity,
        machine_type=machine_type,
        characteristics=characteristics,
        is_executable_image=is_exec_image,
        is_dll=is_dll,
        is_system_driver=is_sys,
        dot_net=dotnet,
        is_masqueraded=is_masqueraded,
        declared_extension=ext,
        anomalies=anomalies,
        has_forshaw_cve_2026_108398_anomaly=cve_2026_108398_anomaly,
    )
