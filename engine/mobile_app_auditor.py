"""
MobSF + jadx Mobile App Security Auditor (M1 / Component 2).
=============================================================
Audits Android (`AndroidManifest.xml`, `network_security_config.xml`, `.kt`, `.java`,
`.apk`) and iOS (`Info.plist`, `.swift`, `.m`, `.mm`, `.ipa`) targets:
  - Enforces XXE-safe XML/Plist parsing (rejects `<!DOCTYPE`/`<!ENTITY` fail-closed).
  - Uses optional `jadx` CLI / local MobSF API only when `not embedded and not no_external_scanners`.
  - Runs multithreaded pure-Python static security rules covering exported components,
    deep links (`openid4vci://`, `openid4vp://`, custom schemes), WebView JS bridges,
    TLS/ATS bypasses, weak crypto, and insecure Keychain accessibility.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import xml.etree.ElementTree as StdET
import zipfile
import zlib

try:
    import defusedxml.ElementTree as _DefusedET  # type: ignore[import-not-found]
except ImportError:
    _DefusedET = None

from engine.host_containment import silent_subprocess_run
from engine.linux_poc_runner import validate_command_tokens, validate_mount_path
from engine.parity_invariant_auditor import is_non_production_noise
from engine.safe_network_validator import is_explicit_loopback_host, validate_target_host


_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        "target",
        "dist",
        "build",
        ".pytest_cache",
        "reports",
    }
)

_MAX_FILE_BYTES = 1_500_000
_MAX_ZIP_MEMBER_BYTES = 2_097_152
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

_XML_XXE_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_PLIST_ENTITY_RE = re.compile(r"<!\s*ENTITY\b", re.IGNORECASE)
_PLIST_INTERNAL_DTD_RE = re.compile(r"<!\s*DOCTYPE[^>\[]*\[", re.IGNORECASE)


def _safe_parse_xml(raw_xml: str) -> StdET.Element:
    """XXE-safe XML parser failing closed on DOCTYPE/ENTITY declarations."""
    if _XML_XXE_RE.search(raw_xml):
        raise ValueError("Unsafe XML DTD/ENTITY declaration rejected")
    if _DefusedET is not None:
        return _DefusedET.fromstring(raw_xml)
    return StdET.fromstring(raw_xml)


def _safe_parse_plist(raw_bytes: bytes) -> Any:
    """XXE-safe plist parser rejecting ENTITY declarations and internal DTD subsets."""
    if len(raw_bytes) > _MAX_ZIP_MEMBER_BYTES:
        raise ValueError("Plist payload exceeds maximum allowed size")
    if not raw_bytes.startswith(b"bplist"):
        if raw_bytes.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            text = raw_bytes.decode("utf-32", errors="ignore")
        elif raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw_bytes.decode("utf-16", errors="ignore")
        elif raw_bytes.startswith(b"\xef\xbb\xbf"):
            text = raw_bytes.decode("utf-8-sig", errors="ignore")
        else:
            text = raw_bytes.decode("utf-8", errors="ignore")
        normalized = text.replace("\x00", "")
        if _PLIST_ENTITY_RE.search(normalized) or _PLIST_INTERNAL_DTD_RE.search(normalized):
            raise ValueError("Unsafe Plist DTD/ENTITY declaration rejected")
    return plistlib.loads(raw_bytes)


def _find_line(lines: List[str], *tokens: str, default: int = 1) -> int:
    for tok in tokens:
        if not tok:
            continue
        tok_l = tok.lower()
        for idx, line in enumerate(lines, start=1):
            if tok_l in line.lower():
                return idx
    return default


def _make_finding(
    *,
    rule_id: str,
    title: str,
    cwe: str,
    severity: str,
    confidence: float,
    file_path: str,
    line: int,
    summary: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    noise = is_non_production_noise(file_path)
    meta = dict(metadata or {})
    meta["non_production_noise"] = noise
    return {
        "engine": "mobile_mobsf",
        "rule_id": rule_id,
        "title": title,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "file_path": file_path,
        "line": max(1, int(line)),
        "summary": summary,
        "deterministic": True,
        "confirmed": True,
        "non_production_noise": noise,
        "metadata": meta,
    }


def _android_attr(elem: StdET.Element, name: str) -> Optional[str]:
    return elem.attrib.get(f"{_ANDROID_NS}{name}") or elem.attrib.get(f"android:{name}") or elem.attrib.get(name)


def _audit_android_manifest(rel_path: str, raw_xml: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = raw_xml.splitlines()
    try:
        root = _safe_parse_xml(raw_xml)
    except (ValueError, StdET.ParseError):
        return findings

    app_elem = root.find("application")
    if app_elem is not None:
        if (_android_attr(app_elem, "usesCleartextTraffic") or "").lower() == "true":
            findings.append(
                _make_finding(
                    rule_id="MOBILE-ANDROID-CONFIG-003",
                    title="Android application permits cleartext HTTP traffic",
                    cwe="CWE-319",
                    severity="HIGH",
                    confidence=0.90,
                    file_path=rel_path,
                    line=_find_line(lines, "usesCleartextTraffic"),
                    summary=f"`android:usesCleartextTraffic=\"true\"` enabled in {rel_path}.",
                )
            )
        if (_android_attr(app_elem, "debuggable") or "").lower() == "true":
            findings.append(
                _make_finding(
                    rule_id="MOBILE-ANDROID-CONFIG-003",
                    title="Android application is marked debuggable",
                    cwe="CWE-489",
                    severity="HIGH",
                    confidence=0.92,
                    file_path=rel_path,
                    line=_find_line(lines, "debuggable"),
                    summary=f"`android:debuggable=\"true\"` enabled in {rel_path}.",
                )
            )
        if (_android_attr(app_elem, "allowBackup") or "").lower() == "true":
            findings.append(
                _make_finding(
                    rule_id="MOBILE-ANDROID-CONFIG-003",
                    title="Android application allows unencrypted ADB/cloud backups",
                    cwe="CWE-530",
                    severity="MEDIUM",
                    confidence=0.82,
                    file_path=rel_path,
                    line=_find_line(lines, "allowBackup"),
                    summary=f"`android:allowBackup=\"true\"` enabled in {rel_path}.",
                )
            )

    comp_tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for tag in comp_tags:
        for comp in root.iter(tag):
            comp_name = _android_attr(comp, "name") or tag
            exported = (_android_attr(comp, "exported") or "").lower()
            has_intent_filter = comp.find("intent-filter") is not None
            perm = _android_attr(comp, "permission")
            read_perm = _android_attr(comp, "readPermission")
            write_perm = _android_attr(comp, "writePermission")
            grant_uri = (_android_attr(comp, "grantUriPermissions") or "").lower() == "true"

            is_exported = exported == "true" or (has_intent_filter and exported != "false")
            lacks_perm = not perm and not (tag == "provider" and (read_perm or write_perm))
            if is_exported and (lacks_perm or (tag == "provider" and grant_uri and not (read_perm and write_perm))):
                findings.append(
                    _make_finding(
                        rule_id="MOBILE-ANDROID-EXPORTED-001",
                        title=f"Exported Android {tag} `{comp_name}` without permission guard",
                        cwe="CWE-926",
                        severity="HIGH",
                        confidence=0.88,
                        file_path=rel_path,
                        line=_find_line(lines, comp_name, f"<{tag}"),
                        summary=(
                            f"Exported `<{tag}>` `{comp_name}` in {rel_path} lacks an enforcing "
                            f"`android:permission` attribute."
                        ),
                        metadata={"component": comp_name, "component_type": tag},
                    )
                )

            if exported == "false":
                continue

            for ifilter in comp.findall("intent-filter"):
                auto_verify = (_android_attr(ifilter, "autoVerify") or "").lower() == "true"
                for data_el in ifilter.findall("data"):
                    scheme = (_android_attr(data_el, "scheme") or "").strip()
                    if not scheme:
                        continue
                    scheme_l = scheme.lower()
                    if scheme_l in ("openid4vci", "openid4vp", "haip", "eudi") or (
                        scheme_l in ("http", "https") and not auto_verify
                    ) or scheme_l not in ("http", "https"):
                        findings.append(
                            _make_finding(
                                rule_id="MOBILE-DEEPLINK-002",
                                title=f"Unverified/custom Android deep-link scheme `{scheme}://` on `{comp_name}`",
                                cwe="CWE-939",
                                severity="HIGH",
                                confidence=0.86,
                                file_path=rel_path,
                                line=_find_line(lines, scheme, "intent-filter"),
                                summary=(
                                    f"Component `{comp_name}` handles deep-link scheme `{scheme}://` "
                                    f"(autoVerify={auto_verify}) requiring strict URI/origin validation."
                                ),
                                metadata={"scheme": scheme, "component": comp_name, "auto_verify": auto_verify},
                            )
                        )
    return findings


def _audit_network_security_config(rel_path: str, raw_xml: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = raw_xml.splitlines()
    try:
        root = _safe_parse_xml(raw_xml)
    except (ValueError, StdET.ParseError):
        return findings

    for el in root.iter():
        if (el.attrib.get("cleartextTrafficPermitted") or "").lower() == "true":
            findings.append(
                _make_finding(
                    rule_id="MOBILE-ANDROID-CONFIG-003",
                    title="Network Security Config permits cleartext traffic",
                    cwe="CWE-319",
                    severity="HIGH",
                    confidence=0.89,
                    file_path=rel_path,
                    line=_find_line(lines, "cleartextTrafficPermitted"),
                    summary=f"`cleartextTrafficPermitted=\"true\"` in {rel_path}.",
                )
            )
        if el.tag.endswith("certificates") and (el.attrib.get("src") or "").lower() == "user":
            findings.append(
                _make_finding(
                    rule_id="MOBILE-ANDROID-CONFIG-003",
                    title="Network Security Config trusts user-installed CAs",
                    cwe="CWE-295",
                    severity="MEDIUM",
                    confidence=0.82,
                    file_path=rel_path,
                    line=_find_line(lines, 'src="user"', "certificates"),
                    summary=f"`<certificates src=\"user\"/>` weakens certificate pinning in {rel_path}.",
                )
            )
    return findings


def _audit_info_plist(rel_path: str, raw_bytes: bytes) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    text = raw_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()
    try:
        data = _safe_parse_plist(raw_bytes)
    except Exception:
        return findings
    if not isinstance(data, dict):
        return findings

    ats = data.get("NSAppTransportSecurity")
    ats_disabled = (
        isinstance(ats, dict)
        and (
            ats.get("NSAllowsArbitraryLoads") is True
            or ats.get("NSAllowsArbitraryLoadsInWebContent") is True
        )
    ) or (
        data.get("NSAllowsArbitraryLoads") is True
        or data.get("NSAllowsArbitraryLoadsInWebContent") is True
    )
    if ats_disabled:
        findings.append(
            _make_finding(
                rule_id="MOBILE-IOS-ATS-008",
                title="iOS App Transport Security disabled (NSAllowsArbitraryLoads)",
                cwe="CWE-319",
                severity="HIGH",
                confidence=0.90,
                file_path=rel_path,
                line=_find_line(lines, "NSAllowsArbitraryLoads"),
                summary=f"`NSAllowsArbitraryLoads` is enabled in {rel_path}.",
            )
        )

    url_types = data.get("CFBundleURLTypes")
    if isinstance(url_types, list):
        for entry in url_types:
            if not isinstance(entry, dict):
                continue
            for scheme in entry.get("CFBundleURLSchemes") or []:
                s_str = str(scheme).strip()
                if s_str:
                    sev = "HIGH" if s_str.lower() in ("openid4vci", "openid4vp", "haip", "eudi") else "MEDIUM"
                    findings.append(
                        _make_finding(
                            rule_id="MOBILE-IOS-DEEPLINK-009",
                            title=f"iOS custom URL scheme `{s_str}://` registered in Info.plist",
                            cwe="CWE-939",
                            severity=sev,
                            confidence=0.80,
                            file_path=rel_path,
                            line=_find_line(lines, s_str, "CFBundleURLSchemes"),
                            summary=f"URL scheme `{s_str}://` registered in {rel_path}; verify strict handler validation.",
                            metadata={"scheme": s_str},
                        )
                    )
    return findings


def _audit_android_code(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()

    has_js_enabled = bool(re.search(r"setJavaScriptEnabled\s*\(\s*true\s*\)", text))
    for pat, label in (
        (r"addJavascriptInterface\s*\(", "addJavascriptInterface"),
        (r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)", "setAllowFileAccessFromFileURLs(true)"),
        (r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", "setAllowUniversalAccessFromFileURLs(true)"),
    ):
        m = re.search(pat, text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-WEBVIEW-004",
                    title=f"Insecure Android WebView configuration (`{label}`)",
                    cwe="CWE-749",
                    severity="HIGH",
                    confidence=0.88 if has_js_enabled else 0.80,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"WebView enables `{label}` in {rel_path}:{line_no}.",
                )
            )

    for pat, desc in (
        (r"onReceivedSslError\b[\s\S]{0,180}?handler\.proceed\s*\(\s*\)", "onReceivedSslError calls handler.proceed()"),
        (r"HostnameVerifier\b[\s\S]{0,200}?return\s+true\b", "HostnameVerifier unconditionally returns true"),
        (r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}", "Empty X509TrustManager.checkServerTrusted implementation"),
    ):
        m = re.search(pat, text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-TLS-005",
                    title=f"Android TLS certificate validation bypass ({desc})",
                    cwe="CWE-295",
                    severity="HIGH",
                    confidence=0.90,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"{desc} at {rel_path}:{line_no}.",
                )
            )

    has_allowlist_guard = bool(
        re.search(
            r"(?:allowedHosts|allowlist|allowedOrigins|validateHost|verifyOrigin|equalsIgnoreCase\s*\(\s*[\"']https[\"']|startsWith\s*\(\s*[\"']https://)",
            text,
        )
    )
    has_intent_sink_flow = bool(
        re.search(r"(?:intent\.data|getIntent\(\)\.getData\(\)|getQueryParameter\s*\()", text)
        and re.search(
            r"\b(?:loadUrl|startActivity|openConnection|HttpURLConnection|OkHttpClient)\b",
            text,
        )
    )
    m_wallet_scheme = re.search(
        r"""["'](?:openid4vci|openid4vp|haip|eudi)://[^"']*["']""",
        text,
        re.IGNORECASE,
    )
    if not has_allowlist_guard:
        if has_intent_sink_flow:
            line_no = _find_line(lines, "intent.data", "getData()", "getQueryParameter")
            findings.append(
                _make_finding(
                    rule_id="MOBILE-DEEPLINK-CODE-006",
                    title="Unvalidated Android Intent/deep-link URI routed to WebView or HTTP sink",
                    cwe="CWE-939",
                    severity="HIGH",
                    confidence=0.82,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"Intent URI data flows to `loadUrl`/`startActivity`/HTTP sink without host/scheme allowlist in {rel_path}:{line_no}.",
                )
            )
        elif m_wallet_scheme:
            line_no = text[: m_wallet_scheme.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-DEEPLINK-CODE-006",
                    title="Unvalidated Android OID4VCI/OID4VP/HAIP deep-link scheme handler",
                    cwe="CWE-939",
                    severity="HIGH",
                    confidence=0.83,
                    file_path=rel_path,
                    line=line_no,
                    summary=(
                        f"Deep-link handler references `{m_wallet_scheme.group(0)}` without explicit "
                        f"host/origin allowlist validation in {rel_path}:{line_no}."
                    ),
                )
            )

    for pat, desc in (
        (r"""["']AES/ECB(?:/[^"']*)?["']""", "AES/ECB insecure cipher mode"),
        (r"""\b(?:MODE_WORLD_READABLE|MODE_WORLD_WRITABLE)\b""", "World-readable/writable storage mode"),
        (r"""SecretKeySpec\s*\(\s*["'][^"']{4,}["']\.toByteArray""", "Hardcoded SecretKeySpec literal"),
    ):
        m = re.search(pat, text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-CRYPTO-007",
                    title=f"Weak Android cryptography / storage ({desc})",
                    cwe="CWE-327",
                    severity="MEDIUM",
                    confidence=0.84,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"{desc} at {rel_path}:{line_no}.",
                )
            )
    return findings


def _audit_ios_code(rel_path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    if re.search(r"(?:application\s*\([^)]*open\s+url:|func\s+scene\([^)]*openURLContexts|\.onOpenURL\b)", text):
        if not re.search(r"(?:allowedHosts|allowedSchemes|url\.scheme\s*==|host\s*==)", text):
            m = re.search(r"(?:open\s+url:|openURLContexts|\.onOpenURL)", text)
            line_no = text[: m.start()].count("\n") + 1 if m else 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-IOS-DEEPLINK-009",
                    title="iOS deep-link handler lacks explicit scheme/host allowlist",
                    cwe="CWE-939",
                    severity="HIGH",
                    confidence=0.81,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"iOS URL open handler at {rel_path}:{line_no} omits scheme/host validation.",
                )
            )

    for pat, desc in (
        (r"\bUIWebView\b", "Deprecated insecure UIWebView usage"),
        (r"allowUniversalAccessFromFileURLs", "WKWebView allowUniversalAccessFromFileURLs enabled"),
        (r"evaluateJavaScript\s*\([^)]*\\\(", "Unsanitized interpolation inside WKWebView evaluateJavaScript"),
    ):
        m = re.search(pat, text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(
                _make_finding(
                    rule_id="MOBILE-IOS-WEBVIEW-010",
                    title=f"Insecure iOS WebView pattern ({desc})",
                    cwe="CWE-749",
                    severity="HIGH",
                    confidence=0.85,
                    file_path=rel_path,
                    line=line_no,
                    summary=f"{desc} at {rel_path}:{line_no}.",
                )
            )

    m_kc = re.search(r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b", text)
    if m_kc:
        line_no = text[: m_kc.start()].count("\n") + 1
        findings.append(
            _make_finding(
                rule_id="MOBILE-IOS-KEYCHAIN-011",
                title="Weak iOS Keychain accessibility (`kSecAttrAccessibleAlways`)",
                cwe="CWE-522",
                severity="MEDIUM",
                confidence=0.86,
                file_path=rel_path,
                line=line_no,
                summary=f"Keychain item uses `{m_kc.group(0)}` at {rel_path}:{line_no}.",
            )
        )
    return findings


def _audit_archive(rel_path: str, archive_path: Path, use_jadx: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                mname = info.filename
                if info.is_dir():
                    continue
                norm_name = mname.replace("\\", "/")
                parts = norm_name.split("/")
                if (
                    ".." in parts
                    or mname.startswith(("/", "\\"))
                    or (len(mname) >= 2 and mname[1] == ":")
                ):
                    continue
                if info.file_size > _MAX_ZIP_MEMBER_BYTES:
                    continue
                base = Path(norm_name).name.lower()
                if base not in ("androidmanifest.xml", "info.plist"):
                    continue
                try:
                    with zf.open(info, "r") as zfh:
                        raw = zfh.read(_MAX_ZIP_MEMBER_BYTES + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, zlib.error):
                    continue
                if len(raw) > _MAX_ZIP_MEMBER_BYTES:
                    continue
                if base == "androidmanifest.xml":
                    text = raw.decode("utf-8", errors="ignore")
                    if "<manifest" in text:
                        findings.extend(_audit_android_manifest(f"{rel_path}!/{norm_name}", text))
                elif base == "info.plist":
                    findings.extend(_audit_info_plist(f"{rel_path}!/{norm_name}", raw))
    except (OSError, zipfile.BadZipFile):
        return findings

    if use_jadx and archive_path.suffix.lower() == ".apk":
        jadx_bin = shutil.which("jadx")
        if jadx_bin:
            with tempfile.TemporaryDirectory(prefix="rfchunt_jadx_") as tmp_dir:
                cmd = [jadx_bin, "--no-res", "-d", tmp_dir, str(archive_path)]
                ok_cmd, _ = validate_command_tokens(cmd)
                if ok_cmd:
                    try:
                        proc = silent_subprocess_run(
                            cmd,
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=60.0,
                        )
                        if proc.returncode == 0:
                            decompiled_hits = audit_mobile_app(
                                tmp_dir, embedded=True, no_external_scanners=True
                            )
                            for hit in decompiled_hits:
                                orig_fp = str(hit.get("file_path") or "").lstrip("/")
                                prefixed = f"{rel_path}!/{orig_fp}" if orig_fp else rel_path
                                hit["file_path"] = prefixed
                                noise = is_non_production_noise(prefixed)
                                hit["non_production_noise"] = noise
                                if isinstance(hit.get("metadata"), dict):
                                    hit["metadata"]["non_production_noise"] = noise
                            findings.extend(decompiled_hits)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
    return findings


def _probe_mobsf_api(mobsf_url: str) -> Optional[Dict[str, Any]]:
    api_key = os.environ.get("MOBSF_API_KEY", "").strip()
    if not api_key:
        return None
    from urllib.parse import urlparse
    import httpx

    base_url = mobsf_url.strip().rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    ok_host, _ = validate_target_host(
        parsed.hostname, allow_private=is_explicit_loopback_host(parsed.hostname)
    )
    if not ok_host:
        return None
    try:
        resp = httpx.get(
            f"{base_url}/api/v1/scans",
            headers={"Authorization": api_key},
            timeout=1.5,
            follow_redirects=False,
            trust_env=False,
        )
        if resp.status_code != 200:
            return None
        payload = resp.json()
        if not isinstance(payload, dict):
            return None

        scan_items = payload.get("content")
        if not isinstance(scan_items, list):
            scan_items = payload.get("scans")
        if isinstance(scan_items, list):
            fetched_reports: List[Dict[str, Any]] = []
            for entry in scan_items[:5]:
                if not isinstance(entry, dict):
                    continue
                md5_hash = str(
                    entry.get("MD5") or entry.get("md5") or entry.get("hash") or ""
                ).strip()
                if not md5_hash:
                    continue
                try:
                    rep = httpx.post(
                        f"{base_url}/api/v1/report_json",
                        headers={"Authorization": api_key},
                        data={"hash": md5_hash},
                        timeout=2.0,
                        follow_redirects=False,
                        trust_env=False,
                    )
                    if rep.status_code == 200:
                        rep_json = rep.json()
                        if isinstance(rep_json, dict):
                            fetched_reports.append(rep_json)
                except Exception:
                    continue
            if fetched_reports:
                payload = dict(payload)
                payload["_fetched_reports"] = fetched_reports
        return payload
    except Exception:
        return None


def _map_mobsf_severity(raw_sev: Any, default: str = "MEDIUM") -> Optional[str]:
    s = str(raw_sev or "").strip().lower()
    if s in ("info", "secure", "good", "pass", "passed", "normal"):
        return None
    if s in ("critical", "crit"):
        return "CRITICAL"
    if s in ("high", "error", "danger"):
        return "HIGH"
    if s in ("warning", "warn", "medium"):
        return "MEDIUM"
    if s in ("low",):
        return "LOW"
    return default


def _mobsf_payload_to_findings(
    payload: Dict[str, Any],
    *,
    source_label: str = "mobsf://api",
    _include_fetched: bool = True,
) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    findings: List[Dict[str, Any]] = []

    def _emit_mobsf(
        *,
        rule_id: str,
        title: str,
        cwe: str,
        severity: str,
        confidence: float,
        file_path: str,
        line: int,
        summary: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        findings.append(
            _make_finding(
                rule_id=rule_id,
                title=title,
                cwe=cwe,
                severity=severity,
                confidence=confidence,
                file_path=file_path or source_label,
                line=max(1, int(line)),
                summary=summary,
                metadata=metadata,
            )
        )

    appsec = payload.get("appsec") if isinstance(payload.get("appsec"), dict) else {}
    for bucket_name, bucket_sev in (("high", "HIGH"), ("warning", "MEDIUM")):
        for container in (payload, appsec):
            entries = container.get(bucket_name)
            if not isinstance(entries, list):
                continue
            for item in entries:
                if isinstance(item, dict):
                    title = str(item.get("title") or item.get("name") or f"MobSF {bucket_name} finding").strip()
                    desc = str(item.get("description") or item.get("summary") or title).strip()
                    sec = str(item.get("section") or bucket_name).strip()
                    fp = str(item.get("file") or item.get("file_path") or source_label).strip()
                    try:
                        ln = int(item.get("line") or 1)
                    except (TypeError, ValueError):
                        ln = 1
                    _emit_mobsf(
                        rule_id="MOBILE-MOBSF-APPSEC-012",
                        title=title,
                        cwe="CWE-200",
                        severity=bucket_sev,
                        confidence=0.84 if bucket_sev == "HIGH" else 0.78,
                        file_path=fp,
                        line=ln,
                        summary=f"MobSF ({sec}): {desc}",
                        metadata={"mobsf_section": sec, "mobsf_bucket": bucket_name},
                    )
                elif isinstance(item, str) and item.strip():
                    _emit_mobsf(
                        rule_id="MOBILE-MOBSF-APPSEC-012",
                        title=item.strip()[:120],
                        cwe="CWE-200",
                        severity=bucket_sev,
                        confidence=0.80,
                        file_path=source_label,
                        line=1,
                        summary=f"MobSF ({bucket_name}): {item.strip()}",
                        metadata={"mobsf_bucket": bucket_name},
                    )

    insec_conns = payload.get("insecure_connections")
    if isinstance(insec_conns, list):
        for conn in insec_conns:
            desc = (
                str(conn.get("description") or conn.get("title") or conn).strip()
                if isinstance(conn, dict)
                else str(conn).strip()
            )
            if desc:
                _emit_mobsf(
                    rule_id="MOBILE-MOBSF-TLS-013",
                    title="MobSF detected insecure/cleartext connection configuration",
                    cwe="CWE-319",
                    severity="HIGH",
                    confidence=0.85,
                    file_path=source_label,
                    line=1,
                    summary=f"MobSF insecure connection: {desc}",
                    metadata={"mobsf_section": "insecure_connections"},
                )

    man_raw = payload.get("manifest_analysis")
    man_list: List[Any] = []
    if isinstance(man_raw, dict):
        mf = man_raw.get("manifest_findings")
        if isinstance(mf, list):
            man_list = mf
    elif isinstance(man_raw, list):
        man_list = man_raw
    for item in man_list:
        if not isinstance(item, dict):
            continue
        sev = _map_mobsf_severity(item.get("severity") or item.get("stat"), default="MEDIUM")
        if sev is None:
            continue
        title = str(item.get("title") or item.get("name") or "MobSF AndroidManifest finding").strip()
        desc = str(item.get("description") or item.get("desc") or title).strip()
        _emit_mobsf(
            rule_id="MOBILE-MOBSF-MANIFEST-014",
            title=title,
            cwe="CWE-926",
            severity=sev,
            confidence=0.84,
            file_path="AndroidManifest.xml",
            line=1,
            summary=f"MobSF manifest analysis: {desc}",
            metadata={"mobsf_section": "manifest_analysis"},
        )

    code_raw = payload.get("code_analysis")
    code_items: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(code_raw, dict):
        inner = code_raw.get("findings")
        if isinstance(inner, dict):
            for k, v in inner.items():
                if isinstance(v, dict):
                    code_items.append((str(k), v))
        elif isinstance(inner, list):
            for idx, v in enumerate(inner):
                if isinstance(v, dict):
                    code_items.append((str(v.get("rule") or f"code_{idx}"), v))
    elif isinstance(code_raw, list):
        for idx, v in enumerate(code_raw):
            if isinstance(v, dict):
                code_items.append((str(v.get("rule") or f"code_{idx}"), v))

    for rule_key, entry in code_items:
        meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else entry
        sev = _map_mobsf_severity(meta.get("severity"), default="MEDIUM")
        if sev is None:
            continue
        desc = str(meta.get("description") or meta.get("title") or rule_key).strip()
        cwe = str(meta.get("cwe") or "CWE-200").strip()
        files_map = entry.get("files")
        fp = source_label
        ln = 1
        if isinstance(files_map, dict) and files_map:
            first_fp, first_lines = next(iter(files_map.items()))
            fp = str(first_fp or source_label)
            if isinstance(first_lines, str) and first_lines.strip():
                first_tok = first_lines.split(",")[0].strip()
                if first_tok.isdigit():
                    ln = int(first_tok)
            elif isinstance(first_lines, list) and first_lines:
                try:
                    ln = int(first_lines[0])
                except (TypeError, ValueError):
                    ln = 1
            elif isinstance(first_lines, int):
                ln = first_lines
        _emit_mobsf(
            rule_id="MOBILE-MOBSF-CODE-015",
            title=desc[:140],
            cwe=cwe if cwe.upper().startswith("CWE-") else "CWE-200",
            severity=sev,
            confidence=0.83,
            file_path=fp,
            line=ln,
            summary=f"MobSF code analysis ({rule_key}): {desc}",
            metadata={"mobsf_section": "code_analysis", "mobsf_rule": rule_key},
        )

    ats_raw = payload.get("ats_analysis")
    ats_list: List[Any] = []
    if isinstance(ats_raw, dict):
        af = ats_raw.get("ats_findings")
        if not isinstance(af, list):
            af = ats_raw.get("findings")
        if isinstance(af, list):
            ats_list = af
    elif isinstance(ats_raw, list):
        ats_list = ats_raw
    for item in ats_list:
        if not isinstance(item, dict):
            continue
        sev = _map_mobsf_severity(item.get("severity") or item.get("status"), default="MEDIUM")
        if sev is None:
            continue
        issue = str(item.get("issue") or item.get("title") or "MobSF ATS finding").strip()
        desc = str(item.get("description") or issue).strip()
        _emit_mobsf(
            rule_id="MOBILE-MOBSF-ATS-016",
            title=issue,
            cwe="CWE-319",
            severity=sev,
            confidence=0.83,
            file_path="Info.plist",
            line=1,
            summary=f"MobSF ATS analysis: {desc}",
            metadata={"mobsf_section": "ats_analysis"},
        )

    if _include_fetched:
        fetched_reports = payload.get("_fetched_reports")
        if isinstance(fetched_reports, list):
            for rep in fetched_reports:
                if isinstance(rep, dict):
                    rep_label = str(
                        rep.get("app_name") or rep.get("file_name") or rep.get("md5") or source_label
                    ).strip()
                    findings.extend(
                        _mobsf_payload_to_findings(
                            rep,
                            source_label=rep_label,
                            _include_fetched=False,
                        )
                    )

    return findings


def _collect_mobsf_findings(mobsf_url: str) -> List[Dict[str, Any]]:
    payload = _probe_mobsf_api(mobsf_url)
    if not payload:
        return []
    raw_findings = _mobsf_payload_to_findings(payload)
    deduped: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, int, str]] = set()
    for item in raw_findings:
        key = (
            str(item.get("rule_id") or ""),
            str(item.get("file_path") or ""),
            int(item.get("line") or 1),
            str(item.get("title") or ""),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _audit_single_file(repo_root: Path, fpath: Path, use_jadx: bool) -> List[Dict[str, Any]]:
    try:
        rel = fpath.relative_to(repo_root).as_posix()
        size = fpath.stat().st_size
    except OSError:
        return []

    name_l = fpath.name.lower()
    ext_l = fpath.suffix.lower()

    if ext_l in (".apk", ".ipa"):
        return _audit_archive(rel, fpath, use_jadx=use_jadx)

    if size > _MAX_FILE_BYTES:
        return []

    if name_l == "info.plist":
        try:
            return _audit_info_plist(rel, fpath.read_bytes())
        except OSError:
            return []

    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if name_l == "androidmanifest.xml":
        return _audit_android_manifest(rel, text)
    if name_l == "network_security_config.xml":
        return _audit_network_security_config(rel, text)
    if ext_l in (".kt", ".java"):
        return _audit_android_code(rel, text)
    if ext_l in (".swift", ".m", ".mm"):
        return _audit_ios_code(rel, text)
    return []


def audit_mobile_app(
    repo_path: Union[Path, str],
    *,
    embedded: bool = False,
    no_external_scanners: bool = False,
    mobsf_url: Optional[str] = None,
    target_files: Optional[Sequence[Union[Path, str]]] = None,
) -> List[Dict[str, Any]]:
    """
    Audits Android and iOS repositories/archives (`AndroidManifest.xml`, `Info.plist`,
    `.kt`, `.java`, `.swift`, `.m`, `.apk`, `.ipa`) with XXE-safe parsing and optional
    `jadx`/MobSF integration when permitted. Supports diff-scoped `target_files`.
    """
    ok_mount, resolved_repo = validate_mount_path(repo_path)
    if not ok_mount:
        return []
    root = Path(resolved_repo)

    use_external = not embedded and not no_external_scanners
    mobsf_findings = _collect_mobsf_findings(mobsf_url) if (use_external and mobsf_url) else []

    _mobile_names = ("androidmanifest.xml", "network_security_config.xml", "info.plist")
    _mobile_exts = (".kt", ".java", ".swift", ".m", ".mm", ".apk", ".ipa")
    targets: List[Path] = []
    if target_files is not None:
        seen_paths: set[Path] = set()
        for raw_f in target_files:
            cand = Path(raw_f)
            cand = (root / cand).resolve() if not cand.is_absolute() else cand.resolve()
            try:
                cand.relative_to(root)
            except ValueError:
                continue
            if cand in seen_paths or not cand.is_file():
                continue
            seen_paths.add(cand)
            if cand.name.lower() in _mobile_names or cand.suffix.lower() in _mobile_exts:
                targets.append(cand)
    else:
        for walk_root, dirs, filenames in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            for fname in sorted(filenames):
                fpath = Path(walk_root) / fname
                nl = fname.lower()
                el = fpath.suffix.lower()
                if nl in _mobile_names or el in _mobile_exts:
                    targets.append(fpath)

    if not targets:
        mobsf_findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
        return mobsf_findings

    max_workers = min(8, max(2, os.cpu_count() or 4))
    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for hits in pool.map(lambda p: _audit_single_file(root, p, use_jadx=use_external), targets):
            findings.extend(hits)

    findings.extend(mobsf_findings)
    findings.sort(key=lambda f: (f["file_path"], f["line"], f["rule_id"]))
    return findings
