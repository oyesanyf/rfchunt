"""
Zero-Mock Integration & Unit Tests for M1 Defensive Ensemble Scanners & Ollama Concurrency Guard.
=================================================================================================
Uses real temporary repositories, real XML/Plist/OpenAPI/AST fixtures, real local
`ThreadingHTTPServer` endpoints, and real Windows-spawn `multiprocessing` workers.
Contains ZERO `unittest.mock`, `MagicMock`, or `monkeypatch`.
"""

from __future__ import annotations

import io
import json
import multiprocessing as mp
import os
import struct
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from engine.ai_infra_guard_auditor import audit_ai_infra
from engine.api_jwt_sdjwt_auditor import _parse_subfinder_jsonl, audit_api_and_jwt
from engine.ensemble_orchestrator import EngineFinding
from engine.gha_llm_verifier import verify_gha_findings_with_llm
from engine.mobile_app_auditor import (
    _mobsf_payload_to_findings,
    _safe_parse_plist,
    _safe_parse_xml,
    audit_mobile_app,
)
from engine.ollama_concurrency_guard import OllamaConcurrencyGuard
from engine.parity_invariant_auditor import (
    audit_parity_and_invariants,
    filter_production_candidates,
    is_non_production_noise,
)
from engine.program_eligibility_db import ProgramEligibilityDB
from engine.trufflehog_scanner import redact_secret, scan_secrets_with_trufflehog


# Top-level picklable worker for Windows `spawn` cross-process lock verification
def _child_try_acquire_ollama_lock(
    lock_path_str: str,
    out_path_str: str,
    timeout_sec: float,
) -> None:
    guard = OllamaConcurrencyGuard(lock_path=lock_path_str, acquire_timeout_sec=timeout_sec)
    with guard.acquire(timeout_sec=timeout_sec) as acquired:
        Path(out_path_str).write_text("1" if acquired else "0", encoding="utf-8")


def _write_cli_shim(bin_dir: Path, name: str, py_body: str) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    impl_path = bin_dir / f"_{name}_impl.py"
    impl_path.write_text(py_body, encoding="utf-8")
    if os.name == "nt":
        shim_path = bin_dir / f"{name}.cmd"
        shim_path.write_text(
            "@echo off\n" + f'"{sys.executable}" "{impl_path}" %*\n',
            encoding="utf-8",
        )
    else:
        shim_path = bin_dir / name
        shim_path.write_text(
            "#!/bin/sh\n" + f'exec "{sys.executable}" "{impl_path}" "$@"\n',
            encoding="utf-8",
        )
        os.chmod(shim_path, 0o755)
    return shim_path


# ---------------------------------------------------------------------------
# 1. TruffleHog Secret Scanner
# ---------------------------------------------------------------------------


def test_trufflehog_scanner_redaction_placeholders_and_only_verified(tmp_path: Path) -> None:
    # Construct synthetic test credentials via concatenation so push protection never false-positives
    aws_tok = "AKIA" + "Q9X7M2K4P8W3R6T5"
    gh_tok = "ghp_" + "9Kx4mP2qR7vL8nT3wZ6yB1cF5hJ0dS4aE8uI"
    ant_tok = "sk-ant-api03-" + "9Kx4mP2qR7vL8nT3wZ6yB1cF5hJ0dS4aE8uI"
    stripe_tok = "sk_live_" + "9Kx4mP2qR7vL8nT3wZ6yB1cF5hJ0dS4a"
    high_ent = "R9vM2xP7qK4wL8nT3zY6bF1cH5jD0sA4eU8iO2pQ7"

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "config.py").write_text(
        "\n".join(
            [
                f'AWS_KEY = "{aws_tok}"',
                f'GH_TOKEN = "{gh_tok}"',
                f'ANT_KEY = "{ant_tok}"',
                f'STRIPE_KEY = "{stripe_tok}"',
                f'api_key = "{high_ent}"',
                'PLACEHOLDER_KEY = "YOUR_EXAMPLE_API_KEY_PLACEHOLDER_12345"',
                'DUMMY_TOKEN = "' + 'ghp_' + 'TESTFAKEEXAMPLE000000000000000000000"',
            ]
        ),
        encoding="utf-8",
    )

    findings = scan_secrets_with_trufflehog(tmp_path, embedded=True)
    rule_ids = {f["rule_id"] for f in findings}
    assert "TRUFFLEHOG-AWS-KEY-001" in rule_ids
    assert "TRUFFLEHOG-GITHUB-TOKEN-002" in rule_ids
    assert "TRUFFLEHOG-ANTHROPIC-KEY-003" in rule_ids
    assert "TRUFFLEHOG-STRIPE-KEY-005" in rule_ids
    assert "TRUFFLEHOG-ENTROPY-009" in rule_ids
    assert len(findings) == 5

    raw_secrets = (aws_tok, gh_tok, ant_tok, stripe_tok, high_ent)
    for f in findings:
        assert f["engine"] == "trufflehog"
        assert f["deterministic"] is True
        assert f["confirmed"] is True
        assert f["non_production_noise"] is False
        assert f["line"] >= 1
        serialized = f["title"] + " " + f["summary"] + " " + json.dumps(f["metadata"])
        for secret in raw_secrets:
            assert secret not in serialized
        assert "<REDACTED" in f["summary"]
        assert "<REDACTED" in redact_secret(secret_preview := aws_tok)
        assert secret_preview not in redact_secret(secret_preview)

    # Fail-closed: offline pure-Python mode cannot live-verify secrets when only_verified=True
    assert scan_secrets_with_trufflehog(tmp_path, embedded=True, only_verified=True) == []


# ---------------------------------------------------------------------------
# 2. MobSF + jadx Mobile App Auditor
# ---------------------------------------------------------------------------


def test_mobile_app_auditor_android_ios_and_xxe_fail_closed(tmp_path: Path) -> None:
    android_dir = tmp_path / "android" / "app" / "src" / "main"
    android_dir.mkdir(parents=True)
    (android_dir / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.wallet.app">
  <application android:usesCleartextTraffic="true" android:debuggable="true">
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="openid4vci" />
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )
    (android_dir / "WebBridge.kt").write_text(
        """class WebBridge {
  fun setup(webView: WebView, handler: SslErrorHandler) {
    webView.settings.setJavaScriptEnabled(true)
    webView.addJavascriptInterface(this, "NativeBridge")
  }
  fun onReceivedSslError(view: WebView, handler: SslErrorHandler) {
    handler.proceed()
  }
}
""",
        encoding="utf-8",
    )

    ios_dir = tmp_path / "ios" / "WalletApp"
    ios_dir.mkdir(parents=True)
    (ios_dir / "Info.plist").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>openid4vp</string>
      </array>
    </dict>
  </array>
</dict>
</plist>
""",
        encoding="utf-8",
    )
    (ios_dir / "KeychainHelper.swift").write_text(
        "let attr = kSecAttrAccessibleAlways\n",
        encoding="utf-8",
    )

    findings = audit_mobile_app(tmp_path, embedded=True)
    rule_ids = {f["rule_id"] for f in findings}
    assert "MOBILE-ANDROID-EXPORTED-001" in rule_ids
    assert "MOBILE-DEEPLINK-002" in rule_ids
    assert "MOBILE-ANDROID-CONFIG-003" in rule_ids
    assert "MOBILE-WEBVIEW-004" in rule_ids
    assert "MOBILE-TLS-005" in rule_ids
    assert "MOBILE-IOS-ATS-008" in rule_ids
    assert "MOBILE-IOS-DEEPLINK-009" in rule_ids
    assert "MOBILE-IOS-KEYCHAIN-011" in rule_ids
    assert all(f["engine"] == "mobile_mobsf" and f["deterministic"] is True for f in findings)

    # XXE rejection must fail closed on DOCTYPE / ENTITY payloads
    xxe_xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><manifest>&xxe;</manifest>'
    with pytest.raises(ValueError):
        _safe_parse_xml(xxe_xml)

    xxe_plist = b'<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><plist><dict/></plist>'
    with pytest.raises(ValueError):
        _safe_parse_plist(xxe_plist)


def test_mobile_app_auditor_mobsf_api_and_failsafe_scan_list(tmp_path: Path) -> None:
    mode = {"with_report": True}
    requests_seen: list[str] = []

    class _MobSFHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests_seen.append(f"GET {self.path}")
            if self.headers.get("Authorization") != "test-mobsf-key":
                self.send_response(401)
                self.end_headers()
                return
            payload = json.dumps({"content": [{"MD5": "abc123", "APP_NAME": "WalletApp"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            requests_seen.append(f"POST {self.path}")
            length = int(self.headers.get("Content-Length") or "0")
            _ = self.rfile.read(length)
            if not mode["with_report"]:
                self.send_response(404)
                self.end_headers()
                return
            rep = json.dumps(
                {
                    "app_name": "WalletApp",
                    "appsec": {
                        "high": [
                            {
                                "title": "App is debuggable",
                                "description": "android:debuggable=true",
                                "section": "manifest",
                            }
                        ],
                        "warning": [],
                    },
                    "insecure_connections": ["http://legacy.internal/api"],
                    "manifest_analysis": {
                        "manifest_findings": [
                            {
                                "title": "Exported Broadcast Receiver",
                                "severity": "high",
                                "description": "Receiver lacks permission",
                            },
                            {
                                "title": "Normal permission",
                                "severity": "info",
                                "description": "Harmless",
                            },
                        ]
                    },
                    "code_analysis": {
                        "findings": {
                            "android_insecure_ssl": {
                                "metadata": {
                                    "severity": "high",
                                    "description": "TrustAllCerts detected",
                                    "cwe": "CWE-295",
                                },
                                "files": {"com/wallet/Net.java": "42, 88"},
                            }
                        }
                    },
                    "ats_analysis": {
                        "ats_findings": [
                            {
                                "issue": "NSAllowsArbitraryLoads enabled",
                                "severity": "high",
                                "description": "ATS disabled",
                            }
                        ]
                    },
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(rep)))
            self.end_headers()
            self.wfile.write(rep)

        def log_message(self, format, *args):
            return

    empty_repo = tmp_path / "empty_repo"
    empty_repo.mkdir()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MobSFHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    orig_key = os.environ.get("MOBSF_API_KEY")
    try:
        os.environ["MOBSF_API_KEY"] = "test-mobsf-key"
        url = f"http://127.0.0.1:{port}"

        # 1. Even with zero local files, MobSF API findings are returned
        hits = audit_mobile_app(empty_repo, embedded=False, no_external_scanners=False, mobsf_url=url)
        rule_ids = {h["rule_id"] for h in hits}
        assert "MOBILE-MOBSF-APPSEC-012" in rule_ids
        assert "MOBILE-MOBSF-TLS-013" in rule_ids
        assert "MOBILE-MOBSF-MANIFEST-014" in rule_ids
        assert "MOBILE-MOBSF-CODE-015" in rule_ids
        assert "MOBILE-MOBSF-ATS-016" in rule_ids
        assert all(h["engine"] == "mobile_mobsf" and h["deterministic"] is True for h in hits)
        code_hit = next(h for h in hits if h["rule_id"] == "MOBILE-MOBSF-CODE-015")
        assert code_hit["file_path"] == "com/wallet/Net.java"
        assert code_hit["line"] == 42

        # 2. embedded=True must NOT call MobSF API
        requests_seen.clear()
        assert audit_mobile_app(empty_repo, embedded=True, mobsf_url=url) == []
        assert requests_seen == []

        # 2b. URLs containing embedded userinfo must be rejected with zero HTTP requests
        requests_seen.clear()
        assert (
            audit_mobile_app(
                empty_repo,
                embedded=False,
                no_external_scanners=False,
                mobsf_url=f"http://user:pass@127.0.0.1:{port}",
            )
            == []
        )
        assert (
            audit_mobile_app(
                empty_repo,
                embedded=False,
                no_external_scanners=False,
                mobsf_url="http://user:pass@127.0.0.1:8000",
            )
            == []
        )
        assert requests_seen == []

        # 2c. Nested _fetched_reports cannot recurse beyond 1 level
        nested_payload = {
            "_fetched_reports": [
                {
                    "app_name": "Level1",
                    "insecure_connections": ["http://level1.internal/api"],
                    "_fetched_reports": [
                        {
                            "app_name": "Level2",
                            "insecure_connections": ["http://level2.internal/api"],
                        }
                    ],
                }
            ]
        }
        nested_hits = _mobsf_payload_to_findings(nested_payload)
        assert len(nested_hits) == 1
        assert nested_hits[0]["file_path"] == "Level1"
        assert "level1.internal" in nested_hits[0]["summary"]

        # 3. Scan-list-only (no report findings) fails safe to [] without fabricating hits
        mode["with_report"] = False
        assert audit_mobile_app(empty_repo, embedded=False, mobsf_url=url) == []
    finally:
        if orig_key is None:
            os.environ.pop("MOBSF_API_KEY", None)
        else:
            os.environ["MOBSF_API_KEY"] = orig_key
        srv.shutdown()
        srv.server_close()


def test_mobile_app_auditor_plist_padding_utf16_zip_spoof_and_exported_false(tmp_path: Path) -> None:
    # 1. >8KB comment-padded & UTF-16 BOM / no-BOM <!ENTITY plists must be rejected
    pad_comment = "<!-- " + ("A" * 9000) + " -->"
    padded_xxe = (
        f'<?xml version="1.0" encoding="UTF-8"?>{pad_comment}'
        '<!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><plist><dict/></plist>'
    ).encode()
    with pytest.raises(ValueError):
        _safe_parse_plist(padded_xxe)

    utf16_xml = '<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><plist><dict/></plist>'
    with pytest.raises(ValueError):
        _safe_parse_plist(utf16_xml.encode("utf-16"))
    with pytest.raises(ValueError):
        _safe_parse_plist(utf16_xml.encode("utf-16-le"))

    # 2. Zip bomb with spoofed info.file_size=100 (>2MB deflated) + backslash traversal skipped cleanly
    repo = tmp_path / "mobile_hardening"
    android_dir = repo / "app"
    android_dir.mkdir(parents=True)

    big_payload = b"<manifest>" + (b"A" * 2_200_000) + b"</manifest>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", big_payload)
    real_size_le = struct.pack("<I", len(big_payload))
    spoof_size_le = struct.pack("<I", 100)
    raw_zip = buf.getvalue().replace(real_size_le, spoof_size_le)
    (repo / "spoofed.apk").write_bytes(raw_zip)
    with zipfile.ZipFile(repo / "spoofed.apk", "r") as zchk:
        assert zchk.infolist()[0].file_size == 100

    # Backslash traversal member should also be skipped safely
    trav_buf = io.BytesIO()
    with zipfile.ZipFile(trav_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "..\\AndroidManifest.xml",
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true"/></manifest>',
        )
    (repo / "traversal.apk").write_bytes(trav_buf.getvalue())

    # 3. exported="false" deep-link must NOT emit MOBILE-DEEPLINK-002 or MOBILE-ANDROID-EXPORTED-001
    (android_dir / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.wallet.safe">
  <application>
    <activity android:name=".InternalLinkActivity" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="openid4vci" />
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )

    # 4. Standalone Kotlin openid4vci:// handler without allowlist triggers MOBILE-DEEPLINK-CODE-006
    (android_dir / "UnsafeOffer.kt").write_text(
        """class UnsafeOffer {
  fun handle(uri: String) {
    if (uri.startsWith("openid4vci://")) {
      processOffer(uri)
    }
  }
}
""",
        encoding="utf-8",
    )
    (android_dir / "SafeOffer.kt").write_text(
        """class SafeOffer {
  private val allowedHosts = setOf("issuer.example.com")
  fun handle(uri: String, host: String) {
    if (allowedHosts.contains(host) && uri.startsWith("openid4vci://")) {
      processOffer(uri)
    }
  }
}
""",
        encoding="utf-8",
    )

    findings = audit_mobile_app(repo, embedded=True)
    rule_ids = {f["rule_id"] for f in findings}
    assert "MOBILE-DEEPLINK-002" not in rule_ids
    assert "MOBILE-ANDROID-EXPORTED-001" not in rule_ids
    assert "MOBILE-ANDROID-CONFIG-003" not in rule_ids
    dl_code = [f for f in findings if f["rule_id"] == "MOBILE-DEEPLINK-CODE-006"]
    assert len(dl_code) == 1
    assert dl_code[0]["file_path"] == "app/UnsafeOffer.kt"


# ---------------------------------------------------------------------------
# 3. API Surface & JWT / SD-JWT Auditor
# ---------------------------------------------------------------------------


def test_api_jwt_sdjwt_auditor_offline_and_fail_closed_live_gate(tmp_path: Path) -> None:
    api_dir = tmp_path / "src" / "auth"
    api_dir.mkdir(parents=True)
    (api_dir / "jwt_verify.py").write_text(
        """import jwt
import requests

def decode_untrusted(token, pub_key):
    hdr = jwt.get_unverified_header(token)
    jwks = requests.get(hdr["jku"]).json()
    a = jwt.decode(token, algorithms=["none", "RS256", "HS256"], options={"verify_exp": False})
    return a, jwks

def parse_sd_jwt(raw_sd_jwt):
    parts = raw_sd_jwt.split("~")
    return parts
""",
        encoding="utf-8",
    )
    (api_dir / "openapi.yaml").write_text(
        """openapi: 3.0.3
info:
  title: Wallet API
  version: 1.0.0
paths:
  /v1/mdvm/issue:
    post:
      security: []
      responses:
        "200":
          description: ok
""",
        encoding="utf-8",
    )

    findings = audit_api_and_jwt(tmp_path, embedded=True)
    rule_ids = {f["rule_id"] for f in findings}
    assert "JWT-ALG-NONE-001" in rule_ids
    assert "JWT-ALG-CONFUSION-002" in rule_ids
    assert "JWT-CLAIMS-MISSING-003" in rule_ids
    assert "JWT-HEADER-SSRF-004" in rule_ids
    assert "SDJWT-BINDING-005" in rule_ids
    assert "OPENAPI-AUTH-MISSING-006" in rule_ids
    assert all(f["engine"] == "api_jwt_sdjwt" and f["deterministic"] is True for f in findings)

    # Verify fail-closed live gate against a real local HTTP server
    hits: list[str] = []

    class _HitHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            return

    db = ProgramEligibilityDB(tmp_path / "elig.sqlite3")
    db.seed_observed_hackerone_baseline()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _HitHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # "shopify" is BLOCKED_SIGNAL -> must NOT make any live network requests
        audit_api_and_jwt(
            tmp_path,
            program="shopify",
            allow_live=True,
            embedded=False,
            no_external_scanners=False,
            eligibility_db=db,
            target_hosts=[f"http://127.0.0.1:{port}"],
        )
        assert hits == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_api_jwt_sdjwt_auditor_live_pipeline_eligible_and_nested_regex(tmp_path: Path) -> None:
    # 1. Static quoted dict options, nested jwt.decode, and OpenAPI servers[].url SSRF (paths: {})
    static_dir = tmp_path / "static_cases"
    (static_dir / "quoted").mkdir(parents=True)
    (static_dir / "quoted" / "options.py").write_text(
        """import jwt

def check_opts(tok, pub_key):
    a = jwt.decode(tok, pub_key, algorithms=["RS256"], options={"verify_signature": False})
    b = jwt.decode(tok, pub_key, algorithms=["RS256"], options={"verify": False})
    c = jwt.decode(tok, pub_key, algorithms=["RS256"], options={"verify_aud": False, "verify_iss": False})
    return a, b, c
""",
        encoding="utf-8",
    )
    (static_dir / "nested_unpinned").mkdir(parents=True)
    (static_dir / "nested_unpinned" / "verify_bad.py").write_text(
        """import jwt

def verify_bad(tok):
    return jwt.decode(tok, get_public_key())
""",
        encoding="utf-8",
    )
    (static_dir / "nested_pinned").mkdir(parents=True)
    (static_dir / "nested_pinned" / "verify_ok.py").write_text(
        """import jwt

def verify_ok(tok):
    return jwt.decode(tok, get_public_key(), algorithms=["RS256"])
""",
        encoding="utf-8",
    )
    (static_dir / "specs").mkdir(parents=True)
    (static_dir / "specs" / "ssrf_openapi.yaml").write_text(
        """openapi: 3.0.3
info:
  title: Metadata Spec
  version: 1.0.0
servers:
  - url: http://169.254.169.254/latest/meta-data/
paths: {}
""",
        encoding="utf-8",
    )
    (static_dir / "specs" / "public_openapi.yaml").write_text(
        """openapi: 3.0.3
info:
  title: Public Spec
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths: {}
""",
        encoding="utf-8",
    )
    (static_dir / "specs" / "proto_rel_ssrf_openapi.yaml").write_text(
        """openapi: 3.0.3
info:
  title: Protocol-Relative Metadata Spec
  version: 1.0.0
servers:
  - url: //169.254.169.254/latest/meta-data/
paths: {}
""",
        encoding="utf-8",
    )
    (static_dir / "specs" / "rel_path_openapi.yaml").write_text(
        """openapi: 3.0.3
info:
  title: Relative Path Spec
  version: 1.0.0
servers:
  - url: /api/v1
paths: {}
""",
        encoding="utf-8",
    )

    quoted_hits = audit_api_and_jwt(static_dir / "quoted", embedded=True)
    assert {h["rule_id"] for h in quoted_hits} >= {"JWT-ALG-NONE-001", "JWT-CLAIMS-MISSING-003"}
    assert len([h for h in quoted_hits if h["rule_id"] == "JWT-ALG-NONE-001"]) == 2

    bad_hits = audit_api_and_jwt(static_dir / "nested_unpinned", embedded=True)
    assert any(h["rule_id"] == "JWT-ALG-CONFUSION-002" for h in bad_hits)

    ok_hits = audit_api_and_jwt(static_dir / "nested_pinned", embedded=True)
    assert not any(h["rule_id"] == "JWT-ALG-CONFUSION-002" for h in ok_hits)

    spec_hits = audit_api_and_jwt(static_dir / "specs", embedded=True)
    ssrf_hits = [h for h in spec_hits if h["rule_id"] == "OPENAPI-SERVER-SSRF-007"]
    assert len(ssrf_hits) == 2
    assert {h["file_path"] for h in ssrf_hits} == {"ssrf_openapi.yaml", "proto_rel_ssrf_openapi.yaml"}
    assert all(
        h["cwe"] == "CWE-918"
        and h["severity"] == "CRITICAL"
        and h["non_production_noise"] is False
        for h in ssrf_hits
    )

    # 2. _parse_subfinder_jsonl SSRF & scope isolation
    sub_jsonl = "\n".join(
        [
            json.dumps({"host": "api.localhost"}),
            json.dumps({"host": "169.254.169.254"}),
            json.dumps({"host": "127.0.0.1"}),
            json.dumps({"host": "evil.com"}),
        ]
    )
    assert _parse_subfinder_jsonl(sub_jsonl, base_host="example.com", allow_private=False) == []
    assert _parse_subfinder_jsonl(sub_jsonl, base_host="localhost", allow_private=True) == ["api.localhost"]

    # 3. Full live pipeline with real CLI shims + ThreadingHTTPServer (blocked vs eligible)
    recorded_requests: list[dict[str, Any]] = []

    class _LiveApiHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            recorded_requests.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "user_agent": self.headers.get("User-Agent"),
                    "x_hackerone": self.headers.get("X-HackerOne"),
                }
            )
            if self.path == "/":
                body = b'<html><title>Wallet Portal</title><a href="/docs/openapi.json">spec</a></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/docs/openapi.json":
                spec_body = json.dumps(
                    {
                        "openapi": "3.0.3",
                        "info": {"title": "Live API", "version": "1.0.0"},
                        "paths": {
                            "/v1/mdvm/issue": {
                                "post": {
                                    "responses": {"200": {"description": "ok"}}
                                }
                            }
                        },
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(spec_body)))
                self.end_headers()
                self.wfile.write(spec_body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            _ = self.rfile.read(length)
            recorded_requests.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "user_agent": self.headers.get("User-Agent"),
                    "x_hackerone": self.headers.get("X-HackerOne"),
                }
            )
            if self.path == "/v1/mdvm/issue":
                err = b'{"error":"server error"}'
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            return

    shim_dir = tmp_path / "shims"
    _write_cli_shim(
        shim_dir,
        "httpx",
        """import json, re, sys, urllib.request
args = sys.argv[1:]
url = ""
hdrs = {}
i = 0
while i < len(args):
    if args[i] == "-u" and i + 1 < len(args):
        url = args[i + 1]
        i += 2
    elif args[i] == "-H" and i + 1 < len(args):
        k, _, v = args[i + 1].partition(":")
        hdrs[k.strip()] = v.strip()
        i += 2
    else:
        i += 1
req = urllib.request.Request(url, headers=hdrs)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = resp.read().decode("utf-8", errors="replace")
    m = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
    print(json.dumps({
        "url": url,
        "status_code": resp.status,
        "header": {k.lower(): v for k, v in resp.headers.items()},
        "title": m.group(1) if m else "",
        "tech": ["Python"],
    }))
""",
    )
    _write_cli_shim(
        shim_dir,
        "katana",
        """import json, re, sys, urllib.parse, urllib.request
args = sys.argv[1:]
url = ""
hdrs = {}
i = 0
while i < len(args):
    if args[i] == "-u" and i + 1 < len(args):
        url = args[i + 1]
        i += 2
    elif args[i] == "-H" and i + 1 < len(args):
        k, _, v = args[i + 1].partition(":")
        hdrs[k.strip()] = v.strip()
        i += 2
    else:
        i += 1
req = urllib.request.Request(url, headers=hdrs)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = resp.read().decode("utf-8", errors="replace")
for href in re.findall(r'href="([^"]+)"', body):
    ep = urllib.parse.urljoin(url, href)
    print(json.dumps({"request": {"method": "GET", "endpoint": ep}, "response": {"status_code": 200}}))
""",
    )
    _write_cli_shim(
        shim_dir,
        "schemathesis",
        """import json, sys, urllib.error, urllib.parse, urllib.request
args = sys.argv[1:]
assert "run" in args
assert "--checks=not_a_server_error" in args
assert "--max-examples=5" in args
hdrs = {}
i = 0
while i < len(args):
    if args[i] == "-H" and i + 1 < len(args):
        k, _, v = args[i + 1].partition(":")
        hdrs[k.strip()] = v.strip()
        i += 2
    else:
        i += 1
spec_url = args[-1]
req = urllib.request.Request(spec_url, headers=hdrs)
with urllib.request.urlopen(req, timeout=5) as resp:
    spec = json.loads(resp.read().decode("utf-8"))
parsed = urllib.parse.urlparse(spec_url)
base = f"{parsed.scheme}://{parsed.netloc}"
failed = False
for p, item in (spec.get("paths") or {}).items():
    for m in item.keys():
        target = base + p
        r2 = urllib.request.Request(target, data=b"{}", method=m.upper(), headers=hdrs)
        try:
            urllib.request.urlopen(r2, timeout=5)
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                print(f"FAILED {m.upper()} {p} (not_a_server_error: HTTP {exc.code})")
                failed = True
sys.exit(1 if failed else 0)
""",
    )

    live_repo = tmp_path / "live_repo"
    live_repo.mkdir()
    (live_repo / "app.py").write_text("print('clean')\n", encoding="utf-8")

    db = ProgramEligibilityDB(tmp_path / "elig_live.sqlite3")
    db.seed_observed_hackerone_baseline()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LiveApiHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    orig_path = os.environ.get("PATH", "")
    orig_h1_handle = os.environ.get("HACKERONE_RESEARCHER_HANDLE")
    try:
        os.environ["PATH"] = f"{shim_dir}{os.pathsep}{orig_path}"
        os.environ["HACKERONE_RESEARCHER_HANDLE"] = "test_researcher"
        target = f"http://127.0.0.1:{port}"

        # Blocked program makes zero HTTP requests even with shims on PATH
        blocked = audit_api_and_jwt(
            live_repo,
            program="shopify",
            allow_live=True,
            embedded=False,
            no_external_scanners=False,
            eligibility_db=db,
            target_hosts=[target],
        )
        assert blocked == []
        assert recorded_requests == []

        # Eligible program executes httpx -> katana -> schemathesis and emits live findings
        live_hits = audit_api_and_jwt(
            live_repo,
            program="common_codes",
            allow_live=True,
            embedded=False,
            no_external_scanners=False,
            eligibility_db=db,
            max_rps=2.0,
            target_hosts=[target],
        )
        live_rules = {h["rule_id"] for h in live_hits}
        assert "API-HTTPX-HEADERS-008" in live_rules
        assert "API-KATANA-SPEC-009" in live_rules
        assert "API-SCHEMATHESIS-5XX-011" in live_rules
        assert all(
            h["engine"] == "api_jwt_sdjwt"
            and h["deterministic"] is True
            and h["non_production_noise"] is False
            for h in live_hits
        )

        paths_hit = [(r["method"], r["path"]) for r in recorded_requests]
        assert ("GET", "/") in paths_hit
        assert ("GET", "/docs/openapi.json") in paths_hit
        assert ("POST", "/v1/mdvm/issue") in paths_hit
        assert all(
            r["user_agent"] == "HackerOne/test_researcher" and r["x_hackerone"] == "test_researcher"
            for r in recorded_requests
        )
    finally:
        os.environ["PATH"] = orig_path
        if orig_h1_handle is None:
            os.environ.pop("HACKERONE_RESEARCHER_HANDLE", None)
        else:
            os.environ["HACKERONE_RESEARCHER_HANDLE"] = orig_h1_handle
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# 4. AI-Infra-Guard & DeepAudit Static Auditor
# ---------------------------------------------------------------------------


def test_ai_infra_guard_auditor_detects_all_rule_families(tmp_path: Path) -> None:
    infra_dir = tmp_path / "deploy"
    infra_dir.mkdir()
    (infra_dir / "docker-compose.yml").write_text(
        """services:
  ollama:
    environment:
      - OLLAMA_HOST=0.0.0.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
        encoding="utf-8",
    )
    (infra_dir / "Dockerfile").write_text("FROM vllm/vllm-openai:latest\n", encoding="utf-8")

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "agent_runner.py").write_text(
        """import pickle
import subprocess
import jinja2
import torch
import yaml

def run_agent(user_input, cfg_text, model_path, blob):
    obj = pickle.loads(blob)
    weights = torch.load(model_path)
    cfg = yaml.load(cfg_text)
    tpl = jinja2.Template(user_input)
    cmd = f"echo {user_input}"
    subprocess.run(cmd, shell=True)
    return obj, weights, cfg, tpl
""",
        encoding="utf-8",
    )

    findings = audit_ai_infra(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert "AI-INFRA-BIND-001" in rule_ids
    assert "AI-INFRA-DESER-002" in rule_ids
    assert "AI-INFRA-SSTI-003" in rule_ids
    assert "AI-INFRA-K8S-004" in rule_ids
    assert "AI-INFRA-TAINT-005" in rule_ids
    assert all(f["engine"] == "ai_infra_guard" and f["deterministic"] is True for f in findings)


def test_ai_infra_guard_nested_ast_taint_quote_id_and_positional_safeloader(tmp_path: Path) -> None:
    app_dir = tmp_path / "src"
    app_dir.mkdir()
    (app_dir / "nested_taint.py").write_text(
        """import shlex
import subprocess
import yaml

def handler(user_input, flag):
    if flag:
        try:
            quote_id = user_input
        except Exception:
            quote_id = "safe"
        subprocess.run(f"echo {quote_id}", shell=True)

def safe_handler(user_input, cfg_text):
    safe_arg = shlex.quote(user_input)
    subprocess.run(f"echo {safe_arg}", shell=True)
    cfg1 = yaml.load(cfg_text, yaml.SafeLoader)
    cfg2 = yaml.load(cfg_text, yaml.CSafeLoader)
    return cfg1, cfg2
""",
        encoding="utf-8",
    )
    (app_dir / "nul_bytes.py").write_bytes(b"def broken():\x00\n    pass\n")

    findings = audit_ai_infra(tmp_path)
    taint_hits = [f for f in findings if f["rule_id"] == "AI-INFRA-TAINT-005"]
    deser_hits = [f for f in findings if f["rule_id"] == "AI-INFRA-DESER-002"]

    assert len(taint_hits) == 1
    assert taint_hits[0]["line"] == 11
    assert deser_hits == []


def test_ai_infra_guard_branch_join_preserves_taint_and_allows_all_branch_sanitized(tmp_path: Path) -> None:
    app_dir = tmp_path / "src"
    app_dir.mkdir()
    (app_dir / "if_branch_taint.py").write_text(
        """import shlex
import subprocess

def unsafe_fallback(user_input, legacy_mode):
    if legacy_mode:
        cmd = user_input
    else:
        cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)

def safe_both_branches(user_input, a):
    if a:
        cmd = shlex.quote(user_input)
    else:
        cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)

def unsafe_try_fallback(user_input):
    try:
        cmd = user_input
        risky_step()
    except Exception:
        cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)

def safe_try_both(user_input):
    try:
        cmd = shlex.quote(user_input)
        risky_step()
    except Exception:
        cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)
""",
        encoding="utf-8",
    )
    (app_dir / "match_branch_taint.py").write_text(
        """import shlex
import subprocess

def unsafe_match(user_input, mode):
    match mode:
        case "legacy":
            cmd = user_input
        case _:
            cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)

def safe_match(user_input, mode):
    match mode:
        case "legacy":
            cmd = shlex.quote(user_input)
        case _:
            cmd = shlex.quote(user_input)
    subprocess.run(f"echo {cmd}", shell=True)
""",
        encoding="utf-8",
    )

    findings = audit_ai_infra(tmp_path)
    taint_hits = [f for f in findings if f["rule_id"] == "AI-INFRA-TAINT-005"]
    if_hits = [f for f in taint_hits if f["file_path"] == "src/if_branch_taint.py"]
    assert [f["line"] for f in if_hits] == [9, 24]
    match_hits = [f for f in taint_hits if f["file_path"] == "src/match_branch_taint.py"]
    assert [f["line"] for f in match_hits] == [10]


def test_ai_infra_guard_loop_fixed_point_and_try_pre_tainted_join(tmp_path: Path) -> None:
    app_dir = tmp_path / "src"
    app_dir.mkdir()
    (app_dir / "loop_and_try_taint.py").write_text(
        """import httpx
import shlex
import subprocess

def poll_loop_sink(user_input):
    url = "https://safe.example.com"
    while httpx.get(url).status_code == 200:
        url = user_input

def second_iter_for_sink(user_input, items):
    cmd = "echo ok"
    for _ in items:
        subprocess.run(cmd, shell=True)
        cmd = user_input

def multihop_loop_carried(user_input, items):
    a = "safe"
    b = "safe"
    for _ in items:
        b = a
        a = user_input
    subprocess.run(b, shell=True)

def safe_try_pre_tainted(user_input):
    cmd = user_input
    try:
        cmd = shlex.quote(user_input)
        risky_step()
    except Exception:
        cmd = shlex.quote(user_input)
    subprocess.run(cmd, shell=True)

def unsafe_finally_uncaught(user_input):
    cmd = user_input
    try:
        risky_step()
        cmd = shlex.quote(user_input)
    except ValueError:
        cmd = shlex.quote(user_input)
    finally:
        subprocess.run(cmd, shell=True)

def safe_try_finally_cleanup(user_input):
    cmd = user_input
    try:
        cmd = shlex.quote(user_input)
        risky_step()
    except Exception:
        cmd = shlex.quote(user_input)
    finally:
        cleanup()
    subprocess.run(cmd, shell=True)
""",
        encoding="utf-8",
    )

    findings = audit_ai_infra(tmp_path)
    taint_hits = [
        f
        for f in findings
        if f["rule_id"] == "AI-INFRA-TAINT-005" and f["file_path"] == "src/loop_and_try_taint.py"
    ]
    assert [f["line"] for f in taint_hits] == [7, 13, 22, 41]
    assert taint_hits[0]["cwe"] == "CWE-918"
    assert [f["cwe"] for f in taint_hits[1:]] == ["CWE-78", "CWE-78", "CWE-78"]


# ---------------------------------------------------------------------------
# 5. Parity & Invariant Auditor + Production Noise Filter
# ---------------------------------------------------------------------------


def test_parity_auditor_sibling_packages_and_same_file_handlers(tmp_path: Path) -> None:
    express_dir = tmp_path / "packages" / "apps" / "shopify-app-express" / "src"
    remix_dir = tmp_path / "packages" / "apps" / "shopify-app-remix" / "src"
    handlers_dir = tmp_path / "src" / "handlers"
    express_dir.mkdir(parents=True)
    remix_dir.mkdir(parents=True)
    handlers_dir.mkdir(parents=True)

    (express_dir / "render.ts").write_text(
        """export function renderAppBridge(res: any, input: string) {
  res.setHeader("Content-Security-Policy", "frame-ancestors https://admin.shopify.com");
  return escapeHtml(input);
}
""",
        encoding="utf-8",
    )
    (remix_dir / "render.ts").write_text(
        """export function renderAppBridge(res: any, input: string) {
  return escapeHtml(input);
}
""",
        encoding="utf-8",
    )
    (handlers_dir / "inbound.ts").write_text(
        """export function handleButtonAction(ctx: any) {
  if (!ctx.allowFrom.includes(ctx.sender) || !ctx.isDM) {
    return;
  }
  return ctx.ok();
}

export function handleInboundText(ctx: any) {
  return ctx.reply("ack");
}
""",
        encoding="utf-8",
    )

    findings = audit_parity_and_invariants(tmp_path)
    sib = [f for f in findings if f["rule_id"] == "PARITY-SIBLING-GUARD-001"]
    same_file = [f for f in findings if f["rule_id"] == "PARITY-SAME-FILE-HANDLER-002"]

    assert len(sib) == 1
    assert sib[0]["file_path"] == "packages/apps/shopify-app-remix/src/render.ts"
    assert sib[0]["engine"] == "parity_auditor"
    assert sib[0]["deterministic"] is True
    assert sib[0]["confirmed"] is True
    assert sib[0]["non_production_noise"] is False

    assert len(same_file) == 1
    assert same_file[0]["file_path"] == "src/handlers/inbound.ts"
    assert same_file[0]["line"] == 8
    assert same_file[0]["metadata"]["function"] == "handleInboundText"

    # Patching both eliminates all parity findings
    (remix_dir / "render.ts").write_text(
        """export function renderAppBridge(res: any, input: string) {
  res.setHeader("Content-Security-Policy", "frame-ancestors https://admin.shopify.com");
  return escapeHtml(input);
}
""",
        encoding="utf-8",
    )
    (handlers_dir / "inbound.ts").write_text(
        """export function handleButtonAction(ctx: any) {
  if (!ctx.allowFrom.includes(ctx.sender) || !ctx.isDM) {
    return;
  }
  return ctx.ok();
}

export function handleInboundText(ctx: any) {
  if (!ctx.allowFrom.includes(ctx.sender)) {
    return;
  }
  return ctx.reply("ack");
}
""",
        encoding="utf-8",
    )
    assert audit_parity_and_invariants(tmp_path) == []


def test_production_noise_filter_dicts_and_engine_findings() -> None:
    assert is_non_production_noise("tests/test_auth.py") is True
    assert is_non_production_noise("src/__tests__/handler.test.ts") is True
    assert is_non_production_noise("pkg/auth_test.go") is True
    assert is_non_production_noise("examples/demo.ts") is True
    assert is_non_production_noise("fixtures/payload.json") is True
    assert is_non_production_noise("README.md") is True
    assert is_non_production_noise("src/auth/verify.ts") is False

    prod_dict = {"file_path": "src/auth/verify.ts", "rule_id": "PARITY-001", "summary": "real", "metadata": {}}
    noise_dict = {"file_path": "fixtures/sample.py", "rule_id": "TRUFFLEHOG-001", "summary": "fixture", "metadata": {}}
    hygiene_obj = EngineFinding(
        engine="gha_agent",
        title="[hygiene_only] pin version",
        file_path=".github/workflows/ci.yml",
        line=4,
        summary="[hygiene_only] lint hygiene",
        metadata={"hygiene_only": True},
    )
    verified_poc_obj = EngineFinding(
        engine="z3_formal",
        title="Verified bypass",
        file_path="tests/repro_poc.py",
        line=1,
        metadata={"poc_verified": True},
    )

    prod, noise = filter_production_candidates([prod_dict, noise_dict, hygiene_obj, verified_poc_obj])
    assert prod_dict in prod and prod_dict["non_production_noise"] is False
    assert verified_poc_obj in prod and verified_poc_obj.metadata["non_production_noise"] is False
    assert noise_dict in noise and noise_dict["non_production_noise"] is True
    assert hygiene_obj in noise and hygiene_obj.metadata["non_production_noise"] is True


def test_parity_auditor_comment_guards_and_rule_id_noise(tmp_path: Path) -> None:
    pkg_a = tmp_path / "packages" / "sdk-a" / "src"
    pkg_b = tmp_path / "packages" / "sdk-b" / "src"
    handlers_dir = tmp_path / "src" / "handlers"
    pkg_a.mkdir(parents=True)
    pkg_b.mkdir(parents=True)
    handlers_dir.mkdir(parents=True)

    # URL string literal with // must NOT hide trailing verifySignature guard
    (pkg_a / "verify.ts").write_text(
        """export function verifyWebhook(req: any) {
  const origin = "https://admin.shopify.com";
  return verifySignature(req, origin);
}
""",
        encoding="utf-8",
    )
    # Comment-only guard must NOT satisfy guard coverage
    (pkg_b / "verify.ts").write_text(
        """export function verifyWebhook(req: any) {
  // TODO: sanitizeInput and verifySignature later
  return req.body;
}
""",
        encoding="utf-8",
    )
    (handlers_dir / "py_handlers.py").write_text(
        """def handle_safe(req):
    verifySignature(req)
    return True

def handle_unsafe(req):
    # TODO: verifySignature
    return False
""",
        encoding="utf-8",
    )

    findings = audit_parity_and_invariants(tmp_path)
    sib = [f for f in findings if f["rule_id"] == "PARITY-SIBLING-GUARD-001"]
    same_file = [f for f in findings if f["rule_id"] == "PARITY-SAME-FILE-HANDLER-002"]

    assert len(sib) == 1
    assert sib[0]["file_path"] == "packages/sdk-b/src/verify.ts"
    assert len(same_file) == 1
    assert same_file[0]["file_path"] == "src/handlers/py_handlers.py"
    assert same_file[0]["metadata"]["function"] == "handle_unsafe"

    assert is_non_production_noise("src/ci.yml", rule_id="GHA-LINT-001") is True
    assert is_non_production_noise("src/ci.yml", rule_id="CI-HYGIENE-002") is True
    assert is_non_production_noise("src/ci.yml", rule_id="FOO-LINT") is True
    assert is_non_production_noise("src/ci.yml", rule_id="FOO-HYGIENE") is True
    assert is_non_production_noise("src/auth.py", rule_id="PARITY-SIBLING-GUARD-001") is False


# ---------------------------------------------------------------------------
# 6. OllamaConcurrencyGuard & gha_llm_verifier.py OOM Downshift + Circuit Breaker
# ---------------------------------------------------------------------------


def test_ollama_concurrency_guard_cross_process_spawn_and_reentrancy(tmp_path: Path) -> None:
    lock_file = tmp_path / "ollama_slot.lock"
    out_busy = tmp_path / "child_busy.txt"
    out_free = tmp_path / "child_free.txt"

    guard = OllamaConcurrencyGuard(lock_path=lock_file, acquire_timeout_sec=2.0)
    ctx = mp.get_context("spawn")

    # Reentrant same-thread acquisition must not self-deadlock
    with guard.acquire() as outer_ok:
        assert outer_ok is True
        with guard.acquire() as inner_ok:
            assert inner_ok is True

        # While parent holds OS lock, spawned child must fail to acquire within 0.15s
        p_busy = ctx.Process(
            target=_child_try_acquire_ollama_lock,
            args=(str(lock_file), str(out_busy), 0.15),
        )
        p_busy.start()
        try:
            p_busy.join(timeout=10.0)
        finally:
            if p_busy.is_alive():
                p_busy.terminate()
                p_busy.join(timeout=2.0)
        assert p_busy.exitcode == 0
        assert out_busy.read_text(encoding="utf-8") == "0"

    # Once parent releases lock, spawned child acquires cleanly
    p_free = ctx.Process(
        target=_child_try_acquire_ollama_lock,
        args=(str(lock_file), str(out_free), 2.0),
    )
    p_free.start()
    try:
        p_free.join(timeout=10.0)
    finally:
        if p_free.is_alive():
            p_free.terminate()
            p_free.join(timeout=2.0)
    assert p_free.exitcode == 0
    assert out_free.read_text(encoding="utf-8") == "1"


def test_gha_llm_verifier_oom_downshift_and_circuit_breaker(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )

    guard_probe = OllamaConcurrencyGuard(lock_path=tmp_path / "probe.lock")
    assert guard_probe.downshift_candidates(
        "qwen2.5:14b",
        ["gemma2:27b", "llama3:8b", "qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b", "nomic-embed-text:latest"],
    ) == ["qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b"]
    assert guard_probe.is_oom_500(500, "CUDA out of memory") is True
    assert guard_probe.is_oom_500(500, "invalid json") is False
    assert guard_probe.is_oom_500(400, "CUDA out of memory") is False

    chat_models_called: list[str] = []
    tags_calls: list[int] = []
    server_mode = {"fail_all": False}

    class _LocalOllamaHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/tags":
                tags_calls.append(1)
                payload = json.dumps(
                    {
                        "models": [
                            {"name": "qwen2.5:14b"},
                            {"name": "llama3:8b"},
                            {"name": "qwen2.5:7b"},
                            {"name": "qwen2.5:3b"},
                            {"name": "qwen2.5:1.5b"},
                        ]
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            model = str(body.get("model") or "")
            chat_models_called.append(model)
            if server_mode["fail_all"] or model in ("qwen2.5:14b", "qwen2.5:7b"):
                err = b'{"error":"CUDA out of memory: failed to allocate VRAM"}'
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err)))
                self.end_headers()
                self.wfile.write(err)
                return

            ok_body = json.dumps(
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "verdicts": [
                                    {
                                        "gha_class": "pwn_request",
                                        "file_path": ".github/workflows/ci.yml",
                                        "line": 1,
                                        "confirmed": True,
                                        "confidence": 0.85,
                                        "severity": "MEDIUM",
                                        "recommended_fix": "Pin action",
                                    }
                                ],
                                "attack_chains": [],
                            }
                        )
                    }
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(ok_body)))
            self.end_headers()
            self.wfile.write(ok_body)

        def log_message(self, format, *args):
            return

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LocalOllamaHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()
    try:
        url = f"http://127.0.0.1:{port}"
        no_env_local = tmp_path / "missing.env.local"

        # 1. OOM 500 downshift: 14b -> 7b -> 3b (never retries 14b, skips sideways 8b)
        downshift_guard = OllamaConcurrencyGuard(
            lock_path=tmp_path / "ds.lock",
            failure_threshold=4,
            cooldown_sec=30.0,
        )
        findings, tele = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="qwen2.5:14b",
            ollama_endpoint=url,
            env_local_path=no_env_local,
            guard=downshift_guard,
        )
        assert tele["status"] == "completed"
        assert tele["model"] == "qwen2.5:3b"
        assert tele["downshifted_from"] == ["qwen2.5:14b", "qwen2.5:7b"]
        assert chat_models_called == ["qwen2.5:14b", "qwen2.5:7b", "qwen2.5:3b"]
        assert len(findings) >= 1

        # 2. Circuit breaker trips at threshold=2 and fast-skips with zero HTTP calls
        chat_models_called.clear()
        tags_calls.clear()
        server_mode["fail_all"] = True
        cb_guard = OllamaConcurrencyGuard(
            lock_path=tmp_path / "cb.lock",
            failure_threshold=2,
            cooldown_sec=1.2,
        )
        _, tele_trip = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="qwen2.5:14b",
            ollama_endpoint=url,
            env_local_path=no_env_local,
            guard=cb_guard,
        )
        assert tele_trip["status"] == "skipped_circuit_open"
        assert cb_guard.is_circuit_open() is True

        calls_before_skip = (len(tags_calls), len(chat_models_called))
        skipped_findings, tele_skip = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="qwen2.5:14b",
            ollama_endpoint=url,
            env_local_path=no_env_local,
            guard=cb_guard,
        )
        assert skipped_findings == []
        assert tele_skip["status"] == "skipped_circuit_open"
        assert (len(tags_calls), len(chat_models_called)) == calls_before_skip

        # 3. After cooldown expires and server recovers, half-open call succeeds
        time.sleep(1.3)
        server_mode["fail_all"] = False
        rec_findings, tele_rec = verify_gha_findings_with_llm(
            tmp_path,
            [],
            model="qwen2.5:3b",
            ollama_endpoint=url,
            env_local_path=no_env_local,
            guard=cb_guard,
        )
        assert tele_rec["status"] == "completed"
        assert tele_rec["model"] == "qwen2.5:3b"
        assert len(rec_findings) >= 1
    finally:
        srv.shutdown()
        srv.server_close()
