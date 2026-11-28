"""
Independent Ground-Truth Patched-vs.-Unpatched CVE/CWE Dataset &
Adversarial Valid-File + False-Claim Corpus (`benchmarks/datasets/cve_patched_pairs.py`).

Modeled on public OWASP Benchmark, NIST SARD/Juliet CWE slices, and real-world
CVE vulnerable-commit vs. patched-commit pairs where the patched commit is the
exact ground-truth negative case on the SAME file path and function.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class PatchedPairCase:
    """Single vulnerable-commit vs. patched-commit ground-truth benchmark pair."""

    case_id: str
    reference: str          # Public benchmark / CVE-class lineage
    cwe: str
    title: str
    filename: str
    target_line: int        # 1-based sink line in BOTH vulnerable and patched files (or patched_line if shifted)
    patched_line: int
    vulnerable_code: str
    patched_code: str
    eval_engine: str = "claim_verifier"  # "claim_verifier" | "verification_inversion_z3"


@dataclass(frozen=True)
class AdversarialFalseClaimCase:
    """Real safe code file paired with a plausible false vulnerability claim at a real line."""

    case_id: str
    cwe: str
    title: str
    filename: str
    cited_line: int
    safe_code: str
    mock_llm_models: List[str] = field(
        default_factory=lambda: ["gemma4:12b", "qwen2.5:7b", "llama3.1:8b"]
    )
    expected_allowed_states: tuple = ("REFUTED", "UNRESOLVED")


CVE_PATCHED_PAIRS: List[PatchedPairCase] = [
    PatchedPairCase(
        case_id="PAIR-01-CWE22-PATH-TRAVERSAL",
        reference="OWASP Benchmark / CVE-2024-class Path Traversal (Flask send_file)",
        cwe="CWE-22",
        title="Arbitrary file read via uncanonicalized user filename",
        filename="file_service.py",
        target_line=6,
        patched_line=9,
        vulnerable_code=(
            "import os\n"
            "from pathlib import Path\n"
            "\n"
            "def serve_report(base_dir: Path, filename: str) -> bytes:\n"
            "    target = os.path.join(str(base_dir), filename)\n"
            "    return open(target, 'rb').read()\n"
        ),
        patched_code=(
            "import os\n"
            "from pathlib import Path\n"
            "\n"
            "def serve_report(base_dir: Path, filename: str) -> bytes:\n"
            "    root = base_dir.resolve()\n"
            "    target = (root / filename).resolve()\n"
            "    if not target.is_relative_to(root):\n"
            "        raise PermissionError('Path traversal blocked')\n"
            "    return open(target, 'rb').read()\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-02-CWE22-COMMONPATH",
        reference="NIST Juliet CWE-22 / commonpath confinement fix",
        cwe="CWE-22",
        title="Directory traversal in archive asset reader",
        filename="asset_loader.py",
        target_line=5,
        patched_line=8,
        vulnerable_code=(
            "import os\n"
            "\n"
            "def load_asset(root_dir: str, user_path: str) -> str:\n"
            "    full = os.path.join(root_dir, user_path)\n"
            "    return open(full, 'r', encoding='utf-8').read()\n"
        ),
        patched_code=(
            "import os\n"
            "\n"
            "def load_asset(root_dir: str, user_path: str) -> str:\n"
            "    real_root = os.path.realpath(root_dir)\n"
            "    full = os.path.realpath(os.path.join(real_root, user_path))\n"
            "    if os.path.commonpath([real_root, full]) != real_root:\n"
            "        raise ValueError('Escapes asset root')\n"
            "    return open(full, 'r', encoding='utf-8').read()\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-03-CWE78-SUBPROCESS-SHELL",
        reference="OWASP Benchmark / CWE-78 subprocess shell=True -> argv shell=False",
        cwe="CWE-78",
        title="OS command injection via shell=True interpolation",
        filename="diagnostics.py",
        target_line=4,
        patched_line=4,
        vulnerable_code=(
            "import subprocess\n"
            "\n"
            "def ping_host(user_input: str) -> str:\n"
            "    return subprocess.check_output(f'ping -c 1 {user_input}', shell=True, text=True)\n"
        ),
        patched_code=(
            "import subprocess\n"
            "\n"
            "def ping_host(user_input: str) -> str:\n"
            "    return subprocess.check_output(['ping', '-c', '1', user_input], shell=False, text=True)\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-04-CWE78-OS-SYSTEM",
        reference="NIST Juliet CWE-78 / os.system -> shlex.quote",
        cwe="CWE-78",
        title="Shell command injection via os.system",
        filename="exporter.py",
        target_line=4,
        patched_line=6,
        vulnerable_code=(
            "import os\n"
            "\n"
            "def export_archive(user_cmd: str) -> int:\n"
            "    return os.system('tar -cf out.tar ' + user_cmd)\n"
        ),
        patched_code=(
            "import os\n"
            "import shlex\n"
            "\n"
            "def export_archive(user_cmd: str) -> int:\n"
            "    safe_arg = shlex.quote(user_cmd)\n"
            "    return os.system('tar -cf out.tar ' + safe_arg)\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-05-CWE89-SQLI-FSTRING",
        reference="OWASP Benchmark / CWE-89 SQLi f-string -> parameterized execute",
        cwe="CWE-89",
        title="SQL injection via interpolated SELECT query",
        filename="user_repo.py",
        target_line=2,
        patched_line=2,
        vulnerable_code=(
            "def fetch_account(cursor, user_id: str):\n"
            "    return cursor.execute(f'SELECT id, email FROM accounts WHERE id = {user_id}').fetchone()\n"
        ),
        patched_code=(
            "def fetch_account(cursor, user_id: str):\n"
            "    return cursor.execute('SELECT id, email FROM accounts WHERE id = ?', (user_id,)).fetchone()\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-06-CWE89-SQLI-FORMAT",
        reference="NIST Juliet CWE-89 / str.format SQL -> bound tuple query",
        cwe="CWE-89",
        title="SQL injection via .format() in ORDER lookup",
        filename="order_repo.py",
        target_line=3,
        patched_line=2,
        vulnerable_code=(
            "def find_orders(cursor, user_name: str):\n"
            "    q = 'SELECT * FROM orders WHERE owner = \"{}\"'.format(user_name)\n"
            "    return cursor.execute('SELECT * FROM orders WHERE owner = ' + user_name).fetchall()\n"
        ),
        patched_code=(
            "def find_orders(cursor, user_name: str):\n"
            "    return cursor.execute('SELECT * FROM orders WHERE owner = %s', (user_name,)).fetchall()\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-07-CWE502-PICKLE-JSON",
        reference="CVE-2023-class Unsafe Deserialization (pickle.loads -> json.loads)",
        cwe="CWE-502",
        title="Arbitrary code execution via pickle.loads on request payload",
        filename="session_codec.py",
        target_line=4,
        patched_line=4,
        vulnerable_code=(
            "import pickle\n"
            "\n"
            "def decode_session(payload: bytes):\n"
            "    return pickle.loads(payload)\n"
        ),
        patched_code=(
            "import json\n"
            "\n"
            "def decode_session(payload: bytes):\n"
            "    return json.loads(payload.decode('utf-8'))\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-08-CWE502-YAML-LOAD",
        reference="PyYAML CVE-2020-14343 (yaml.load -> yaml.safe_load)",
        cwe="CWE-502",
        title="Unsafe YAML deserialization without SafeLoader",
        filename="config_loader.py",
        target_line=4,
        patched_line=4,
        vulnerable_code=(
            "import yaml\n"
            "\n"
            "def parse_manifest(raw_input: str):\n"
            "    return yaml.load(raw_input, Loader=yaml.UnsafeLoader)\n"
        ),
        patched_code=(
            "import yaml\n"
            "\n"
            "def parse_manifest(raw_input: str):\n"
            "    return yaml.safe_load(raw_input)\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-09-CWE79-RAW-HTML",
        reference="OWASP Benchmark / CWE-79 Reflected XSS -> html.escape",
        cwe="CWE-79",
        title="Reflected XSS via unescaped HTML interpolation",
        filename="profile_view.py",
        target_line=2,
        patched_line=4,
        vulnerable_code=(
            "def render_greeting(user_name: str) -> str:\n"
            "    return f'<div class=\"banner\">Hello {user_name}</div>'\n"
        ),
        patched_code=(
            "import html\n"
            "\n"
            "def render_greeting(user_name: str) -> str:\n"
            "    return f'<div class=\"banner\">Hello {html.escape(user_name)}</div>'\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-10-CWE94-EVAL-LITERAL",
        reference="NIST Juliet CWE-94 / eval() -> ast.literal_eval()",
        cwe="CWE-94",
        title="Arbitrary Python code injection via eval()",
        filename="expr_parser.py",
        target_line=2,
        patched_line=4,
        vulnerable_code=(
            "def parse_filter(expr: str):\n"
            "    return eval(expr)\n"
        ),
        patched_code=(
            "import ast\n"
            "\n"
            "def parse_filter(expr: str):\n"
            "    return ast.literal_eval(expr)\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-11-CWE918-SSRF",
        reference="CVE-2024-class SSRF (requests.get -> IP/CIDR metadata guard)",
        cwe="CWE-918",
        title="SSRF via unvalidated webhook URL",
        filename="webhook_client.py",
        target_line=4,
        patched_line=10,
        vulnerable_code=(
            "import requests\n"
            "\n"
            "def fetch_webhook(user_url: str):\n"
            "    return requests.get(user_url, timeout=5).text\n"
        ),
        patched_code=(
            "import ipaddress\n"
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "\n"
            "ALLOWED_HOSTS = {'hooks.example.org'}\n"
            "\n"
            "def fetch_webhook(user_url: str):\n"
            "    host = urlparse(user_url).hostname or ''\n"
            "    if host not in ALLOWED_HOSTS:\n"
            "        raise PermissionError('SSRF host blocked')\n"
            "    return requests.get(user_url, timeout=5).text\n"
        ),
    ),
    PatchedPairCase(
        case_id="PAIR-12-CWE1284-Z3-BOUNDS",
        reference="HTTP Framing Header-Length Arithmetic Bounds (Z3 SMT Verifier)",
        cwe="CWE-1284",
        title="Unclamped Content-Length allocation allows negative/OOM values",
        filename="frame_alloc.py",
        target_line=2,
        patched_line=2,
        vulnerable_code=(
            "def parse_frame(raw_hdr: str) -> bytes:\n"
            "    content_length = int(raw_hdr)\n"
            "    return b'0' * content_length\n"
        ),
        patched_code=(
            "MAX_FRAME_LEN = 65536\n"
            "def parse_frame(raw_hdr: str) -> bytes:\n"
            "    content_length = int(raw_hdr)\n"
            "    if not (0 <= content_length <= MAX_FRAME_LEN):\n"
            "        raise ValueError('Out of bounds content_length')\n"
            "    return b'0' * content_length\n"
        ),
        eval_engine="verification_inversion_z3",
    ),
    PatchedPairCase(
        case_id="PAIR-13-CWE863-Z3-RBAC",
        reference="AWS Cedar / RBAC Comparator Contract (Z3 SMT Verifier)",
        cwe="CWE-863",
        title="Inverted RBAC role predicate grants access to non-admins",
        filename="rbac_gate.py",
        target_line=2,
        patched_line=2,
        vulnerable_code=(
            "def authorize_admin(user_role: str) -> bool:\n"
            "    if user_role != 'admin':\n"
            "        return True\n"
            "    return False\n"
        ),
        patched_code=(
            "def authorize_admin(user_role: str, forbid: bool = False) -> bool:\n"
            "    if forbid:\n"
            "        return False\n"
            "    return user_role == 'admin'\n"
        ),
        eval_engine="verification_inversion_z3",
    ),
    PatchedPairCase(
        case_id="PAIR-14-CWE345-Z3-JWT",
        reference="JWT/OIDC Comparator Contract (missing aud/iss -> Z3 SAT witness)",
        cwe="CWE-345",
        title="JWT verification omits audience and issuer binding",
        filename="jwt_auth.py",
        target_line=4,
        patched_line=4,
        vulnerable_code=(
            "import jwt\n"
            "\n"
            "def verify_bearer(token: str, key: str):\n"
            "    return jwt.decode(token, key, algorithms=['RS256'])\n"
        ),
        patched_code=(
            "import jwt\n"
            "\n"
            "def verify_bearer(token: str, key: str):\n"
            "    return jwt.decode(token, key, algorithms=['RS256'], audience='api.internal', issuer='https://idp.internal')\n"
        ),
        eval_engine="verification_inversion_z3",
    ),
]


ADVERSARIAL_FALSE_CLAIM_CASES: List[AdversarialFalseClaimCase] = [
    AdversarialFalseClaimCase(
        case_id="ADV-01-SAFE-PATH-RESOLVE",
        cwe="CWE-22",
        title="False Path Traversal claim on resolve()+is_relative_to() guarded handler",
        filename="safe_files.py",
        cited_line=8,
        safe_code=(
            "from pathlib import Path\n"
            "\n"
            "def read_doc(base_dir: Path, doc_name: str) -> str:\n"
            "    root = base_dir.resolve()\n"
            "    cand = (root / doc_name).resolve()\n"
            "    if not cand.is_relative_to(root):\n"
            "        raise PermissionError('blocked')\n"
            "    return open(cand, 'r', encoding='utf-8').read()\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-02-SAFE-SUBPROCESS-ARGV",
        cwe="CWE-78",
        title="False Command Injection claim on shell=False static argv list",
        filename="safe_cli.py",
        cited_line=4,
        safe_code=(
            "import subprocess\n"
            "\n"
            "def check_git_status(repo_dir: str) -> str:\n"
            "    return subprocess.run(['git', 'status', '--short'], cwd=repo_dir, shell=False, capture_output=True, text=True).stdout\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-03-SAFE-SQL-PARAM",
        cwe="CWE-89",
        title="False SQL Injection claim on parameterized sqlite3 execute",
        filename="safe_db.py",
        cited_line=3,
        safe_code=(
            "def lookup_user(conn, email: str):\n"
            "    cur = conn.cursor()\n"
            "    return cur.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-04-SAFE-YAML-SAFELOAD",
        cwe="CWE-502",
        title="False Unsafe Deserialization claim on yaml.safe_load",
        filename="safe_yaml.py",
        cited_line=4,
        safe_code=(
            "import yaml\n"
            "\n"
            "def load_policy(raw_yaml: str) -> dict:\n"
            "    return yaml.safe_load(raw_yaml) or {}\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-05-SAFE-SECRET-REGEX",
        cwe="CWE-798",
        title="False Hardcoded Secret claim on regex detector pattern",
        filename="secret_scanner.py",
        cited_line=4,
        safe_code=(
            "import re\n"
            "\n"
            "AWS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')\n"
            "API_KEY = os.getenv('RFCHUNT_API_KEY', 'YOUR_KEY_PLACEHOLDER')\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-06-SAFE-SSRF-ALLOWLIST",
        cwe="CWE-918",
        title="False SSRF claim on allowlist-enforced outbound fetch",
        filename="safe_fetch.py",
        cited_line=8,
        safe_code=(
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "ALLOWED_HOSTS = {'api.trusted.internal'}\n"
            "\n"
            "def fetch_status(url: str) -> int:\n"
            "    if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
            "        raise ValueError('Blocked host')\n"
            "    return requests.get(url, timeout=3).status_code\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-07-SAFE-COMMENT-LINE",
        cwe="CWE-78",
        title="False Command Injection claim pointing to a real comment line",
        filename="commented.py",
        cited_line=2,
        safe_code=(
            "def noop() -> int:\n"
            "    # Never call os.system(user_input) here!\n"
            "    return 0\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-08-SAFE-LITERAL-EVAL",
        cwe="CWE-94",
        title="False Code Injection claim on ast.literal_eval",
        filename="safe_eval.py",
        cited_line=4,
        safe_code=(
            "import ast\n"
            "\n"
            "def parse_tuple(raw: str):\n"
            "    return ast.literal_eval(raw)\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-09-AMBIGUOUS-NO-SINK-UNANIMOUS-LLM",
        cwe="CWE-999",
        title="Plausible-sounding logic flaw backed ONLY by 3/3 unanimous LLM agreement",
        filename="pure_helper.py",
        cited_line=3,
        safe_code=(
            "def normalize_header_name(name: str) -> str:\n"
            "    cleaned = name.strip().lower()\n"
            "    return cleaned\n"
        ),
    ),
    AdversarialFalseClaimCase(
        case_id="ADV-10-SAFE-CALLEE-SANITIZER",
        cwe="CWE-22",
        title="False Path Traversal claim where helper callee enforces resolve()+is_relative_to()",
        filename="delegated_files.py",
        cited_line=11,
        safe_code=(
            "from pathlib import Path\n"
            "\n"
            "def _safe_join(root: Path, rel: str) -> Path:\n"
            "    r = root.resolve()\n"
            "    cand = (r / rel).resolve()\n"
            "    if not cand.is_relative_to(r):\n"
            "        raise PermissionError('blocked')\n"
            "    return cand\n"
            "\n"
            "def read_report(root: Path, filename: str) -> bytes:\n"
            "    target = _safe_join(root, filename)\n"
            "    return open(target, 'rb').read()\n"
        ),
    ),
]
