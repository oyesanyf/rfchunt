"""
Hybrid Deterministic + Per-Package Git-History SBOM Diff Guard.

Provides two complementary supply-chain anomaly detection layers without external
network calls or target repository mutation:
  - Layer 1 (Deterministic High-Precision Diff Rules): Always active on single
    snapshots or any baseline-to-candidate diff. Detects unpinned git+/remote
    dependencies, registry/source domain swaps, newly introduced install/build
    hooks (npm preinstall/install/postinstall, Cargo build.rs), permissive OSI
    license drops, and typosquatting candidates (Levenshtein distance 1-2).
  - Layer 2 (Per-Package Latent Drift Scorer): Collapse-free EMA-JEPA with
    VICReg variance/covariance regularization and empirically calibrated p99
    conformal threshold over per-component transition vectors. Strictly gated
    behind a real git-history cold-start threshold (>= min_lockfile_commits,
    default 10) and immune to lockfile-size dilution (e.g., 1 poisoned package
    inside a 500-dependency lockfile).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import subprocess
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union
from urllib.parse import parse_qs, unquote, urlparse

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - fallback for older Python runtimes
    tomllib = None  # type: ignore[assignment]

try:
    import numpy as np

    _HAS_NUMPY = True
except ImportError:  # pragma: no cover - pure Python fallback supported
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False


_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

_READ_ONLY_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "rev-parse",
        "log",
        "show",
        "ls-tree",
        "cat-file",
    }
)

_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "target",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
        "out",
        "vendor",
        ".tox",
        ".mypy_cache",
        ".idea",
        ".vs",
    }
)

_GIT_MANIFEST_PATHSPECS: Tuple[str, ...] = (
    ":(glob)**/package-lock.json",
    ":(glob)**/package.json",
    ":(glob)**/Cargo.lock",
    ":(glob)**/Cargo.toml",
    ":(glob)**/build.rs",
    ":(glob)**/requirements*.txt",
    ":(glob)**/constraints*.txt",
    ":(glob)**/*.cdx.json",
    ":(glob)**/bom.json",
    ":(glob)**/sbom.json",
)

_NPM_INSTALL_SCRIPT_KEYS: frozenset[str] = frozenset(
    {"preinstall", "install", "postinstall"}
)

_SUSPICIOUS_HOOK_COMMAND_RX = re.compile(
    r"\b(?:curl|wget|powershell|pwsh|cmd\.exe|bash\s+-c|sh\s+-c|node\s+-e|python[3]?\s+-c|eval|base64|nc|ncat|certutil)\b"
    r"|https?://",
    re.IGNORECASE,
)

_NUMBERED_SIBLING_RX = re.compile(r"^(.+[-_])\d+$")
_SEMVER_RX = re.compile(r"(?P<maj>\d+)(?:\.(?P<min>\d+))?(?:\.(?P<pat>\d+))?(?P<pre>-[0-9A-Za-z.-]+)?")
_REQ_NAME_RX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(.*)$")
_PEP508_DIRECT_RX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*@\s*(\S+)$")
_TOML_PKG_NAME_RX = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.MULTILINE)
_TOML_PKG_LICENSE_RX = re.compile(r'^\s*license\s*=\s*"([^"]+)"', re.MULTILINE)
_TOML_BUILD_RX = re.compile(r'^\s*build\s*=\s*(?:true|"([^"]+)")', re.MULTILINE)
_SHA_HEX_RX = re.compile(r"^[0-9a-fA-F]{7,40}$")

_OFFICIAL_REGISTRIES: Dict[str, frozenset[str]] = {
    "npm": frozenset({"registry.npmjs.org", "registry.yarnpkg.com"}),
    "cargo": frozenset({"crates.io"}),
    "pypi": frozenset({"pypi.org"}),
}

_PERMISSIVE_OSI_LICENSES: frozenset[str] = frozenset(
    {
        "mit",
        "mit-0",
        "apache-2.0",
        "bsd-2-clause",
        "bsd-3-clause",
        "bsd-2-clause-patent",
        "bsd",
        "isc",
        "0bsd",
        "unlicense",
        "cc0-1.0",
        "zlib",
        "bsl-1.0",
        "mpl-2.0",
        "artistic-2.0",
        "wtfpl",
        "blueoak-1.0.0",
        "ncsa",
        "postgresql",
        "python-2.0",
        "psf-2.0",
        "json",
    }
)

_UNLICENSED_TOKENS: frozenset[str] = frozenset(
    {
        "unlicensed",
        "none",
        "unknown",
        "noassertion",
        "proprietary",
        "commercial",
        "all rights reserved",
        "n/a",
        "null",
    }
)

_UNPINNED_VERSION_TOKENS: frozenset[str] = frozenset(
    {"*", "latest", "next", "canary", "nightly", "main", "master", "head"}
)

_VCS_PREFIXES: Tuple[str, ...] = (
    "git+",
    "git://",
    "ssh://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "hg+",
    "svn+",
    "bzr+",
    "file:",
    "link:",
)

_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_SEVERITY_CVSS: Dict[str, float] = {
    "CRITICAL": 9.1,
    "HIGH": 7.8,
    "MEDIUM": 5.3,
    "LOW": 3.1,
    "INFO": 0.0,
}

_RULE_REMEDIATION: Dict[str, str] = {
    "SBOM_UNPINNED_GIT_DEP": (
        "Pin the dependency to an immutable release version on an approved package "
        "registry with verified integrity checksums instead of a git+ or unpinned remote URL."
    ),
    "SBOM_REGISTRY_SOURCE_SWAP": (
        "Audit the lockfile diff to confirm whether the registry/source domain change "
        "was authorized; restore the canonical package registry and verify package checksums."
    ),
    "SBOM_NEW_INSTALL_BUILD_HOOK": (
        "Inspect the newly introduced preinstall/install/postinstall script or build.rs "
        "for unauthorized code execution, network egress, or credential harvesting."
    ),
    "SBOM_LICENSE_DROP": (
        "Verify why the package's permissive OSI license disappeared or became unlicensed; "
        "review upstream repository ownership and recent commits for takeover indicators."
    ),
    "SBOM_TYPOSQUAT_SUSPECT": (
        "Confirm the package spelling and maintainer identity against the official ecosystem "
        "registry; replace with the intended canonical package if mistyped."
    ),
    "SBOM_PER_PACKAGE_LATENT_DRIFT": (
        "Review this package's version jump, dependency fan-out delta, source origin, and "
        "lifecycle capabilities against historical repository update patterns."
    ),
}

DEFAULT_POPULAR_PACKAGES: Dict[str, frozenset[str]] = {
    "npm": frozenset(
        {
            "lodash",
            "express",
            "react",
            "react-dom",
            "preact",
            "axios",
            "chalk",
            "commander",
            "debug",
            "dotenv",
            "eslint",
            "prettier",
            "typescript",
            "webpack",
            "vite",
            "next",
            "vue",
            "angular",
            "moment",
            "dayjs",
            "semver",
            "uuid",
            "yargs",
            "minimist",
            "glob",
            "rimraf",
            "mkdirp",
            "cross-env",
            "inquirer",
            "ora",
            "colors",
            "request",
            "node-fetch",
            "undici",
            "got",
            "superagent",
            "ws",
            "socket.io",
            "jsonwebtoken",
            "bcrypt",
            "bcryptjs",
            "crypto-js",
            "zod",
            "joi",
            "yup",
            "ajv",
            "cheerio",
            "puppeteer",
            "playwright",
            "jest",
            "mocha",
            "vitest",
            "sinon",
            "tslib",
            "rxjs",
            "ramda",
            "underscore",
            "bluebird",
            "async",
            "body-parser",
            "cors",
            "helmet",
            "morgan",
            "multer",
            "passport",
            "mongoose",
            "sequelize",
            "prisma",
            "pg",
            "mysql2",
            "redis",
            "ioredis",
            "kafkajs",
            "graphql",
            "apollo-server",
            "tailwindcss",
            "postcss",
            "autoprefixer",
            "styled-components",
            "lucide-react",
            "date-fns",
            "immer",
            "zustand",
            "redux",
            "esbuild",
            "rollup",
            "babel-core",
            "core-js",
            "regenerator-runtime",
            "js-yaml",
            "marked",
            "dompurify",
            "sanitize-html",
            "sharp",
            "tar",
            "jszip",
            "adm-zip",
            "form-data",
            "qs",
            "mime",
            "mime-types",
            "chokidar",
            "fs-extra",
            "execa",
            "which",
            "nanoid",
            "pino",
            "winston",
        }
    ),
    "cargo": frozenset(
        {
            "serde",
            "serde_json",
            "serde_derive",
            "tokio",
            "tokio-util",
            "reqwest",
            "hyper",
            "axum",
            "actix-web",
            "rocket",
            "warp",
            "clap",
            "anyhow",
            "thiserror",
            "tracing",
            "tracing-subscriber",
            "log",
            "env_logger",
            "rand",
            "rand_core",
            "regex",
            "chrono",
            "time",
            "uuid",
            "bytes",
            "futures",
            "futures-util",
            "async-trait",
            "pin-project",
            "syn",
            "quote",
            "proc-macro2",
            "libc",
            "bitflags",
            "once_cell",
            "lazy_static",
            "parking_lot",
            "crossbeam",
            "rayon",
            "dashmap",
            "indexmap",
            "itertools",
            "smallvec",
            "hashbrown",
            "ahash",
            "sha2",
            "blake3",
            "ring",
            "rustls",
            "openssl",
            "native-tls",
            "ed25519-dalek",
            "x25519-dalek",
            "aes-gcm",
            "chacha20poly1305",
            "argon2",
            "hmac",
            "base64",
            "hex",
            "url",
            "http",
            "tower",
            "tonic",
            "prost",
            "sqlx",
            "diesel",
            "rusqlite",
            "toml",
            "yaml-rust",
            "serde_yaml",
            "flate2",
            "zstd",
            "tar",
            "zip",
            "tempfile",
            "walkdir",
            "glob",
            "notify",
            "nix",
            "winapi",
            "windows-sys",
            "cc",
            "bindgen",
            "pkg-config",
            "wasm-bindgen",
            "pyo3",
            "criterion",
            "proptest",
        }
    ),
    "pypi": frozenset(
        {
            "requests",
            "urllib3",
            "certifi",
            "charset-normalizer",
            "idna",
            "httpx",
            "aiohttp",
            "flask",
            "django",
            "fastapi",
            "uvicorn",
            "starlette",
            "pydantic",
            "sqlalchemy",
            "alembic",
            "psycopg2",
            "pymysql",
            "redis",
            "celery",
            "numpy",
            "scipy",
            "pandas",
            "matplotlib",
            "scikit-learn",
            "torch",
            "tensorflow",
            "transformers",
            "pillow",
            "opencv-python",
            "cryptography",
            "pyopenssl",
            "pynacl",
            "bcrypt",
            "passlib",
            "pyjwt",
            "boto3",
            "botocore",
            "google-cloud-storage",
            "azure-identity",
            "pyyaml",
            "toml",
            "tomli",
            "lxml",
            "beautifulsoup4",
            "html5lib",
            "jinja2",
            "markupsafe",
            "click",
            "typer",
            "rich",
            "colorama",
            "tqdm",
            "pytest",
            "hypothesis",
            "mypy",
            "ruff",
            "black",
            "flake8",
            "setuptools",
            "wheel",
            "pip",
            "packaging",
            "attrs",
            "cattrs",
            "typing-extensions",
            "python-dateutil",
            "pytz",
            "tzdata",
            "six",
            "decorator",
            "wrapt",
            "protobuf",
            "grpcio",
            "paramiko",
            "fabric",
            "ansible",
            "docker",
            "kubernetes",
            "psutil",
            "watchdog",
            "filelock",
            "platformdirs",
            "virtualenv",
            "poetry",
            "networkx",
            "sympy",
            "nltk",
            "spacy",
            "pypdf",
            "python-docx",
        }
    ),
}


@dataclass
class DependencyRecord:
    """Normalized dependency component parsed from a manifest, lockfile, or SBOM."""

    name: str
    version: str
    ecosystem: str
    source_url: str = ""
    is_unpinned_or_git: bool = False
    has_install_or_build_hook: bool = False
    license_id: str = ""
    direct_dep_count: int = 0
    manifest_path: str = ""
    integrity: str = ""
    hook_details: Tuple[str, ...] = ()

    @property
    def canonical_key(self) -> str:
        return f"{self.ecosystem.lower()}:{canonical_package_name(self.name, self.ecosystem)}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["hook_details"] = list(self.hook_details)
        return data


@dataclass
class SbomDriftFinding:
    """Supply-chain drift finding compatible with Mantis SARIF/JSON aggregation."""

    rule_id: str
    severity: str
    title: str
    description: str
    package_name: str
    ecosystem: str
    layer: str  # "deterministic_rule" | "per_package_latent_drift"
    surprise_score: Optional[float] = None
    threshold: Optional[float] = None
    cwe: str = "CWE-829"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_finding_dict(self) -> Dict[str, Any]:
        sev = str(self.severity or "MEDIUM").upper()
        digest_src = f"{self.rule_id}|{self.ecosystem}|{self.package_name}|{self.layer}|{self.title}"
        finding_id = "SBOM-" + hashlib.sha256(digest_src.encode("utf-8")).hexdigest()[:12].upper()
        ev = dict(self.evidence or {})
        file_path = str(ev.get("manifest_path") or ev.get("file_path") or "repo")
        try:
            line_number = max(1, int(ev.get("line_number") or 1))
        except (TypeError, ValueError):
            line_number = 1
        return {
            "finding_id": finding_id,
            "rule_id": self.rule_id,
            "severity": sev,
            "title": self.title,
            "description": self.description,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "layer": self.layer,
            "surprise_score": self.surprise_score,
            "threshold": self.threshold,
            "cwe": self.cwe,
            "evidence": ev,
            "file_path": file_path,
            "line_number": line_number,
            "sink": f"{self.ecosystem}:{self.package_name}",
            "scanner": "sbom_drift_guard",
            "category": "Supply Chain Drift",
            "cvss_score": _SEVERITY_CVSS.get(sev, 5.3),
            "remediation": _RULE_REMEDIATION.get(
                self.rule_id,
                "Audit dependency changes against trusted registries and release provenance.",
            ),
            "reproduced": self.layer == "deterministic_rule",
            "patch_verified": False,
            "is_zero_day": False,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.to_finding_dict()


@dataclass
class SbomSnapshot:
    """Point-in-time dependency snapshot from a working tree or git commit."""

    records: Dict[str, DependencyRecord] = field(default_factory=dict)
    commit_sha: Optional[str] = None
    commit_timestamp: Optional[str] = None
    manifest_paths: List[str] = field(default_factory=list)

    @property
    def ecosystems(self) -> List[str]:
        return sorted({rec.ecosystem for rec in self.records.values() if rec.ecosystem})


# ---------------------------------------------------------------------------
# Normalization, Levenshtein, License & Registry Utilities
# ---------------------------------------------------------------------------


def canonical_package_name(name: str, ecosystem: str) -> str:
    """Canonicalizes package names per ecosystem rules (e.g. PEP 503 for PyPI)."""
    clean = str(name or "").strip().lower()
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", clean)
    return clean


def levenshtein_distance(a: str, b: str, *, max_dist: Optional[int] = None) -> int:
    """Computes exact Levenshtein edit distance with optional bounded early exit."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if max_dist is not None and abs(la - lb) > max_dist:
        return max_dist + 1
    if la == 0:
        return lb
    if lb == 0:
        return la
    if la < lb:
        a, b = b, a
        la, lb = lb, la

    prev_row = list(range(lb + 1))
    for i, ch_a in enumerate(a, start=1):
        curr_row = [i] + [0] * lb
        row_min = i
        for j, ch_b in enumerate(b, start=1):
            cost = 0 if ch_a == ch_b else 1
            val = min(
                prev_row[j] + 1,
                curr_row[j - 1] + 1,
                prev_row[j - 1] + cost,
            )
            curr_row[j] = val
            if val < row_min:
                row_min = val
        if max_dist is not None and row_min > max_dist:
            return max_dist + 1
        prev_row = curr_row
    return prev_row[lb]


def parse_semver(version: str) -> Tuple[int, int, int, bool]:
    """Parses major/minor/patch/prerelease components from a version string."""
    raw = str(version or "").strip()
    if not raw:
        return (0, 0, 0, False)
    m = _SEMVER_RX.search(raw)
    if not m:
        return (0, 0, 0, False)
    maj = int(m.group("maj") or 0)
    minor = int(m.group("min") or 0)
    pat = int(m.group("pat") or 0)
    is_pre = bool(m.group("pre"))
    return (maj, minor, pat, is_pre)


def classify_license(license_id: str) -> str:
    """Classifies license string into permissive, known_other, unlicensed, or missing."""
    raw = str(license_id or "").strip()
    if not raw:
        return "missing"
    lowered = raw.lower().strip()
    if lowered in _UNLICENSED_TOKENS or lowered.startswith("see license"):
        return "unlicensed"

    tokens = [
        tok.strip().strip("()").lower()
        for tok in re.split(r"\b(?:OR|AND|WITH)\b|[/,;]", raw, flags=re.IGNORECASE)
        if tok.strip().strip("()")
    ]
    if not tokens:
        return "missing"
    if all(tok in _UNLICENSED_TOKENS for tok in tokens):
        return "unlicensed"
    if any(tok in _PERMISSIVE_OSI_LICENSES for tok in tokens):
        return "permissive"
    return "known_other"


def extract_registry_origin(source_url: str, ecosystem: str = "") -> str:
    """Extracts a canonical registry/source origin identifier for domain-swap comparisons."""
    raw = str(source_url or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    eco = ecosystem.lower()

    if eco == "cargo":
        if "crates.io-index" in lowered or "index.crates.io" in lowered:
            return "crates.io"

    if lowered.startswith(("github:", "gitlab:", "bitbucket:")):
        provider, _, rest = lowered.partition(":")
        repo_part = rest.split("#", 1)[0].strip("/")
        return f"git:{provider}/{repo_part}"

    is_git = lowered.startswith(("git+", "git://", "ssh://", "hg+", "svn+", "bzr+"))
    clean_url = re.sub(r"^(?:registry|sparse|git|hg|svn|bzr)\+", "", raw, flags=re.IGNORECASE)
    parsed = urlparse(clean_url)
    host = (parsed.hostname or "").lower()

    if not host:
        if lowered.startswith(("file:", "link:")):
            return "local-path"
        return lowered[:80]

    if eco == "pypi" and host in ("pypi.org", "files.pythonhosted.org"):
        return "pypi.org"
    if eco == "cargo" and ("crates.io" in host or "crates.io-index" in parsed.path.lower()):
        return "crates.io"

    if is_git or parsed.path.lower().endswith(".git"):
        repo_path = parsed.path.strip("/").split("?", 1)[0]
        return f"git:{host}/{repo_path}" if repo_path else f"git:{host}"

    return host


def is_official_registry_origin(origin: str, ecosystem: str) -> bool:
    """Returns True if origin is a canonical official registry for the ecosystem."""
    if not origin:
        return False
    official = _OFFICIAL_REGISTRIES.get(ecosystem.lower(), frozenset())
    return origin.lower() in official


def is_unpinned_or_git_source(source_url: str, version: str, ecosystem: str = "") -> bool:
    """Determines whether a dependency source/version represents a git+ or unpinned remote ref."""
    src = str(source_url or "").strip()
    src_l = src.lower()
    ver_l = str(version or "").strip().lower()

    if ver_l in _UNPINNED_VERSION_TOKENS:
        return True
    if ver_l.startswith(_VCS_PREFIXES) or ver_l.startswith(("http://", "https://")):
        return True

    if not src_l:
        return False

    if src_l.startswith(_VCS_PREFIXES):
        return True
    if src_l.startswith("http://"):
        return True

    origin = extract_registry_origin(src, ecosystem)
    if origin.startswith("git:"):
        return True
    if ".git" in src_l and origin != "crates.io":
        return True

    # Direct archive/code tarball from git hosts (e.g. codeload.github.com)
    if any(
        marker in src_l
        for marker in (
            "codeload.github.com",
            "raw.githubusercontent.com",
            "github.com/",
            "gitlab.com/",
        )
    ) and origin != "crates.io":
        return True

    # Direct archive/wheel URL outside standard npm /-/ registry layout
    if src_l.startswith("https://") and not is_official_registry_origin(origin, ecosystem):
        parsed = urlparse(src_l)
        if parsed.path.endswith((".tgz", ".tar.gz", ".whl", ".zip", ".crate")):
            if "/-/" not in parsed.path:
                return True

    return False


def _merge_record(existing: DependencyRecord, incoming: DependencyRecord) -> DependencyRecord:
    """Conservatively merges duplicate records so risky attributes are never masked."""
    existing_origin = extract_registry_origin(existing.source_url, existing.ecosystem)
    incoming_origin = extract_registry_origin(incoming.source_url, incoming.ecosystem)

    # Prefer risky/non-official source if one copy introduces it so it cannot hide behind a benign copy
    chosen_source = existing.source_url or incoming.source_url
    if incoming.is_unpinned_or_git and not existing.is_unpinned_or_git:
        chosen_source = incoming.source_url or existing.source_url
    elif incoming_origin and existing_origin and is_official_registry_origin(existing_origin, existing.ecosystem):
        if not is_official_registry_origin(incoming_origin, incoming.ecosystem):
            chosen_source = incoming.source_url

    chosen_version = existing.version or incoming.version
    if incoming.version and existing.version:
        if parse_semver(incoming.version)[:3] > parse_semver(existing.version)[:3]:
            chosen_version = incoming.version

    # Prefer explicit license, or preserve drop if neither has one
    chosen_license = existing.license_id or incoming.license_id
    combined_hooks = tuple(sorted(set(existing.hook_details) | set(incoming.hook_details)))

    return DependencyRecord(
        name=existing.name or incoming.name,
        version=chosen_version,
        ecosystem=existing.ecosystem or incoming.ecosystem,
        source_url=chosen_source,
        is_unpinned_or_git=bool(existing.is_unpinned_or_git or incoming.is_unpinned_or_git),
        has_install_or_build_hook=bool(
            existing.has_install_or_build_hook or incoming.has_install_or_build_hook
        ),
        license_id=chosen_license,
        direct_dep_count=max(int(existing.direct_dep_count), int(incoming.direct_dep_count)),
        manifest_path=existing.manifest_path or incoming.manifest_path,
        integrity=existing.integrity or incoming.integrity,
        hook_details=combined_hooks,
    )


def _records_to_map(
    snapshot_or_records: Optional[
        Union[SbomSnapshot, Mapping[str, DependencyRecord], Sequence[DependencyRecord]]
    ]
) -> Dict[str, DependencyRecord]:
    if snapshot_or_records is None:
        return {}
    if isinstance(snapshot_or_records, SbomSnapshot):
        return dict(snapshot_or_records.records)
    if isinstance(snapshot_or_records, Mapping):
        out: Dict[str, DependencyRecord] = {}
        for rec in snapshot_or_records.values():
            key = rec.canonical_key
            out[key] = _merge_record(out[key], rec) if key in out else rec
        return out
    out = {}
    for rec in snapshot_or_records:
        key = rec.canonical_key
        out[key] = _merge_record(out[key], rec) if key in out else rec
    return out


# ---------------------------------------------------------------------------
# Manifest & SBOM Parsers
# ---------------------------------------------------------------------------


def _extract_npm_license(raw_license: Any) -> str:
    if isinstance(raw_license, str):
        return raw_license.strip()
    if isinstance(raw_license, dict):
        return str(raw_license.get("type") or raw_license.get("name") or "").strip()
    if isinstance(raw_license, list):
        parts = [_extract_npm_license(item) for item in raw_license]
        parts = [p for p in parts if p]
        return " OR ".join(parts)
    return ""


def _extract_npm_install_hooks(meta: Mapping[str, Any]) -> Tuple[bool, Tuple[str, ...]]:
    hooks: List[str] = []
    if bool(meta.get("hasInstallScript")):
        hooks.append("hasInstallScript")
    if bool(meta.get("gypfile")):
        hooks.append("binding.gyp")
    scripts = meta.get("scripts")
    if isinstance(scripts, Mapping):
        for key in ("preinstall", "install", "postinstall"):
            val = scripts.get(key)
            if isinstance(val, str) and val.strip():
                hooks.append(f"{key}:{val.strip()[:120]}")
    return (bool(hooks), tuple(hooks))


def parse_package_json(
    content: str,
    *,
    manifest_path: str = "package.json",
) -> Tuple[Optional[DependencyRecord], List[DependencyRecord]]:
    """Parses package.json for root install hooks and declared dependency specs."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError):
        return (None, [])
    if not isinstance(data, dict):
        return (None, [])

    root_name = str(data.get("name") or "").strip()
    root_version = str(data.get("version") or "0.0.0").strip()
    root_license = _extract_npm_license(data.get("license") or data.get("licenses"))
    has_hook, hook_details = _extract_npm_install_hooks(data)

    dep_count = 0
    dep_records: List[DependencyRecord] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        sec_map = data.get(section)
        if not isinstance(sec_map, dict):
            continue
        if section != "devDependencies":
            dep_count += len(sec_map)
        for dep_name, spec in sec_map.items():
            if not isinstance(dep_name, str) or not dep_name.strip():
                continue
            spec_str = str(spec or "").strip()
            src_url = spec_str if (
                spec_str.lower().startswith(_VCS_PREFIXES)
                or spec_str.lower().startswith(("http://", "https://"))
            ) else ""
            is_unpinned = is_unpinned_or_git_source(src_url, spec_str, "npm")
            dep_records.append(
                DependencyRecord(
                    name=dep_name.strip(),
                    version=spec_str,
                    ecosystem="npm",
                    source_url=src_url,
                    is_unpinned_or_git=is_unpinned,
                    has_install_or_build_hook=False,
                    license_id="",
                    direct_dep_count=0,
                    manifest_path=manifest_path,
                )
            )

    root_record: Optional[DependencyRecord] = None
    if root_name or has_hook:
        root_record = DependencyRecord(
            name=root_name or "<root-package>",
            version=root_version,
            ecosystem="npm",
            source_url="",
            is_unpinned_or_git=False,
            has_install_or_build_hook=has_hook,
            license_id=root_license,
            direct_dep_count=dep_count,
            manifest_path=manifest_path,
            hook_details=hook_details,
        )
    return (root_record, dep_records)


def parse_package_lock(
    content: str,
    *,
    manifest_path: str = "package-lock.json",
    package_json_content: Optional[str] = None,
) -> List[DependencyRecord]:
    """Parses npm package-lock.json (lockfileVersion 1, 2, and 3) into DependencyRecords."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    by_key: Dict[str, DependencyRecord] = {}

    def _add(rec: DependencyRecord) -> None:
        key = rec.canonical_key
        by_key[key] = _merge_record(by_key[key], rec) if key in by_key else rec

    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        for pkg_path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            has_hook, hook_details = _extract_npm_install_hooks(meta)
            if pkg_path == "":
                if has_hook:
                    root_name = str(meta.get("name") or data.get("name") or "<root-package>").strip()
                    root_deps = (meta.get("dependencies") or {}) if isinstance(meta.get("dependencies"), dict) else {}
                    _add(
                        DependencyRecord(
                            name=root_name,
                            version=str(meta.get("version") or data.get("version") or "0.0.0"),
                            ecosystem="npm",
                            source_url="",
                            is_unpinned_or_git=False,
                            has_install_or_build_hook=True,
                            license_id=_extract_npm_license(meta.get("license") or meta.get("licenses")),
                            direct_dep_count=len(root_deps),
                            manifest_path=manifest_path,
                            hook_details=hook_details,
                        )
                    )
                continue

            if "node_modules/" in pkg_path:
                pkg_name = pkg_path.rsplit("node_modules/", 1)[-1].strip()
            else:
                pkg_name = str(meta.get("name") or pkg_path).strip()
            if not pkg_name:
                continue

            version = str(meta.get("version") or "").strip()
            resolved = str(meta.get("resolved") or "").strip()
            integrity = str(meta.get("integrity") or "").strip()
            if not resolved and (
                version.lower().startswith(_VCS_PREFIXES)
                or version.lower().startswith(("http://", "https://"))
            ):
                resolved = version

            deps = meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else {}
            opt_deps = (
                meta.get("optionalDependencies")
                if isinstance(meta.get("optionalDependencies"), dict)
                else {}
            )
            direct_count = len(deps) + len(opt_deps)
            license_id = _extract_npm_license(meta.get("license") or meta.get("licenses"))
            is_unpinned = is_unpinned_or_git_source(resolved, version, "npm")

            _add(
                DependencyRecord(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    source_url=resolved,
                    is_unpinned_or_git=is_unpinned,
                    has_install_or_build_hook=has_hook,
                    license_id=license_id,
                    direct_dep_count=direct_count,
                    manifest_path=manifest_path,
                    integrity=integrity,
                    hook_details=hook_details,
                )
            )
    elif isinstance(data.get("dependencies"), dict):
        # lockfileVersion 1 recursive tree
        def _walk_v1(dep_map: Mapping[str, Any], depth: int = 0) -> None:
            if depth > 32:
                return
            for dep_name, meta in dep_map.items():
                if not isinstance(dep_name, str) or not isinstance(meta, dict):
                    continue
                version = str(meta.get("version") or "").strip()
                resolved = str(meta.get("resolved") or "").strip()
                integrity = str(meta.get("integrity") or "").strip()
                if not resolved and (
                    version.lower().startswith(_VCS_PREFIXES)
                    or version.lower().startswith(("http://", "https://"))
                ):
                    resolved = version
                has_hook, hook_details = _extract_npm_install_hooks(meta)
                requires = meta.get("requires") if isinstance(meta.get("requires"), dict) else {}
                license_id = _extract_npm_license(meta.get("license") or meta.get("licenses"))
                is_unpinned = is_unpinned_or_git_source(resolved, version, "npm")
                _add(
                    DependencyRecord(
                        name=dep_name.strip(),
                        version=version,
                        ecosystem="npm",
                        source_url=resolved,
                        is_unpinned_or_git=is_unpinned,
                        has_install_or_build_hook=has_hook,
                        license_id=license_id,
                        direct_dep_count=len(requires),
                        manifest_path=manifest_path,
                        integrity=integrity,
                        hook_details=hook_details,
                    )
                )
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    _walk_v1(nested, depth + 1)

        _walk_v1(data["dependencies"])

    if package_json_content:
        root_rec, declared_deps = parse_package_json(
            package_json_content,
            manifest_path=str(Path(manifest_path).with_name("package.json").as_posix()),
        )
        if root_rec is not None:
            _add(root_rec)
        for decl in declared_deps:
            key = decl.canonical_key
            if key in by_key:
                existing = by_key[key]
                if decl.is_unpinned_or_git and not existing.is_unpinned_or_git:
                    by_key[key] = _merge_record(existing, decl)
            elif decl.is_unpinned_or_git:
                _add(decl)

    return sorted(by_key.values(), key=lambda r: (r.ecosystem, r.name.lower()))


def parse_cargo_toml_metadata(content: str) -> Tuple[str, str, bool]:
    """Extracts (package_name, license_id, has_explicit_build_script) from Cargo.toml."""
    if tomllib is not None:
        try:
            data = tomllib.loads(content)
            pkg = data.get("package")
            if isinstance(pkg, dict):
                name = str(pkg.get("name") or "").strip()
                lic = str(pkg.get("license") or "").strip()
                build_val = pkg.get("build")
                has_build = bool(build_val) and build_val is not False
                return (name, lic, has_build)
        except Exception:
            pass

    name_m = _TOML_PKG_NAME_RX.search(content)
    lic_m = _TOML_PKG_LICENSE_RX.search(content)
    build_m = _TOML_BUILD_RX.search(content)
    return (
        name_m.group(1).strip() if name_m else "",
        lic_m.group(1).strip() if lic_m else "",
        bool(build_m),
    )


def _fallback_parse_cargo_lock_packages(content: str) -> List[Dict[str, Any]]:
    """Minimal fallback parser for Cargo.lock if tomllib is unavailable."""
    packages: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    in_deps = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[package]]":
            if current:
                packages.append(current)
            current = {"dependencies": []}
            in_deps = False
            continue
        if current is None:
            continue
        if in_deps:
            if line.startswith("]"):
                in_deps = False
                continue
            m = re.search(r'"([^"]+)"', line)
            if m:
                current["dependencies"].append(m.group(1))
            continue
        if line.startswith("dependencies") and "[" in line:
            if "]" in line:
                current["dependencies"].extend(re.findall(r'"([^"]+)"', line))
            else:
                in_deps = True
            continue
        m_kv = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"', line)
        if m_kv:
            current[m_kv.group(1)] = m_kv.group(2)
    if current:
        packages.append(current)
    return packages


def parse_cargo_lock(
    content: str,
    *,
    manifest_path: str = "Cargo.lock",
    build_rs_packages: Optional[Iterable[str]] = None,
    cargo_licenses: Optional[Mapping[str, str]] = None,
) -> List[DependencyRecord]:
    """Parses Cargo.lock TOML entries and attaches detected build.rs capabilities."""
    packages_raw: List[Dict[str, Any]] = []
    if tomllib is not None:
        try:
            parsed = tomllib.loads(content)
            pkgs = parsed.get("package")
            if isinstance(pkgs, list):
                packages_raw = [p for p in pkgs if isinstance(p, dict)]
        except Exception:
            packages_raw = _fallback_parse_cargo_lock_packages(content)
    else:  # pragma: no cover
        packages_raw = _fallback_parse_cargo_lock_packages(content)

    build_set = {str(p).strip().lower() for p in (build_rs_packages or ()) if str(p).strip()}
    lic_map = {str(k).strip().lower(): str(v).strip() for k, v in (cargo_licenses or {}).items()}
    by_key: Dict[str, DependencyRecord] = {}

    for pkg in packages_raw:
        name = str(pkg.get("name") or "").strip()
        if not name:
            continue
        version = str(pkg.get("version") or "").strip()
        source = str(pkg.get("source") or "").strip()
        checksum = str(pkg.get("checksum") or "").strip()
        deps = pkg.get("dependencies")
        dep_count = len(deps) if isinstance(deps, list) else 0

        is_unpinned = bool(source) and is_unpinned_or_git_source(source, version, "cargo")
        has_build = (name.lower() in build_set) or bool(pkg.get("build"))
        hook_details = ("build.rs",) if has_build else ()
        license_id = str(pkg.get("license") or lic_map.get(name.lower(), "")).strip()

        rec = DependencyRecord(
            name=name,
            version=version,
            ecosystem="cargo",
            source_url=source,
            is_unpinned_or_git=is_unpinned,
            has_install_or_build_hook=has_build,
            license_id=license_id,
            direct_dep_count=dep_count,
            manifest_path=manifest_path,
            integrity=checksum,
            hook_details=hook_details,
        )
        key = rec.canonical_key
        by_key[key] = _merge_record(by_key[key], rec) if key in by_key else rec

    return sorted(by_key.values(), key=lambda r: (r.ecosystem, r.name.lower()))


def _strip_req_comment(line: str) -> str:
    """Strips # comments from requirements.txt while preserving URL fragments (#egg=...)."""
    if line.lstrip().startswith("#"):
        return ""
    idx = line.find(" #")
    if idx != -1:
        return line[:idx].strip()
    idx_tab = line.find("\t#")
    if idx_tab != -1:
        return line[:idx_tab].strip()
    return line.strip()


def _infer_name_from_url(url: str) -> str:
    parsed = urlparse(re.sub(r"^(?:git|hg|svn|bzr)\+", "", url, flags=re.IGNORECASE))
    if parsed.fragment:
        frag_params = parse_qs(parsed.fragment)
        if "egg" in frag_params and frag_params["egg"]:
            return frag_params["egg"][0].split("[", 1)[0].strip()
    tail = unquote(parsed.path.rstrip("/").rsplit("/", 1)[-1])
    if tail.endswith(".git"):
        tail = tail[:-4]
    if tail.endswith((".whl", ".tar.gz", ".tgz", ".zip")):
        base = re.sub(r"(?:\.tar\.gz|\.tgz|\.whl|\.zip)$", "", tail)
        return re.split(r"[-_]\d", base, maxsplit=1)[0] or base
    return tail or "remote-package"


def parse_requirements_txt(
    content: str,
    *,
    manifest_path: str = "requirements.txt",
) -> List[DependencyRecord]:
    """Parses Python requirements.txt including pinned deps, git+ URLs, and --extra-index-url."""
    # Join backslash line continuations
    raw_lines = content.splitlines()
    logical_lines: List[str] = []
    buf = ""
    for raw in raw_lines:
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1].strip() + " "
        else:
            logical_lines.append((buf + stripped).strip())
            buf = ""
    if buf.strip():
        logical_lines.append(buf.strip())

    active_index = "https://pypi.org/simple"
    by_key: Dict[str, DependencyRecord] = {}

    def _add(rec: DependencyRecord) -> None:
        key = rec.canonical_key
        by_key[key] = _merge_record(by_key[key], rec) if key in by_key else rec

    for raw_line in logical_lines:
        line = _strip_req_comment(raw_line)
        if not line:
            continue

        # Capture inline --hash tokens before removing options
        hashes = re.findall(r"--hash(?:=|\s+)([^\s]+)", line)
        integrity = hashes[0] if hashes else ""
        line_no_hash = re.sub(r"--hash(?:=|\s+)[^\s]+", "", line).strip()

        # Index URL directives
        m_idx = re.match(r"^(?:--index-url|-i)(?:=|\s+)(\S+)$", line_no_hash)
        if m_idx:
            active_index = m_idx.group(1).strip()
            continue

        m_extra = re.match(r"^--extra-index-url(?:=|\s+)(\S+)$", line_no_hash)
        if m_extra:
            extra_url = m_extra.group(1).strip()
            extra_origin = extract_registry_origin(extra_url, "pypi")
            if not is_official_registry_origin(extra_origin, "pypi"):
                _add(
                    DependencyRecord(
                        name=f"extra-index:{extra_origin or extra_url}",
                        version="unpinned",
                        ecosystem="pypi",
                        source_url=extra_url,
                        is_unpinned_or_git=True,
                        has_install_or_build_hook=False,
                        license_id="",
                        direct_dep_count=0,
                        manifest_path=manifest_path,
                    )
                )
            continue

        editable = False
        if line_no_hash.startswith(("-e ", "--editable ", "--editable=")):
            editable = True
            line_no_hash = re.sub(r"^(?:-e|--editable)(?:=|\s+)", "", line_no_hash).strip()

        if line_no_hash.startswith("-"):
            # Skip other pip CLI flags (-r, -c, --trusted-host, --find-links, etc.)
            continue

        # Strip environment marker (; python_version >= ...)
        req_body = line_no_hash.split(";", 1)[0].strip()
        if not req_body:
            continue

        # PEP 508 direct reference: pkg @ git+https://... or pkg @ https://...
        m_direct = _PEP508_DIRECT_RX.match(req_body)
        if m_direct:
            pkg_name = m_direct.group(1).strip()
            url = m_direct.group(2).strip()
            _add(
                DependencyRecord(
                    name=pkg_name,
                    version=url.split("@")[-1].split("#", 1)[0] if "@" in url else "direct-url",
                    ecosystem="pypi",
                    source_url=url,
                    is_unpinned_or_git=True,
                    has_install_or_build_hook=False,
                    license_id="",
                    direct_dep_count=0,
                    manifest_path=manifest_path,
                    integrity=integrity,
                )
            )
            continue

        # Bare VCS or direct HTTP(S) URL
        if req_body.lower().startswith(_VCS_PREFIXES) or req_body.lower().startswith(
            ("http://", "https://")
        ):
            pkg_name = _infer_name_from_url(req_body)
            _add(
                DependencyRecord(
                    name=pkg_name,
                    version="vcs-ref",
                    ecosystem="pypi",
                    source_url=req_body,
                    is_unpinned_or_git=True,
                    has_install_or_build_hook=False,
                    license_id="",
                    direct_dep_count=0,
                    manifest_path=manifest_path,
                    integrity=integrity,
                )
            )
            continue

        # Standard requirement line
        m_std = _REQ_NAME_RX.match(req_body)
        if not m_std:
            continue
        pkg_name = m_std.group(1).strip()
        spec = m_std.group(2).strip()
        version = spec.lstrip("=<>!~ ").split(",", 1)[0].strip() if spec else ""
        is_unpinned = editable or is_unpinned_or_git_source(active_index, version, "pypi")

        _add(
            DependencyRecord(
                name=pkg_name,
                version=version,
                ecosystem="pypi",
                source_url=active_index,
                is_unpinned_or_git=is_unpinned,
                has_install_or_build_hook=False,
                license_id="",
                direct_dep_count=0,
                manifest_path=manifest_path,
                integrity=integrity,
            )
        )

    return sorted(by_key.values(), key=lambda r: (r.ecosystem, r.name.lower()))


def _parse_purl_metadata(purl: str) -> Tuple[str, str]:
    """Extracts (ecosystem, qualifier_source_url) from a Package URL (purl)."""
    raw = str(purl or "").strip()
    if not raw.lower().startswith("pkg:"):
        return ("cyclonedx", "")
    body = raw[4:]
    eco_raw = body.split("/", 1)[0].strip().lower()
    eco_map = {
        "npm": "npm",
        "cargo": "cargo",
        "pypi": "pypi",
        "golang": "go",
        "maven": "maven",
        "nuget": "nuget",
        "gem": "rubygems",
    }
    eco = eco_map.get(eco_raw, eco_raw or "cyclonedx")
    src_url = ""
    if "?" in body:
        query_str = body.split("?", 1)[1].split("#", 1)[0]
        qs = parse_qs(query_str)
        for key in ("vcs_url", "download_url", "repository_url"):
            if key in qs and qs[key]:
                src_url = unquote(qs[key][0]).strip()
                break
    return (eco, src_url)


def _extract_cdx_licenses(licenses_field: Any) -> str:
    if not isinstance(licenses_field, list):
        return ""
    found: List[str] = []
    for entry in licenses_field:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str) and entry["expression"].strip():
            found.append(entry["expression"].strip())
        elif isinstance(entry.get("license"), dict):
            lic = entry["license"]
            val = str(lic.get("id") or lic.get("name") or "").strip()
            if val:
                found.append(val)
    return " OR ".join(found)


def _extract_cdx_properties(props_field: Any) -> Tuple[str, bool, Tuple[str, ...]]:
    src_url = ""
    hooks: List[str] = []
    if not isinstance(props_field, list):
        return ("", False, ())
    for prop in props_field:
        if not isinstance(prop, dict):
            continue
        k = str(prop.get("name") or "").strip()
        kl = k.lower()
        v = str(prop.get("value") or "").strip()
        if not k or not v:
            continue
        if any(tok in kl for tok in ("resolved", "vcs_url", "registry", "source_url", "download_url")):
            if not src_url:
                src_url = v
        if any(
            tok in kl
            for tok in ("postinstall", "preinstall", "hasinstallscript", "install_hook", "build.rs", "build_script")
        ):
            if v.lower() not in ("false", "0", "no", "none", ""):
                hooks.append(f"{k}:{v[:120]}")
    return (src_url, bool(hooks), tuple(hooks))


def parse_cyclonedx_json(
    content: str,
    *,
    manifest_path: str = "bom.json",
) -> List[DependencyRecord]:
    """Parses CycloneDX JSON SBOMs (*.cdx.json, bom.json) into DependencyRecords."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    bom_format = str(data.get("bomFormat") or "")
    if bom_format and bom_format.lower() != "cyclonedx":
        return []
    components = data.get("components")
    if not isinstance(components, list):
        return []

    dep_counts: Dict[str, int] = {}
    dependencies = data.get("dependencies")
    if isinstance(dependencies, list):
        for dep_entry in dependencies:
            if not isinstance(dep_entry, dict):
                continue
            ref = str(dep_entry.get("ref") or "").strip()
            depends_on = dep_entry.get("dependsOn")
            if ref and isinstance(depends_on, list):
                dep_counts[ref] = len(depends_on)

    by_key: Dict[str, DependencyRecord] = {}

    def _walk_components(comp_list: Sequence[Any], depth: int = 0) -> None:
        if depth > 16:
            return
        for comp in comp_list:
            if not isinstance(comp, dict):
                continue
            raw_name = str(comp.get("name") or "").strip()
            group = str(comp.get("group") or "").strip()
            if not raw_name:
                continue
            full_name = f"{group}/{raw_name}" if (group and not raw_name.startswith(group)) else raw_name
            version = str(comp.get("version") or "").strip()
            purl = str(comp.get("purl") or "").strip()
            bom_ref = str(comp.get("bom-ref") or "").strip()

            eco, purl_src = _parse_purl_metadata(purl)
            prop_src, has_hook, hook_details = _extract_cdx_properties(comp.get("properties"))

            ext_src = ""
            ext_refs = comp.get("externalReferences")
            if isinstance(ext_refs, list):
                for ref_type in ("distribution", "vcs", "website"):
                    for ref in ext_refs:
                        if isinstance(ref, dict) and str(ref.get("type") or "").lower() == ref_type:
                            candidate_url = str(ref.get("url") or "").strip()
                            if candidate_url:
                                ext_src = candidate_url
                                break
                    if ext_src:
                        break

            source_url = prop_src or purl_src or ext_src
            license_id = _extract_cdx_licenses(comp.get("licenses"))
            direct_count = (
                dep_counts.get(bom_ref)
                if bom_ref in dep_counts
                else dep_counts.get(purl, dep_counts.get(full_name, 0))
            )
            is_unpinned = is_unpinned_or_git_source(source_url, version, eco)

            integrity = ""
            hashes = comp.get("hashes")
            if isinstance(hashes, list) and hashes and isinstance(hashes[0], dict):
                alg = str(hashes[0].get("alg") or "")
                val = str(hashes[0].get("content") or "")
                if val:
                    integrity = f"{alg}:{val}" if alg else val

            rec = DependencyRecord(
                name=full_name,
                version=version,
                ecosystem=eco,
                source_url=source_url,
                is_unpinned_or_git=is_unpinned,
                has_install_or_build_hook=has_hook,
                license_id=license_id,
                direct_dep_count=int(direct_count or 0),
                manifest_path=manifest_path,
                integrity=integrity,
                hook_details=hook_details,
            )
            key = rec.canonical_key
            by_key[key] = _merge_record(by_key[key], rec) if key in by_key else rec

            nested = comp.get("components")
            if isinstance(nested, list) and nested:
                _walk_components(nested, depth + 1)

    _walk_components(components)
    return sorted(by_key.values(), key=lambda r: (r.ecosystem, r.name.lower()))


# ---------------------------------------------------------------------------
# Layer 1 — Deterministic High-Precision Supply-Chain Diff Rules
# ---------------------------------------------------------------------------


def _resolve_popular_sets(
    known_popular: Optional[Union[Mapping[str, Iterable[str]], Iterable[str]]]
) -> Dict[str, Set[str]]:
    merged: Dict[str, Set[str]] = {
        eco: {canonical_package_name(p, eco) for p in pkgs}
        for eco, pkgs in DEFAULT_POPULAR_PACKAGES.items()
    }
    if known_popular is None:
        return merged
    if isinstance(known_popular, Mapping):
        for eco, pkgs in known_popular.items():
            eco_l = str(eco).lower()
            merged.setdefault(eco_l, set()).update(
                canonical_package_name(str(p), eco_l) for p in pkgs
            )
    else:
        flat = {str(p).strip().lower() for p in known_popular if str(p).strip()}
        for eco in ("npm", "cargo", "pypi", "cyclonedx"):
            merged.setdefault(eco, set()).update(
                canonical_package_name(p, eco) for p in flat
            )
    return merged


def _is_same_scope_official_or_types(candidate: str, target: str) -> bool:
    """Excludes same-scope packages (@scope/a vs @scope/b) and @types/<exact>."""
    if candidate.startswith("@") and target.startswith("@"):
        c_scope = candidate.split("/", 1)[0]
        t_scope = target.split("/", 1)[0]
        if c_scope == t_scope:
            return True
    if candidate.startswith("@types/"):
        unscoped = candidate[len("@types/") :]
        if unscoped == target:
            return True
    if target.startswith("@types/"):
        unscoped = target[len("@types/") :]
        if unscoped == candidate:
            return True
    return False


def _is_numbered_sibling(a: str, b: str) -> bool:
    """Returns True if both names share an identical stem with trailing numeric suffixes (pkg-001 vs pkg-002)."""
    ma = _NUMBERED_SIBLING_RX.match(a)
    mb = _NUMBERED_SIBLING_RX.match(b)
    return bool(ma and mb and ma.group(1) == mb.group(1))


def _find_typosquat_match(
    rec: DependencyRecord,
    *,
    baseline_names: Set[str],
    popular_names: Set[str],
) -> Optional[Tuple[str, int, str]]:
    """
    Checks if `rec.name` is within Levenshtein edit distance 1-2 of an existing
    baseline dependency or curated popular ecosystem package.
    Returns (matched_target, distance, match_source) or None.
    """
    cand_full = canonical_package_name(rec.name, rec.ecosystem)
    if not cand_full or cand_full.startswith(("extra-index:", "<root")):
        return None
    if cand_full in popular_names or cand_full in baseline_names:
        return None

    # Compare both full name and unscoped npm name (but exclude same-scope official pairs)
    cand_unscoped = cand_full.split("/", 1)[1] if (cand_full.startswith("@") and "/" in cand_full) else cand_full
    if cand_unscoped in popular_names:
        # e.g. @types/lodash or @org/lodash is not a typosquat of lodash unless scoped name matches another scoped pkg
        if cand_full.startswith("@types/"):
            return None

    best: Optional[Tuple[str, int, str]] = None

    def _check_pool(pool: Set[str], source_label: str) -> None:
        nonlocal best
        for target in pool:
            if target == cand_full:
                return
            if _is_same_scope_official_or_types(cand_full, target):
                continue
            if _is_numbered_sibling(cand_full, target):
                continue
            if len(target) < 4:
                continue
            max_allowed = 2 if (len(target) >= 5 and len(cand_full) >= 4) else 1
            dist = levenshtein_distance(cand_full, target, max_dist=max_allowed)
            if 1 <= dist <= max_allowed:
                if best is None or dist < best[1] or (dist == best[1] and target < best[0]):
                    best = (target, dist, source_label)

    _check_pool(baseline_names, "existing_dependency")
    _check_pool(popular_names, "popular_ecosystem_package")
    return best


def evaluate_snapshot_diff(
    baseline: Optional[
        Union[SbomSnapshot, Mapping[str, DependencyRecord], Sequence[DependencyRecord]]
    ],
    candidate: Union[SbomSnapshot, Mapping[str, DependencyRecord], Sequence[DependencyRecord]],
    *,
    known_popular: Optional[Union[Mapping[str, Iterable[str]], Iterable[str]]] = None,
) -> List[SbomDriftFinding]:
    """
    Layer 1 deterministic high-precision supply-chain diff evaluator.

    Supports both diff inspection (`baseline` vs `candidate`) and single-snapshot
    inspection (`baseline=None`), catching:
      - SBOM_UNPINNED_GIT_DEP
      - SBOM_REGISTRY_SOURCE_SWAP
      - SBOM_NEW_INSTALL_BUILD_HOOK
      - SBOM_LICENSE_DROP
      - SBOM_TYPOSQUAT_SUSPECT
    """
    base_map = _records_to_map(baseline)
    cand_map = _records_to_map(candidate)
    is_single_snapshot = baseline is None
    popular_sets = _resolve_popular_sets(known_popular)

    baseline_registries_by_eco: Dict[str, Set[str]] = {}
    baseline_names_by_eco: Dict[str, Set[str]] = {}
    for rec in base_map.values():
        eco = rec.ecosystem.lower()
        origin = extract_registry_origin(rec.source_url, eco)
        if origin and not origin.startswith("git:"):
            baseline_registries_by_eco.setdefault(eco, set()).add(origin)
        baseline_names_by_eco.setdefault(eco, set()).add(canonical_package_name(rec.name, eco))

    findings: List[SbomDriftFinding] = []

    for key in sorted(cand_map.keys()):
        rec = cand_map[key]
        prev = base_map.get(key)
        eco = rec.ecosystem.lower()
        cand_origin = extract_registry_origin(rec.source_url, eco)
        prev_origin = extract_registry_origin(prev.source_url, eco) if prev is not None else ""
        trusted_origins = baseline_registries_by_eco.get(eco, set()) | set(
            _OFFICIAL_REGISTRIES.get(eco, frozenset())
        )

        # 1. SBOM_UNPINNED_GIT_DEP
        is_non_standard_new_origin = (
            bool(cand_origin)
            and cand_origin != "local-path"
            and cand_origin not in trusted_origins
            and not is_official_registry_origin(cand_origin, eco)
        )
        unpinned_triggered = False
        if is_single_snapshot:
            if rec.is_unpinned_or_git or is_non_standard_new_origin:
                unpinned_triggered = True
        elif prev is None:
            if rec.is_unpinned_or_git or is_non_standard_new_origin:
                unpinned_triggered = True
        else:
            if rec.is_unpinned_or_git and not prev.is_unpinned_or_git:
                unpinned_triggered = True

        if unpinned_triggered:
            is_cleartext = rec.source_url.lower().startswith("http://")
            sev = "CRITICAL" if (rec.has_install_or_build_hook or is_cleartext) else "HIGH"
            findings.append(
                SbomDriftFinding(
                    rule_id="SBOM_UNPINNED_GIT_DEP",
                    severity=sev,
                    title=f"Unpinned git+/remote dependency introduced: {rec.name}",
                    description=(
                        f"Dependency '{rec.name}' ({rec.ecosystem}) resolves from an unpinned, "
                        f"VCS, or non-standard source '{rec.source_url or rec.version}'."
                    ),
                    package_name=rec.name,
                    ecosystem=rec.ecosystem,
                    layer="deterministic_rule",
                    surprise_score=None,
                    threshold=None,
                    cwe="CWE-829",
                    evidence={
                        "manifest_path": rec.manifest_path or "repo",
                        "version": rec.version,
                        "source_url": rec.source_url,
                        "origin": cand_origin,
                        "has_install_or_build_hook": rec.has_install_or_build_hook,
                        "is_new_package": prev is None,
                    },
                )
            )

        # 2. SBOM_REGISTRY_SOURCE_SWAP
        if prev is not None and prev_origin and cand_origin and prev_origin != cand_origin:
            swapped_from_official = is_official_registry_origin(prev_origin, eco) and not is_official_registry_origin(
                cand_origin, eco
            )
            sev = "CRITICAL" if (swapped_from_official or rec.has_install_or_build_hook) else "HIGH"
            findings.append(
                SbomDriftFinding(
                    rule_id="SBOM_REGISTRY_SOURCE_SWAP",
                    severity=sev,
                    title=f"Registry/source domain swapped for {rec.name}: {prev_origin} -> {cand_origin}",
                    description=(
                        f"Existing dependency '{rec.name}' ({rec.ecosystem}) changed its resolved "
                        f"source origin from '{prev_origin}' to '{cand_origin}'."
                    ),
                    package_name=rec.name,
                    ecosystem=rec.ecosystem,
                    layer="deterministic_rule",
                    surprise_score=None,
                    threshold=None,
                    cwe="CWE-494",
                    evidence={
                        "manifest_path": rec.manifest_path or "repo",
                        "prev_version": prev.version,
                        "new_version": rec.version,
                        "prev_source_url": prev.source_url,
                        "new_source_url": rec.source_url,
                        "prev_origin": prev_origin,
                        "new_origin": cand_origin,
                    },
                )
            )

        # 3. SBOM_NEW_INSTALL_BUILD_HOOK
        hook_triggered = False
        if is_single_snapshot:
            if rec.has_install_or_build_hook and (
                rec.is_unpinned_or_git
                or any(_SUSPICIOUS_HOOK_COMMAND_RX.search(h) for h in rec.hook_details)
            ):
                hook_triggered = True
        elif prev is None:
            if rec.has_install_or_build_hook:
                hook_triggered = True
        else:
            if rec.has_install_or_build_hook and not prev.has_install_or_build_hook:
                hook_triggered = True

        if hook_triggered:
            suspicious_cmd = any(_SUSPICIOUS_HOOK_COMMAND_RX.search(h) for h in rec.hook_details)
            sev = (
                "CRITICAL"
                if (rec.is_unpinned_or_git or suspicious_cmd or (prev is not None and prev_origin and cand_origin and prev_origin != cand_origin))
                else "HIGH"
            )
            findings.append(
                SbomDriftFinding(
                    rule_id="SBOM_NEW_INSTALL_BUILD_HOOK",
                    severity=sev,
                    title=f"New install/build execution hook detected in {rec.name}",
                    description=(
                        f"Dependency '{rec.name}' ({rec.ecosystem}) introduced install/build "
                        f"script execution capability ({', '.join(rec.hook_details) or 'install/build hook'})."
                    ),
                    package_name=rec.name,
                    ecosystem=rec.ecosystem,
                    layer="deterministic_rule",
                    surprise_score=None,
                    threshold=None,
                    cwe="CWE-506",
                    evidence={
                        "manifest_path": rec.manifest_path or "repo",
                        "prev_version": prev.version if prev else None,
                        "new_version": rec.version,
                        "hook_details": list(rec.hook_details),
                        "is_new_package": prev is None,
                    },
                )
            )

        # 4. SBOM_LICENSE_DROP
        if prev is not None:
            prev_lic_cls = classify_license(prev.license_id)
            cand_lic_cls = classify_license(rec.license_id)
            if prev_lic_cls == "permissive" and cand_lic_cls in ("missing", "unlicensed"):
                findings.append(
                    SbomDriftFinding(
                        rule_id="SBOM_LICENSE_DROP",
                        severity="MEDIUM",
                        title=f"Permissive OSI license dropped on {rec.name} ({prev.license_id} -> {rec.license_id or 'NONE'})",
                        description=(
                            f"Dependency '{rec.name}' ({rec.ecosystem}) previously declared permissive "
                            f"license '{prev.license_id}', which disappeared or changed to '{rec.license_id or 'missing'}'."
                        ),
                        package_name=rec.name,
                        ecosystem=rec.ecosystem,
                        layer="deterministic_rule",
                        surprise_score=None,
                        threshold=None,
                        cwe="CWE-1357",
                        evidence={
                            "manifest_path": rec.manifest_path or "repo",
                            "prev_version": prev.version,
                            "new_version": rec.version,
                            "prev_license": prev.license_id,
                            "new_license": rec.license_id,
                        },
                    )
                )

        # 5. SBOM_TYPOSQUAT_SUSPECT (newly added packages in diff mode, or all packages on single snapshot)
        if prev is None:
            typo = _find_typosquat_match(
                rec,
                baseline_names=baseline_names_by_eco.get(eco, set()),
                popular_names=popular_sets.get(eco, set()),
            )
            if typo is not None:
                matched_target, dist, match_source = typo
                findings.append(
                    SbomDriftFinding(
                        rule_id="SBOM_TYPOSQUAT_SUSPECT",
                        severity="HIGH",
                        title=f"Suspected typosquat package '{rec.name}' (distance {dist} from '{matched_target}')",
                        description=(
                            f"Newly added dependency '{rec.name}' ({rec.ecosystem}) is within "
                            f"Levenshtein edit distance {dist} of {match_source.replace('_', ' ')} "
                            f"'{matched_target}'."
                        ),
                        package_name=rec.name,
                        ecosystem=rec.ecosystem,
                        layer="deterministic_rule",
                        surprise_score=None,
                        threshold=None,
                        cwe="CWE-1357",
                        evidence={
                            "manifest_path": rec.manifest_path or "repo",
                            "version": rec.version,
                            "matched_target": matched_target,
                            "edit_distance": dist,
                            "match_source": match_source,
                        },
                    )
                )

    findings.sort(
        key=lambda f: (
            -_SEVERITY_RANK.get(f.severity.upper(), 0),
            f.rule_id,
            f.ecosystem,
            f.package_name.lower(),
        )
    )
    return findings


# ---------------------------------------------------------------------------
# Layer 2 — Per-Package Collapse-Free EMA-JEPA Latent Drift Scorer
# ---------------------------------------------------------------------------


def extract_component_transition_vectors(
    prev_rec: Optional[DependencyRecord],
    next_rec: DependencyRecord,
    *,
    baseline_registries: Optional[Set[str]] = None,
) -> Tuple[List[float], List[float], List[float], Dict[str, Any]]:
    """
    Builds per-component (prev_state, action_vec, next_state, delta_summary) vectors.

    State vector (dim=14) encodes per-package attributes and supply-chain capabilities.
    Action vector (dim=10) encodes declared commit intent (add/update, semver bump class,
    ecosystem) without leaking unexpected supply-chain side effects.
    """
    eco = next_rec.ecosystem.lower()
    trusted = set(_OFFICIAL_REGISTRIES.get(eco, frozenset()))
    if baseline_registries:
        trusted |= baseline_registries

    def _lic_score(lic: str) -> float:
        cls = classify_license(lic)
        if cls == "permissive":
            return 1.0
        if cls == "known_other":
            return 0.5
        return 0.0

    def _base_state(rec: Optional[DependencyRecord]) -> List[float]:
        if rec is None:
            return [0.0] * 14
        maj, minor, pat, _ = parse_semver(rec.version)
        origin = extract_registry_origin(rec.source_url, eco)
        non_std = (
            1.5
            if (origin and origin != "local-path" and origin not in trusted and not is_official_registry_origin(origin, eco))
            else 0.0
        )
        return [
            1.0,
            min(1.0, math.log1p(maj) / 4.0),
            min(1.0, math.log1p(minor) / 5.0),
            min(1.0, math.log1p(pat) / 5.0),
            min(1.0, math.log1p(max(0, rec.direct_dep_count)) / 5.0),
            0.0,  # fan_out_delta_norm
            0.0,  # version_jump_norm
            1.5 if rec.is_unpinned_or_git else 0.0,
            non_std,
            0.0,  # registry_swapped
            1.5 if rec.has_install_or_build_hook else 0.0,
            0.0,  # hook_newly_introduced
            _lic_score(rec.license_id),
            0.0,  # license_dropped
        ]

    prev_vec = _base_state(prev_rec)

    n_maj, n_min, n_pat, _ = parse_semver(next_rec.version)
    if prev_rec is not None:
        p_maj, p_min, p_pat, _ = parse_semver(prev_rec.version)
        major_delta = n_maj - p_maj
        minor_delta = n_min - p_min
        patch_delta = n_pat - p_pat
        fan_out_delta = next_rec.direct_dep_count - prev_rec.direct_dep_count
        prev_origin = extract_registry_origin(prev_rec.source_url, eco)
        next_origin = extract_registry_origin(next_rec.source_url, eco)
        registry_swapped = bool(prev_origin and next_origin and prev_origin != next_origin)
        hook_added = bool(next_rec.has_install_or_build_hook and not prev_rec.has_install_or_build_hook)
        lic_dropped = bool(
            classify_license(prev_rec.license_id) == "permissive"
            and classify_license(next_rec.license_id) in ("missing", "unlicensed")
        )
        version_jump = min(
            2.0,
            abs(major_delta) * 0.8
            + min(abs(minor_delta), 10) * 0.08
            + min(abs(patch_delta), 20) * 0.015,
        )
        is_addition = 0.0
        is_update = 1.0
        is_major_bump = 1.0 if major_delta > 0 else 0.0
        is_minor_bump = 1.0 if (major_delta == 0 and minor_delta > 0) else 0.0
        is_patch_bump = 1.0 if (major_delta == 0 and minor_delta == 0 and patch_delta > 0) else 0.0
        is_downgrade = 1.0 if (n_maj, n_min, n_pat) < (p_maj, p_min, p_pat) else 0.0
    else:
        fan_out_delta = next_rec.direct_dep_count
        next_origin = extract_registry_origin(next_rec.source_url, eco)
        registry_swapped = False
        hook_added = bool(next_rec.has_install_or_build_hook)
        lic_dropped = False
        version_jump = 0.0
        is_addition = 1.0
        is_update = 0.0
        is_major_bump = 0.0
        is_minor_bump = 0.0
        is_patch_bump = 0.0
        is_downgrade = 0.0

    non_std_next = (
        1.5
        if (
            next_origin
            and next_origin != "local-path"
            and next_origin not in trusted
            and not is_official_registry_origin(next_origin, eco)
        )
        else 0.0
    )

    next_vec = [
        1.0,
        min(1.0, math.log1p(n_maj) / 4.0),
        min(1.0, math.log1p(n_min) / 5.0),
        min(1.0, math.log1p(n_pat) / 5.0),
        min(1.0, math.log1p(max(0, next_rec.direct_dep_count)) / 5.0),
        math.tanh(fan_out_delta / 10.0),
        version_jump,
        1.5 if next_rec.is_unpinned_or_git else 0.0,
        non_std_next,
        2.0 if registry_swapped else 0.0,
        1.5 if next_rec.has_install_or_build_hook else 0.0,
        2.0 if hook_added else 0.0,
        _lic_score(next_rec.license_id),
        1.5 if lic_dropped else 0.0,
    ]

    action_vec = [
        is_addition,
        is_update,
        is_major_bump,
        is_minor_bump,
        is_patch_bump,
        is_downgrade,
        1.0 if eco == "npm" else 0.0,
        1.0 if eco == "cargo" else 0.0,
        1.0 if eco == "pypi" else 0.0,
        1.0 if eco not in ("npm", "cargo", "pypi") else 0.0,
    ]

    delta_summary = {
        "is_addition": bool(is_addition),
        "fan_out_delta": int(fan_out_delta),
        "version_jump_norm": round(version_jump, 4),
        "is_unpinned_or_git": bool(next_rec.is_unpinned_or_git),
        "non_standard_registry": bool(non_std_next > 0.0),
        "registry_swapped": bool(registry_swapped),
        "hook_newly_introduced": bool(hook_added),
        "license_dropped": bool(lic_dropped),
    }
    return (prev_vec, action_vec, next_vec, delta_summary)


def _record_changed(prev: Optional[DependencyRecord], curr: DependencyRecord) -> bool:
    if prev is None:
        return True
    return (
        prev.version != curr.version
        or prev.source_url != curr.source_url
        or prev.is_unpinned_or_git != curr.is_unpinned_or_git
        or prev.has_install_or_build_hook != curr.has_install_or_build_hook
        or prev.license_id != curr.license_id
        or prev.direct_dep_count != curr.direct_dep_count
    )


# Pure-Python linear algebra fallbacks (used when numpy is unavailable or use_numpy=False)
def _py_matmul(a: List[List[float]], b: List[List[float]]) -> List[List[float]]:
    n = len(a)
    k = len(b)
    m = len(b[0]) if k else 0
    out = [[0.0] * m for _ in range(n)]
    for i in range(n):
        row_a = a[i]
        row_out = out[i]
        for p in range(k):
            av = row_a[p]
            if av == 0.0:
                continue
            row_b = b[p]
            for j in range(m):
                row_out[j] += av * row_b[j]
    return out


def _py_transpose(a: List[List[float]]) -> List[List[float]]:
    if not a:
        return []
    return [[a[i][j] for i in range(len(a))] for j in range(len(a[0]))]


def _py_add_bias(a: List[List[float]], b: List[float]) -> List[List[float]]:
    return [[row[j] + b[j] for j in range(len(b))] for row in a]


def _py_layernorm_fwd(
    x: List[List[float]], eps: float = 1e-5
) -> Tuple[List[List[float]], List[List[float]], List[float]]:
    out: List[List[float]] = []
    x_hat_list: List[List[float]] = []
    inv_std_list: List[float] = []
    for row in x:
        d = len(row)
        mean = sum(row) / d
        var = sum((v - mean) ** 2 for v in row) / d
        inv_std = 1.0 / math.sqrt(var + eps)
        x_hat = [(v - mean) * inv_std for v in row]
        out.append(x_hat)
        x_hat_list.append(x_hat)
        inv_std_list.append(inv_std)
    return (out, x_hat_list, inv_std_list)


def _py_layernorm_bwd(
    grad_out: List[List[float]], x_hat: List[List[float]], inv_std: List[float]
) -> List[List[float]]:
    grad_in: List[List[float]] = []
    for g_row, xh_row, istd in zip(grad_out, x_hat, inv_std):
        d = len(g_row)
        sum_g = sum(g_row)
        sum_g_xh = sum(g * xh for g, xh in zip(g_row, xh_row))
        grad_in.append(
            [(istd / d) * (d * g - sum_g - xh * sum_g_xh) for g, xh in zip(g_row, xh_row)]
        )
    return grad_in


def _py_sigmoid(v: float) -> float:
    if v >= 0.0:
        z = math.exp(-v)
        return 1.0 / (1.0 + z)
    z = math.exp(v)
    return z / (1.0 + z)


def _py_silu_fwd(x: List[List[float]]) -> Tuple[List[List[float]], List[List[float]]]:
    sig = [[_py_sigmoid(v) for v in row] for row in x]
    out = [[v * s for v, s in zip(row, s_row)] for row, s_row in zip(x, sig)]
    return (out, sig)


def _py_silu_bwd(
    grad_out: List[List[float]], x: List[List[float]], sig: List[List[float]]
) -> List[List[float]]:
    return [
        [g * (s + v * s * (1.0 - s)) for g, v, s in zip(g_row, x_row, s_row)]
        for g_row, x_row, s_row in zip(grad_out, x, sig)
    ]


class PerPackageDriftScorer:
    """
    Collapse-free Per-Package EMA-JEPA Latent Drift Scorer.

    Trains an Online Encoder E_theta, stop-gradient EMA Target Encoder E_bar_theta,
    and Forward Dynamics Predictor P_phi with VICReg variance + covariance
    regularization over per-component transition vectors extracted from real
    git lockfile history. Strictly inactive (cold_start_active=True) until at
    least `min_lockfile_commits` real historical lockfile commits are present.
    """

    STATE_DIM: int = 14
    ACTION_DIM: int = 10
    SKIP_SCALE: float = 0.35

    def __init__(
        self,
        *,
        latent_dim: int = 8,
        hidden_dim: int = 20,
        ema_decay: float = 0.99,
        min_lockfile_commits: int = 10,
        quantile: float = 0.99,
        seed: int = 42,
        use_numpy: Optional[bool] = None,
    ) -> None:
        self.latent_dim = int(latent_dim)
        self.hidden_dim = int(hidden_dim)
        self.ema_decay = float(ema_decay)
        self.min_lockfile_commits = max(2, int(min_lockfile_commits))
        self.quantile = min(0.999, max(0.5, float(quantile)))
        self.seed = int(seed)
        self._use_numpy = _HAS_NUMPY if use_numpy is None else bool(use_numpy and _HAS_NUMPY)

        self._calibrated: bool = False
        self._threshold: float = 0.0
        self._commits_seen: int = 0
        self._transitions_trained: int = 0
        self._min_latent_std: float = 0.0
        self._cal_summary: Dict[str, float] = {}

        self._init_weights()

    def _init_weights(self) -> None:
        rng = random.Random(self.seed)

        def _xavier(rows: int, cols: int) -> List[List[float]]:
            scale = math.sqrt(2.0 / (rows + cols))
            return [[rng.gauss(0.0, scale) for _ in range(cols)] for _ in range(rows)]

        def _row_normalized_skip(rows: int, cols: int) -> List[List[float]]:
            mat = [[rng.gauss(0.0, 1.0) for _ in range(cols)] for _ in range(rows)]
            for r in range(rows):
                norm = math.sqrt(sum(v * v for v in mat[r])) or 1.0
                mat[r] = [v / norm for v in mat[r]]
            return mat

        # Online encoder parameters
        self.w1 = _xavier(self.STATE_DIM, self.hidden_dim)
        self.b1 = [0.0] * self.hidden_dim
        self.w2 = _xavier(self.hidden_dim, self.latent_dim)
        self.b2 = [0.0] * self.latent_dim

        # Fixed unit-norm skip projection preserving sensitivity to unseen OOD risk features
        self.w_skip = _row_normalized_skip(self.STATE_DIM, self.latent_dim)

        # EMA target encoder parameters (strict stop-gradient)
        self.t_w1 = [list(r) for r in self.w1]
        self.t_b1 = list(self.b1)
        self.t_w2 = [list(r) for r in self.w2]
        self.t_b2 = list(self.b2)

        # Forward predictor P_phi([z_t; a_t]) -> z_hat_{t+1}
        pred_in = self.latent_dim + self.ACTION_DIM
        self.wp1 = _xavier(pred_in, self.hidden_dim)
        self.bp1 = [0.0] * self.hidden_dim
        self.wp2 = _xavier(self.hidden_dim, self.latent_dim)
        self.bp2 = [0.0] * self.latent_dim

    @property
    def cold_start_active(self) -> bool:
        """True while Layer 2 is suppressed due to insufficient real lockfile history."""
        return not self._calibrated

    @property
    def calibrated(self) -> bool:
        return self._calibrated

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def commits_seen(self) -> int:
        return self._commits_seen

    @property
    def transitions_trained(self) -> int:
        return self._transitions_trained

    @property
    def min_latent_std(self) -> float:
        return self._min_latent_std

    @property
    def backend_label(self) -> str:
        return "per_package_ema_jepa_numpy" if self._use_numpy else "per_package_ema_jepa_python"

    def _encode_batch_np(
        self,
        x_arr: Any,
        w1: Any,
        b1: Any,
        w2: Any,
        b2: Any,
        w_skip: Any,
    ) -> Tuple[Any, Dict[str, Any]]:
        h1 = x_arr @ w1 + b1
        mean = np.mean(h1, axis=1, keepdims=True)
        var = np.var(h1, axis=1, keepdims=True)
        inv_std = 1.0 / np.sqrt(var + 1e-5)
        u1 = (h1 - mean) * inv_std
        sig = 1.0 / (1.0 + np.exp(-np.clip(u1, -30.0, 30.0)))
        a1 = u1 * sig
        z = a1 @ w2 + b2 + self.SKIP_SCALE * (x_arr @ w_skip)
        return (z, {"x": x_arr, "u1": u1, "inv_std": inv_std, "sig": sig, "a1": a1})

    def _predict_batch_np(
        self, z_t: Any, a_arr: Any, wp1: Any, bp1: Any, wp2: Any, bp2: Any
    ) -> Tuple[Any, Dict[str, Any]]:
        c = np.concatenate([z_t, a_arr], axis=1)
        hp_pre = c @ wp1 + bp1
        sig_p = 1.0 / (1.0 + np.exp(-np.clip(hp_pre, -30.0, 30.0)))
        hp = hp_pre * sig_p
        z_pred = hp @ wp2 + bp2
        return (z_pred, {"c": c, "hp_pre": hp_pre, "sig_p": sig_p, "hp": hp})

    def _fit_numpy(
        self,
        train_triples: Sequence[Tuple[List[float], List[float], List[float]]],
        epochs: int,
        lr: float,
    ) -> float:
        x_prev = np.asarray([t[0] for t in train_triples], dtype=np.float64)
        a_act = np.asarray([t[1] for t in train_triples], dtype=np.float64)
        x_next = np.asarray([t[2] for t in train_triples], dtype=np.float64)
        n = float(x_prev.shape[0])

        w1 = np.asarray(self.w1, dtype=np.float64)
        b1 = np.asarray(self.b1, dtype=np.float64)
        w2 = np.asarray(self.w2, dtype=np.float64)
        b2 = np.asarray(self.b2, dtype=np.float64)
        w_skip = np.asarray(self.w_skip, dtype=np.float64)

        t_w1 = np.asarray(self.t_w1, dtype=np.float64)
        t_b1 = np.asarray(self.t_b1, dtype=np.float64)
        t_w2 = np.asarray(self.t_w2, dtype=np.float64)
        t_b2 = np.asarray(self.t_b2, dtype=np.float64)

        wp1 = np.asarray(self.wp1, dtype=np.float64)
        bp1 = np.asarray(self.bp1, dtype=np.float64)
        wp2 = np.asarray(self.wp2, dtype=np.float64)
        bp2 = np.asarray(self.bp2, dtype=np.float64)

        params = [w1, b1, w2, b2, wp1, bp1, wp2, bp2]
        m_adam = [np.zeros_like(p) for p in params]
        v_adam = [np.zeros_like(p) for p in params]
        beta1, beta2, eps_adam = 0.9, 0.999, 1e-8
        lam_var = 0.25
        lam_cov = 0.05
        gamma_std = 0.5

        for step in range(1, max(1, epochs) + 1):
            z_t, enc_cache = self._encode_batch_np(x_prev, w1, b1, w2, b2, w_skip)
            z_next_online, enc_next_cache = self._encode_batch_np(x_next, w1, b1, w2, b2, w_skip)
            z_target, _ = self._encode_batch_np(x_next, t_w1, t_b1, t_w2, t_b2, w_skip)
            z_pred, pred_cache = self._predict_batch_np(z_t, a_act, wp1, bp1, wp2, bp2)

            # Dynamics MSE gradient: d/dz_pred (1/N sum ||z_pred - sg(z_target)||^2)
            diff = z_pred - z_target
            grad_z_pred = (2.0 / n) * diff

            # Predictor backward
            grad_wp2 = pred_cache["hp"].T @ grad_z_pred
            grad_bp2 = np.sum(grad_z_pred, axis=0)
            grad_hp = grad_z_pred @ wp2.T
            sig_p = pred_cache["sig_p"]
            hp_pre = pred_cache["hp_pre"]
            grad_hp_pre = grad_hp * (sig_p + hp_pre * sig_p * (1.0 - sig_p))
            grad_wp1 = pred_cache["c"].T @ grad_hp_pre
            grad_bp1 = np.sum(grad_hp_pre, axis=0)
            grad_c = grad_hp_pre @ wp1.T
            grad_z_t = grad_c[:, : self.latent_dim].copy()

            # VICReg variance + off-diagonal covariance regularization on combined online embeddings
            z_all = np.concatenate([z_t, z_next_online], axis=0)
            m_all = float(z_all.shape[0])
            z_mean = np.mean(z_all, axis=0, keepdims=True)
            z_centered = z_all - z_mean
            var_z = np.mean(z_centered * z_centered, axis=0)
            std_z = np.sqrt(var_z + 1e-4)

            # Variance hinge gradient
            active_var = (std_z < gamma_std).astype(np.float64)
            grad_z_all = -(lam_var / (self.latent_dim * m_all)) * (
                active_var / std_z
            )[None, :] * z_centered

            # Covariance off-diagonal gradient
            denom_cov = max(1.0, m_all - 1.0)
            cov = (z_centered.T @ z_centered) / denom_cov
            cov_off = cov.copy()
            np.fill_diagonal(cov_off, 0.0)
            grad_z_all += (4.0 * lam_cov / (self.latent_dim * denom_cov)) * (z_centered @ cov_off)

            grad_z_t += grad_z_all[: int(n)]
            grad_z_next = grad_z_all[int(n) :]

            # Online encoder backward (sum over both x_prev and x_next online passes)
            def _enc_bwd(grad_z: Any, cache: Dict[str, Any]) -> Tuple[Any, Any, Any, Any]:
                g_w2 = cache["a1"].T @ grad_z
                g_b2 = np.sum(grad_z, axis=0)
                g_a1 = grad_z @ w2.T
                sig = cache["sig"]
                u1 = cache["u1"]
                g_u1 = g_a1 * (sig + u1 * sig * (1.0 - sig))
                d_h = float(self.hidden_dim)
                sum_g = np.sum(g_u1, axis=1, keepdims=True)
                sum_g_u = np.sum(g_u1 * u1, axis=1, keepdims=True)
                g_h1 = (cache["inv_std"] / d_h) * (d_h * g_u1 - sum_g - u1 * sum_g_u)
                g_w1 = cache["x"].T @ g_h1
                g_b1 = np.sum(g_h1, axis=0)
                return (g_w1, g_b1, g_w2, g_b2)

            gw1_a, gb1_a, gw2_a, gb2_a = _enc_bwd(grad_z_t, enc_cache)
            gw1_b, gb1_b, gw2_b, gb2_b = _enc_bwd(grad_z_next, enc_next_cache)
            grads = [
                gw1_a + gw1_b,
                gb1_a + gb1_b,
                gw2_a + gw2_b,
                gb2_a + gb2_b,
                grad_wp1,
                grad_bp1,
                grad_wp2,
                grad_bp2,
            ]

            # Global gradient norm clip
            total_norm = math.sqrt(sum(float(np.sum(g * g)) for g in grads))
            if total_norm > 5.0:
                clip = 5.0 / total_norm
                grads = [g * clip for g in grads]

            # Adam update
            bc1 = 1.0 - (beta1 ** step)
            bc2 = 1.0 - (beta2 ** step)
            for idx, (p, g) in enumerate(zip(params, grads)):
                m_adam[idx] = beta1 * m_adam[idx] + (1.0 - beta1) * g
                v_adam[idx] = beta2 * v_adam[idx] + (1.0 - beta2) * (g * g)
                m_hat = m_adam[idx] / bc1
                v_hat = v_adam[idx] / bc2
                p -= lr * m_hat / (np.sqrt(v_hat) + eps_adam)

            # Stop-gradient EMA target encoder update
            tau = self.ema_decay
            t_w1 = tau * t_w1 + (1.0 - tau) * w1
            t_b1 = tau * t_b1 + (1.0 - tau) * b1
            t_w2 = tau * t_w2 + (1.0 - tau) * w2
            t_b2 = tau * t_b2 + (1.0 - tau) * b2

        # Final latent standard deviation (collapse health check)
        z_final_a, _ = self._encode_batch_np(x_prev, w1, b1, w2, b2, w_skip)
        z_final_b, _ = self._encode_batch_np(x_next, w1, b1, w2, b2, w_skip)
        z_final = np.concatenate([z_final_a, z_final_b], axis=0)
        min_std = float(np.min(np.std(z_final, axis=0)))

        self.w1 = w1.tolist()
        self.b1 = b1.tolist()
        self.w2 = w2.tolist()
        self.b2 = b2.tolist()
        self.t_w1 = t_w1.tolist()
        self.t_b1 = t_b1.tolist()
        self.t_w2 = t_w2.tolist()
        self.t_b2 = t_b2.tolist()
        self.wp1 = wp1.tolist()
        self.bp1 = bp1.tolist()
        self.wp2 = wp2.tolist()
        self.bp2 = bp2.tolist()
        return min_std

    def _encode_batch_py(
        self,
        x_rows: List[List[float]],
        w1: List[List[float]],
        b1: List[float],
        w2: List[List[float]],
        b2: List[float],
    ) -> Tuple[List[List[float]], Dict[str, Any]]:
        h1 = _py_add_bias(_py_matmul(x_rows, w1), b1)
        u1, x_hat, inv_std = _py_layernorm_fwd(h1)
        a1, sig = _py_silu_fwd(u1)
        z_main = _py_add_bias(_py_matmul(a1, w2), b2)
        z_skip = _py_matmul(x_rows, self.w_skip)
        z = [
            [zm + self.SKIP_SCALE * zs for zm, zs in zip(rm, rs)]
            for rm, rs in zip(z_main, z_skip)
        ]
        return (z, {"x": x_rows, "u1": u1, "x_hat": x_hat, "inv_std": inv_std, "sig": sig, "a1": a1})

    def _predict_batch_py(
        self, z_rows: List[List[float]], a_rows: List[List[float]]
    ) -> Tuple[List[List[float]], Dict[str, Any]]:
        c = [zr + ar for zr, ar in zip(z_rows, a_rows)]
        hp_pre = _py_add_bias(_py_matmul(c, self.wp1), self.bp1)
        hp, sig_p = _py_silu_fwd(hp_pre)
        z_pred = _py_add_bias(_py_matmul(hp, self.wp2), self.bp2)
        return (z_pred, {"c": c, "hp_pre": hp_pre, "sig_p": sig_p, "hp": hp})

    def _fit_python(
        self,
        train_triples: Sequence[Tuple[List[float], List[float], List[float]]],
        epochs: int,
        lr: float,
    ) -> float:
        x_prev = [list(t[0]) for t in train_triples]
        a_act = [list(t[1]) for t in train_triples]
        x_next = [list(t[2]) for t in train_triples]
        n = len(train_triples)
        nf = float(n)
        d = self.latent_dim
        lam_var = 0.25
        lam_cov = 0.05
        gamma_std = 0.5

        def _zeros_like_2d(mat: List[List[float]]) -> List[List[float]]:
            return [[0.0] * len(mat[0]) for _ in range(len(mat))]

        def _zeros_like_1d(vec: List[float]) -> List[float]:
            return [0.0] * len(vec)

        m_2d = {
            "w1": _zeros_like_2d(self.w1),
            "w2": _zeros_like_2d(self.w2),
            "wp1": _zeros_like_2d(self.wp1),
            "wp2": _zeros_like_2d(self.wp2),
        }
        v_2d = {k: _zeros_like_2d(val) for k, val in m_2d.items()}
        m_1d = {
            "b1": _zeros_like_1d(self.b1),
            "b2": _zeros_like_1d(self.b2),
            "bp1": _zeros_like_1d(self.bp1),
            "bp2": _zeros_like_1d(self.bp2),
        }
        v_1d = {k: _zeros_like_1d(val) for k, val in m_1d.items()}
        beta1, beta2, eps_adam = 0.9, 0.999, 1e-8

        for step in range(1, max(1, epochs) + 1):
            z_t, enc_cache = self._encode_batch_py(x_prev, self.w1, self.b1, self.w2, self.b2)
            z_next_online, enc_next_cache = self._encode_batch_py(
                x_next, self.w1, self.b1, self.w2, self.b2
            )
            z_target, _ = self._encode_batch_py(x_next, self.t_w1, self.t_b1, self.t_w2, self.t_b2)
            z_pred, pred_cache = self._predict_batch_py(z_t, a_act)

            grad_z_pred = [
                [(2.0 / nf) * (zp - zt) for zp, zt in zip(rp, rt)]
                for rp, rt in zip(z_pred, z_target)
            ]

            grad_wp2 = _py_matmul(_py_transpose(pred_cache["hp"]), grad_z_pred)
            grad_bp2 = [sum(grad_z_pred[i][j] for i in range(n)) for j in range(d)]
            grad_hp = _py_matmul(grad_z_pred, _py_transpose(self.wp2))
            grad_hp_pre = _py_silu_bwd(grad_hp, pred_cache["hp_pre"], pred_cache["sig_p"])
            grad_wp1 = _py_matmul(_py_transpose(pred_cache["c"]), grad_hp_pre)
            grad_bp1 = [sum(grad_hp_pre[i][j] for i in range(n)) for j in range(self.hidden_dim)]
            grad_c = _py_matmul(grad_hp_pre, _py_transpose(self.wp1))
            grad_z_t = [row[:d] for row in grad_c]

            # VICReg variance + covariance on combined embeddings
            z_all = z_t + z_next_online
            m_all = len(z_all)
            mf = float(m_all)
            means = [sum(z_all[i][j] for i in range(m_all)) / mf for j in range(d)]
            z_centered = [[z_all[i][j] - means[j] for j in range(d)] for i in range(m_all)]
            stds = [
                math.sqrt(sum(z_centered[i][j] ** 2 for i in range(m_all)) / mf + 1e-4)
                for j in range(d)
            ]

            grad_z_all = [[0.0] * d for _ in range(m_all)]
            for j in range(d):
                if stds[j] < gamma_std:
                    coeff = -(lam_var / (d * mf)) / stds[j]
                    for i in range(m_all):
                        grad_z_all[i][j] += coeff * z_centered[i][j]

            denom_cov = max(1.0, mf - 1.0)
            cov_off = [[0.0] * d for _ in range(d)]
            for j in range(d):
                for k in range(d):
                    if j != k:
                        cov_off[j][k] = (
                            sum(z_centered[i][j] * z_centered[i][k] for i in range(m_all))
                            / denom_cov
                        )
            cov_grad = _py_matmul(z_centered, cov_off)
            cov_scale = 4.0 * lam_cov / (d * denom_cov)
            for i in range(m_all):
                for j in range(d):
                    grad_z_all[i][j] += cov_scale * cov_grad[i][j]

            for i in range(n):
                for j in range(d):
                    grad_z_t[i][j] += grad_z_all[i][j]
            grad_z_next = grad_z_all[n:]

            def _enc_bwd_py(
                grad_z: List[List[float]], cache: Dict[str, Any]
            ) -> Tuple[List[List[float]], List[float], List[List[float]], List[float]]:
                g_w2 = _py_matmul(_py_transpose(cache["a1"]), grad_z)
                g_b2 = [sum(grad_z[i][j] for i in range(n)) for j in range(d)]
                g_a1 = _py_matmul(grad_z, _py_transpose(self.w2))
                g_u1 = _py_silu_bwd(g_a1, cache["u1"], cache["sig"])
                g_h1 = _py_layernorm_bwd(g_u1, cache["x_hat"], cache["inv_std"])
                g_w1 = _py_matmul(_py_transpose(cache["x"]), g_h1)
                g_b1 = [sum(g_h1[i][j] for i in range(n)) for j in range(self.hidden_dim)]
                return (g_w1, g_b1, g_w2, g_b2)

            gw1_a, gb1_a, gw2_a, gb2_a = _enc_bwd_py(grad_z_t, enc_cache)
            gw1_b, gb1_b, gw2_b, gb2_b = _enc_bwd_py(grad_z_next, enc_next_cache)

            grads_2d = {
                "w1": [[a + b for a, b in zip(ra, rb)] for ra, rb in zip(gw1_a, gw1_b)],
                "w2": [[a + b for a, b in zip(ra, rb)] for ra, rb in zip(gw2_a, gw2_b)],
                "wp1": grad_wp1,
                "wp2": grad_wp2,
            }
            grads_1d = {
                "b1": [a + b for a, b in zip(gb1_a, gb1_b)],
                "b2": [a + b for a, b in zip(gb2_a, gb2_b)],
                "bp1": grad_bp1,
                "bp2": grad_bp2,
            }

            norm_sq = sum(v * v for mat in grads_2d.values() for row in mat for v in row) + sum(
                v * v for vec in grads_1d.values() for v in vec
            )
            total_norm = math.sqrt(norm_sq)
            clip = (5.0 / total_norm) if total_norm > 5.0 else 1.0

            bc1 = 1.0 - (beta1 ** step)
            bc2 = 1.0 - (beta2 ** step)

            for name, param_mat in (
                ("w1", self.w1),
                ("w2", self.w2),
                ("wp1", self.wp1),
                ("wp2", self.wp2),
            ):
                g_mat = grads_2d[name]
                m_mat = m_2d[name]
                v_mat = v_2d[name]
                for i in range(len(param_mat)):
                    for j in range(len(param_mat[0])):
                        g = g_mat[i][j] * clip
                        m_mat[i][j] = beta1 * m_mat[i][j] + (1.0 - beta1) * g
                        v_mat[i][j] = beta2 * v_mat[i][j] + (1.0 - beta2) * g * g
                        param_mat[i][j] -= lr * (m_mat[i][j] / bc1) / (
                            math.sqrt(v_mat[i][j] / bc2) + eps_adam
                        )

            for name, param_vec in (
                ("b1", self.b1),
                ("b2", self.b2),
                ("bp1", self.bp1),
                ("bp2", self.bp2),
            ):
                g_vec = grads_1d[name]
                m_vec = m_1d[name]
                v_vec = v_1d[name]
                for j in range(len(param_vec)):
                    g = g_vec[j] * clip
                    m_vec[j] = beta1 * m_vec[j] + (1.0 - beta1) * g
                    v_vec[j] = beta2 * v_vec[j] + (1.0 - beta2) * g * g
                    param_vec[j] -= lr * (m_vec[j] / bc1) / (
                        math.sqrt(v_vec[j] / bc2) + eps_adam
                    )

            tau = self.ema_decay
            for t_mat, o_mat in ((self.t_w1, self.w1), (self.t_w2, self.w2)):
                for i in range(len(t_mat)):
                    for j in range(len(t_mat[0])):
                        t_mat[i][j] = tau * t_mat[i][j] + (1.0 - tau) * o_mat[i][j]
            for t_vec, o_vec in ((self.t_b1, self.b1), (self.t_b2, self.b2)):
                for j in range(len(t_vec)):
                    t_vec[j] = tau * t_vec[j] + (1.0 - tau) * o_vec[j]

        z_fa, _ = self._encode_batch_py(x_prev, self.w1, self.b1, self.w2, self.b2)
        z_fb, _ = self._encode_batch_py(x_next, self.w1, self.b1, self.w2, self.b2)
        z_all = z_fa + z_fb
        mf = float(len(z_all))
        means = [sum(row[j] for row in z_all) / mf for j in range(d)]
        stds = [
            math.sqrt(sum((row[j] - means[j]) ** 2 for row in z_all) / mf) for j in range(d)
        ]
        return min(stds) if stds else 0.0

    def _raw_surprise_vectors(
        self, prev_vec: Sequence[float], action_vec: Sequence[float], next_vec: Sequence[float]
    ) -> float:
        if self._use_numpy:
            xp = np.asarray([prev_vec], dtype=np.float64)
            aa = np.asarray([action_vec], dtype=np.float64)
            xn = np.asarray([next_vec], dtype=np.float64)
            z_t, _ = self._encode_batch_np(
                xp,
                np.asarray(self.w1, dtype=np.float64),
                np.asarray(self.b1, dtype=np.float64),
                np.asarray(self.w2, dtype=np.float64),
                np.asarray(self.b2, dtype=np.float64),
                np.asarray(self.w_skip, dtype=np.float64),
            )
            z_target, _ = self._encode_batch_np(
                xn,
                np.asarray(self.t_w1, dtype=np.float64),
                np.asarray(self.t_b1, dtype=np.float64),
                np.asarray(self.t_w2, dtype=np.float64),
                np.asarray(self.t_b2, dtype=np.float64),
                np.asarray(self.w_skip, dtype=np.float64),
            )
            z_pred, _ = self._predict_batch_np(
                z_t,
                aa,
                np.asarray(self.wp1, dtype=np.float64),
                np.asarray(self.bp1, dtype=np.float64),
                np.asarray(self.wp2, dtype=np.float64),
                np.asarray(self.bp2, dtype=np.float64),
            )
            diff = z_pred[0] - z_target[0]
            return float(np.sum(diff * diff))

        z_t, _ = self._encode_batch_py([list(prev_vec)], self.w1, self.b1, self.w2, self.b2)
        z_target, _ = self._encode_batch_py(
            [list(next_vec)], self.t_w1, self.t_b1, self.t_w2, self.t_b2
        )
        z_pred, _ = self._predict_batch_py(z_t, [list(action_vec)])
        return float(sum((a - b) ** 2 for a, b in zip(z_pred[0], z_target[0])))

    def fit_from_snapshots(
        self,
        snapshots: Sequence[SbomSnapshot],
        *,
        total_lockfile_commits: Optional[int] = None,
        epochs: int = 40,
        lr: float = 0.015,
    ) -> Dict[str, Any]:
        """
        Trains and calibrates the per-package EMA-JEPA scorer strictly on real
        historical lockfile snapshots ordered oldest -> newest.
        """
        commit_count = (
            int(total_lockfile_commits) if total_lockfile_commits is not None else len(snapshots)
        )
        self._commits_seen = commit_count
        self._calibrated = False
        self._threshold = 0.0
        self._transitions_trained = 0
        self._min_latent_std = 0.0
        self._cal_summary = {}

        if commit_count < self.min_lockfile_commits or len(snapshots) < 2:
            return {
                "calibrated": False,
                "cold_start_active": True,
                "reason": "insufficient_lockfile_commits",
                "commits_seen": commit_count,
                "required": self.min_lockfile_commits,
                "backend_label": self.backend_label,
            }

        transitions: List[Tuple[List[float], List[float], List[float]]] = []
        continuity_fallback: List[Tuple[List[float], List[float], List[float]]] = []

        for idx in range(len(snapshots) - 1):
            prev_snap = snapshots[idx]
            next_snap = snapshots[idx + 1]
            prev_map = prev_snap.records
            next_map = next_snap.records

            base_regs: Set[str] = set()
            for r in prev_map.values():
                org = extract_registry_origin(r.source_url, r.ecosystem)
                if org and not org.startswith("git:"):
                    base_regs.add(org)

            unchanged_in_step = 0
            for key in sorted(next_map.keys()):
                curr_rec = next_map[key]
                prev_rec = prev_map.get(key)
                if _record_changed(prev_rec, curr_rec):
                    p_v, a_v, n_v, _ = extract_component_transition_vectors(
                        prev_rec, curr_rec, baseline_registries=base_regs
                    )
                    transitions.append((p_v, a_v, n_v))
                elif unchanged_in_step < 2:
                    p_v, a_v, n_v, _ = extract_component_transition_vectors(
                        prev_rec, curr_rec, baseline_registries=base_regs
                    )
                    continuity_fallback.append((p_v, a_v, n_v))
                    unchanged_in_step += 1

        if len(transitions) < 6 and continuity_fallback:
            needed = min(len(continuity_fallback), 8 - len(transitions))
            transitions.extend(continuity_fallback[:needed])

        if len(transitions) < 4:
            return {
                "calibrated": False,
                "cold_start_active": True,
                "reason": "insufficient_package_transitions",
                "commits_seen": commit_count,
                "transitions_extracted": len(transitions),
                "required": self.min_lockfile_commits,
                "backend_label": self.backend_label,
            }

        # Chronological train / held-out calibration split
        cal_size = max(2, int(round(len(transitions) * 0.25)))
        if len(transitions) - cal_size < 2:
            cal_size = max(1, len(transitions) - 2)
        train_split = transitions[:-cal_size]
        cal_split = transitions[-cal_size:]

        # Reset weights deterministically before fitting
        self._init_weights()
        if self._use_numpy:
            min_std = self._fit_numpy(train_split, epochs=epochs, lr=lr)
        else:
            min_std = self._fit_python(train_split, epochs=epochs, lr=lr)

        # Empirical p99 conformal calibration on held-out split
        cal_scores = sorted(
            self._raw_surprise_vectors(p_v, a_v, n_v) for (p_v, a_v, n_v) in cal_split
        )
        n_cal = len(cal_scores)
        conformal_idx = min(n_cal - 1, max(0, math.ceil((n_cal + 1) * self.quantile) - 1))
        q_score = cal_scores[conformal_idx]
        cal_mean = sum(cal_scores) / n_cal
        if n_cal > 1:
            cal_std = math.sqrt(sum((s - cal_mean) ** 2 for s in cal_scores) / (n_cal - 1))
        else:
            cal_std = 0.0

        margin = max(0.08, 0.5 * cal_std + 0.15 * q_score)
        self._threshold = float(q_score + margin)
        self._calibrated = True
        self._transitions_trained = len(train_split)
        self._min_latent_std = float(min_std)
        self._cal_summary = {
            "cal_count": float(n_cal),
            "cal_mean": round(cal_mean, 6),
            "cal_std": round(cal_std, 6),
            "cal_quantile": round(q_score, 6),
            "threshold": round(self._threshold, 6),
        }

        return {
            "calibrated": True,
            "cold_start_active": False,
            "commits_seen": commit_count,
            "transitions_trained": len(train_split),
            "cal_transitions": n_cal,
            "threshold": round(self._threshold, 6),
            "min_latent_std": round(min_std, 6),
            "backend_label": self.backend_label,
        }

    def score_component_transition(
        self,
        prev_rec: Optional[DependencyRecord],
        next_rec: DependencyRecord,
        *,
        baseline_registries: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Scores a single package transition against the calibrated per-package threshold."""
        if self.cold_start_active:
            return {
                "calibrated": False,
                "cold_start_active": True,
                "is_anomalous": False,
                "surprise_score": None,
                "threshold": None,
                "ratio": None,
                "feature_deltas": {},
            }

        p_v, a_v, n_v, delta_summary = extract_component_transition_vectors(
            prev_rec, next_rec, baseline_registries=baseline_registries
        )
        score = self._raw_surprise_vectors(p_v, a_v, n_v)
        is_anomalous = score > self._threshold
        return {
            "calibrated": True,
            "cold_start_active": False,
            "is_anomalous": bool(is_anomalous),
            "surprise_score": float(score),
            "threshold": float(self._threshold),
            "ratio": float(score / max(self._threshold, 1e-9)),
            "feature_deltas": delta_summary,
        }

    def score_snapshot_diff(
        self,
        baseline: Optional[
            Union[SbomSnapshot, Mapping[str, DependencyRecord], Sequence[DependencyRecord]]
        ],
        candidate: Union[SbomSnapshot, Mapping[str, DependencyRecord], Sequence[DependencyRecord]],
    ) -> List[SbomDriftFinding]:
        """
        Scores every newly added or modified package in `candidate` vs `baseline`
        individually so a single malicious injection in a 500-dep lockfile is never diluted.
        """
        if self.cold_start_active:
            return []

        base_map = _records_to_map(baseline)
        cand_map = _records_to_map(candidate)

        base_regs: Set[str] = set()
        for r in base_map.values():
            org = extract_registry_origin(r.source_url, r.ecosystem)
            if org and not org.startswith("git:"):
                base_regs.add(org)

        findings: List[SbomDriftFinding] = []
        for key in sorted(cand_map.keys()):
            curr_rec = cand_map[key]
            prev_rec = base_map.get(key)
            if not _record_changed(prev_rec, curr_rec):
                continue

            verdict = self.score_component_transition(
                prev_rec, curr_rec, baseline_registries=base_regs
            )
            if not verdict["is_anomalous"]:
                continue

            score = float(verdict["surprise_score"])
            thresh = float(verdict["threshold"])
            ratio = float(verdict["ratio"])
            deltas = verdict["feature_deltas"]

            high_risk_delta = bool(
                deltas.get("is_unpinned_or_git")
                or deltas.get("hook_newly_introduced")
                or deltas.get("registry_swapped")
            )
            if ratio >= 4.0 and high_risk_delta:
                sev = "CRITICAL"
            elif ratio >= 2.0 or high_risk_delta:
                sev = "HIGH"
            else:
                sev = "MEDIUM"

            findings.append(
                SbomDriftFinding(
                    rule_id="SBOM_PER_PACKAGE_LATENT_DRIFT",
                    severity=sev,
                    title=(
                        f"Per-package latent supply-chain drift detected on '{curr_rec.name}' "
                        f"(surprise {score:.3f} > p99 threshold {thresh:.3f})"
                    ),
                    description=(
                        f"Component '{curr_rec.name}' ({curr_rec.ecosystem}) exhibited an "
                        f"anomalous transition relative to {self._commits_seen} historical "
                        f"lockfile commits (latent surprise={score:.4f}, threshold={thresh:.4f}, "
                        f"ratio={ratio:.2f}x)."
                    ),
                    package_name=curr_rec.name,
                    ecosystem=curr_rec.ecosystem,
                    layer="per_package_latent_drift",
                    surprise_score=round(score, 6),
                    threshold=round(thresh, 6),
                    cwe="CWE-1357",
                    evidence={
                        "manifest_path": curr_rec.manifest_path or "repo",
                        "prev_version": prev_rec.version if prev_rec else None,
                        "new_version": curr_rec.version,
                        "surprise_score": round(score, 6),
                        "threshold": round(thresh, 6),
                        "ratio": round(ratio, 4),
                        "feature_deltas": deltas,
                        "commits_seen": self._commits_seen,
                        "transitions_trained": self._transitions_trained,
                        "min_latent_std": round(self._min_latent_std, 6),
                        "backend_label": self.backend_label,
                    },
                )
            )

        findings.sort(
            key=lambda f: (
                -_SEVERITY_RANK.get(f.severity.upper(), 0),
                -(f.surprise_score or 0.0),
                f.package_name.lower(),
            )
        )
        return findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_dim": self.STATE_DIM,
            "action_dim": self.ACTION_DIM,
            "latent_dim": self.latent_dim,
            "hidden_dim": self.hidden_dim,
            "ema_decay": self.ema_decay,
            "min_lockfile_commits": self.min_lockfile_commits,
            "quantile": self.quantile,
            "seed": self.seed,
            "calibrated": self._calibrated,
            "threshold": self._threshold,
            "commits_seen": self._commits_seen,
            "transitions_trained": self._transitions_trained,
            "min_latent_std": self._min_latent_std,
            "cal_summary": dict(self._cal_summary),
            "weights": {
                "w1": self.w1,
                "b1": self.b1,
                "w2": self.w2,
                "b2": self.b2,
                "w_skip": self.w_skip,
                "t_w1": self.t_w1,
                "t_b1": self.t_b1,
                "t_w2": self.t_w2,
                "t_b2": self.t_b2,
                "wp1": self.wp1,
                "bp1": self.bp1,
                "wp2": self.wp2,
                "bp2": self.bp2,
            },
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PerPackageDriftScorer":
        obj = cls(
            latent_dim=int(data.get("latent_dim", 8)),
            hidden_dim=int(data.get("hidden_dim", 20)),
            ema_decay=float(data.get("ema_decay", 0.99)),
            min_lockfile_commits=int(data.get("min_lockfile_commits", 10)),
            quantile=float(data.get("quantile", 0.99)),
            seed=int(data.get("seed", 42)),
        )
        obj._calibrated = bool(data.get("calibrated", False))
        obj._threshold = float(data.get("threshold", 0.0))
        obj._commits_seen = int(data.get("commits_seen", 0))
        obj._transitions_trained = int(data.get("transitions_trained", 0))
        obj._min_latent_std = float(data.get("min_latent_std", 0.0))
        obj._cal_summary = dict(data.get("cal_summary") or {})
        weights = data.get("weights") or {}
        for attr in ("w1", "b1", "w2", "b2", "w_skip", "t_w1", "t_b1", "t_w2", "t_b2", "wp1", "bp1", "wp2", "bp2"):
            if attr in weights:
                setattr(obj, attr, weights[attr])
        return obj


# ---------------------------------------------------------------------------
# Read-Only Git Runner & Repository Manifest Discovery
# ---------------------------------------------------------------------------


def run_git_readonly(
    repo_path: Path,
    args: Sequence[str],
    *,
    timeout: float = 15.0,
) -> Tuple[int, str, str]:
    """
    Executes a strictly read-only git command with shell=False, DEVNULL stdin,
    no pager, fsmonitor disabled, and CREATE_NO_WINDOW on Windows.
    """
    if not args:
        raise ValueError("git args must be non-empty")
    subcommand = str(args[0]).strip()
    if subcommand not in _READ_ONLY_GIT_SUBCOMMANDS:
        raise ValueError(f"Refusing non-read-only git subcommand: {subcommand!r}")

    cmd = [
        "git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(repo_path),
        *list(args),
    ]
    kwargs: Dict[str, Any] = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": timeout,
    }
    if os.name == "nt":
        kwargs["creationflags"] = _CREATE_NO_WINDOW

    try:
        proc = subprocess.run(cmd, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return (1, "", str(exc))

    stdout_text = (proc.stdout or b"").decode("utf-8", errors="ignore")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="ignore")
    return (int(proc.returncode), stdout_text, stderr_text)


def _is_excluded_relpath(rel_posix: str) -> bool:
    parts = [p for p in rel_posix.replace("\\", "/").split("/") if p]
    return any(part in _EXCLUDED_DIR_NAMES for part in parts[:-1])


def _classify_manifest_relpath(rel_posix: str) -> Optional[str]:
    if _is_excluded_relpath(rel_posix):
        return None
    name = rel_posix.rsplit("/", 1)[-1]
    lower = name.lower()
    if lower == "package-lock.json":
        return "package_lock"
    if lower == "package.json":
        return "package_json"
    if lower == "cargo.lock":
        return "cargo_lock"
    if lower == "cargo.toml":
        return "cargo_toml"
    if lower == "build.rs":
        return "build_rs"
    if lower.endswith(".txt") and (
        lower.startswith("requirements") or lower.startswith("constraints")
    ):
        return "requirements"
    if lower.endswith(".cdx.json") or lower in ("bom.json", "sbom.json"):
        return "cyclonedx"
    return None


def _build_snapshot_from_blobs(
    classified_files: Mapping[str, List[str]],
    read_blob: Any,
    *,
    commit_sha: Optional[str] = None,
    commit_timestamp: Optional[str] = None,
) -> SbomSnapshot:
    """Parses a set of classified manifest paths using `read_blob(rel_posix) -> Optional[str]`."""
    records: Dict[str, DependencyRecord] = {}
    manifest_paths: List[str] = []

    def _add_all(recs: Iterable[DependencyRecord]) -> None:
        for r in recs:
            key = r.canonical_key
            records[key] = _merge_record(records[key], r) if key in records else r

    # 1. Cargo.toml + build.rs metadata map (maps directory -> crate name, licenses, build scripts)
    cargo_licenses: Dict[str, str] = {}
    build_rs_packages: Set[str] = set()
    dir_to_crate: Dict[str, str] = {}

    for toml_path in sorted(classified_files.get("cargo_toml", [])):
        txt = read_blob(toml_path)
        if not txt:
            continue
        crate_name, lic, has_build = parse_cargo_toml_metadata(txt)
        parent_dir = toml_path.rsplit("/", 1)[0] if "/" in toml_path else ""
        if crate_name:
            dir_to_crate[parent_dir] = crate_name
            if lic:
                cargo_licenses[crate_name.lower()] = lic
            if has_build:
                build_rs_packages.add(crate_name.lower())

    root_has_unmapped_build_rs = False
    for brs_path in sorted(classified_files.get("build_rs", [])):
        parent_dir = brs_path.rsplit("/", 1)[0] if "/" in brs_path else ""
        crate = dir_to_crate.get(parent_dir)
        if not crate:
            if parent_dir:
                crate = parent_dir.rsplit("/", 1)[-1]
            else:
                crate = "root-crate"
                root_has_unmapped_build_rs = True
        build_rs_packages.add(crate.lower())
        manifest_paths.append(brs_path)

    # 2. Cargo.lock
    cargo_locks = sorted(classified_files.get("cargo_lock", []))
    for lock_path in cargo_locks:
        txt = read_blob(lock_path)
        if not txt:
            continue
        manifest_paths.append(lock_path)
        parsed_cargo = parse_cargo_lock(
            txt,
            manifest_path=lock_path,
            build_rs_packages=build_rs_packages,
            cargo_licenses=cargo_licenses,
        )
        if root_has_unmapped_build_rs and not any(r.has_install_or_build_hook for r in parsed_cargo):
            local_crates = [r for r in parsed_cargo if not r.source_url]
            if local_crates:
                for lc in local_crates:
                    lc.has_install_or_build_hook = True
                    lc.hook_details = tuple(sorted(set(lc.hook_details) | {"build.rs"}))
            else:
                parsed_cargo.append(
                    DependencyRecord(
                        name="root-crate",
                        version="0.0.0",
                        ecosystem="cargo",
                        source_url="",
                        is_unpinned_or_git=False,
                        has_install_or_build_hook=True,
                        license_id="",
                        direct_dep_count=0,
                        manifest_path="build.rs",
                        hook_details=("build.rs",),
                    )
                )
        _add_all(parsed_cargo)

    # If a repo has Cargo.toml + build.rs but no Cargo.lock yet, still emit the workspace crate record
    if not cargo_locks and (dir_to_crate or build_rs_packages):
        for parent_dir, crate_name in sorted(dir_to_crate.items()):
            has_b = crate_name.lower() in build_rs_packages
            _add_all(
                [
                    DependencyRecord(
                        name=crate_name,
                        version="0.0.0",
                        ecosystem="cargo",
                        source_url="",
                        is_unpinned_or_git=False,
                        has_install_or_build_hook=has_b,
                        license_id=cargo_licenses.get(crate_name.lower(), ""),
                        direct_dep_count=0,
                        manifest_path=f"{parent_dir}/Cargo.toml".lstrip("/"),
                        hook_details=("build.rs",) if has_b else (),
                    )
                ]
            )

    # 3. package-lock.json + sibling package.json
    pkg_json_by_dir: Dict[str, Tuple[str, str]] = {}
    for pj_path in sorted(classified_files.get("package_json", [])):
        txt = read_blob(pj_path)
        if txt:
            parent_dir = pj_path.rsplit("/", 1)[0] if "/" in pj_path else ""
            pkg_json_by_dir[parent_dir] = (pj_path, txt)

    consumed_pkg_json_dirs: Set[str] = set()
    for pl_path in sorted(classified_files.get("package_lock", [])):
        txt = read_blob(pl_path)
        if not txt:
            continue
        manifest_paths.append(pl_path)
        parent_dir = pl_path.rsplit("/", 1)[0] if "/" in pl_path else ""
        sibling_pj = pkg_json_by_dir.get(parent_dir)
        pj_txt = sibling_pj[1] if sibling_pj else None
        if sibling_pj:
            consumed_pkg_json_dirs.add(parent_dir)
            manifest_paths.append(sibling_pj[0])
        _add_all(
            parse_package_lock(
                txt,
                manifest_path=pl_path,
                package_json_content=pj_txt,
            )
        )

    for parent_dir, (pj_path, pj_txt) in sorted(pkg_json_by_dir.items()):
        if parent_dir in consumed_pkg_json_dirs:
            continue
        manifest_paths.append(pj_path)
        root_rec, dep_recs = parse_package_json(pj_txt, manifest_path=pj_path)
        if root_rec is not None:
            _add_all([root_rec])
        _add_all(dep_recs)

    # 4. requirements*.txt
    for req_path in sorted(classified_files.get("requirements", [])):
        txt = read_blob(req_path)
        if not txt:
            continue
        manifest_paths.append(req_path)
        _add_all(parse_requirements_txt(txt, manifest_path=req_path))

    # 5. CycloneDX JSON
    for cdx_path in sorted(classified_files.get("cyclonedx", [])):
        txt = read_blob(cdx_path)
        if not txt:
            continue
        recs = parse_cyclonedx_json(txt, manifest_path=cdx_path)
        if recs:
            manifest_paths.append(cdx_path)
            _add_all(recs)

    return SbomSnapshot(
        records=records,
        commit_sha=commit_sha,
        commit_timestamp=commit_timestamp,
        manifest_paths=sorted(set(manifest_paths)),
    )


def _snapshots_equal(a: SbomSnapshot, b: SbomSnapshot) -> bool:
    if len(a.records) != len(b.records):
        return False
    for key, rec_a in a.records.items():
        rec_b = b.records.get(key)
        if rec_b is None or _record_changed(rec_a, rec_b):
            return False
    return True


class SbomDriftGuard:
    """
    Hybrid Deterministic + Per-Package Git-History SBOM Diff Guard.

    Inspects working-tree dependency manifests/SBOMs alongside read-only `git log`
    history, executing Layer 1 deterministic supply-chain diff rules unconditionally
    and activating Layer 2 per-package EMA-JEPA latent drift scoring strictly when
    `>= min_lockfile_commits` real historical lockfile commits exist.
    """

    def __init__(
        self,
        *,
        known_popular: Optional[Union[Mapping[str, Iterable[str]], Iterable[str]]] = None,
        quantile: float = 0.99,
        seed: int = 42,
        max_workers: Optional[int] = None,
        use_numpy: Optional[bool] = None,
    ) -> None:
        self.known_popular = known_popular
        self.quantile = float(quantile)
        self.seed = int(seed)
        cpu = os.cpu_count() or 4
        self.max_workers = max(1, min(8, int(max_workers or cpu)))
        self.use_numpy = use_numpy
        self.last_scorer: Optional[PerPackageDriftScorer] = None

    def _load_working_tree_snapshot(self, repo_path: Path) -> SbomSnapshot:
        classified: Dict[str, List[str]] = {}
        max_file_bytes = 25 * 1024 * 1024

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = sorted(d for d in dirs if d not in _EXCLUDED_DIR_NAMES)
            for fname in sorted(files):
                full_path = Path(root) / fname
                try:
                    rel_posix = full_path.relative_to(repo_path).as_posix()
                except ValueError:
                    continue
                kind = _classify_manifest_relpath(rel_posix)
                if kind is None:
                    continue
                try:
                    if full_path.stat().st_size > max_file_bytes:
                        continue
                except OSError:
                    continue
                classified.setdefault(kind, []).append(rel_posix)

        def _read_disk(rel_posix: str) -> Optional[str]:
            target = (repo_path / rel_posix).resolve()
            try:
                target.relative_to(repo_path.resolve())
            except ValueError:
                return None
            try:
                raw = target.read_bytes()
                return raw.decode("utf-8", errors="ignore")
            except OSError:
                return None

        return _build_snapshot_from_blobs(classified, _read_disk)

    def _is_git_repo(self, repo_path: Path) -> bool:
        if (repo_path / ".git").exists():
            return True
        rc, out, _ = run_git_readonly(repo_path, ["rev-parse", "--is-inside-work-tree"])
        return rc == 0 and out.strip().lower() == "true"

    def _list_lockfile_commits(
        self, repo_path: Path, max_commits: int
    ) -> List[Tuple[str, str]]:
        rc, out, _ = run_git_readonly(
            repo_path,
            [
                "log",
                f"-n{max(1, int(max_commits))}",
                "--format=%H\t%cI",
                "--",
                *_GIT_MANIFEST_PATHSPECS,
            ],
        )
        if rc != 0 or not out.strip():
            return []
        commits: List[Tuple[str, str]] = []
        for line in out.splitlines():
            parts = line.strip().split("\t", 1)
            if not parts:
                continue
            sha = parts[0].strip()
            if not _SHA_HEX_RX.match(sha):
                continue
            ts = parts[1].strip() if len(parts) > 1 else ""
            commits.append((sha, ts))
        # Reverse to chronological order (oldest -> newest)
        commits.reverse()
        return commits

    def _load_commit_snapshot(
        self, repo_path: Path, commit_sha: str, commit_ts: str
    ) -> SbomSnapshot:
        rc, tree_out, _ = run_git_readonly(
            repo_path, ["ls-tree", "-r", "--name-only", commit_sha]
        )
        if rc != 0 or not tree_out.strip():
            return SbomSnapshot(commit_sha=commit_sha, commit_timestamp=commit_ts)

        classified: Dict[str, List[str]] = {}
        for line in tree_out.splitlines():
            rel_posix = line.strip().replace("\\", "/")
            if not rel_posix or rel_posix.startswith("-"):
                continue
            kind = _classify_manifest_relpath(rel_posix)
            if kind is not None:
                classified.setdefault(kind, []).append(rel_posix)

        blob_cache: Dict[str, Optional[str]] = {}

        def _read_commit_blob(rel_posix: str) -> Optional[str]:
            if rel_posix in blob_cache:
                return blob_cache[rel_posix]
            rc_b, out_b, _ = run_git_readonly(
                repo_path, ["show", f"{commit_sha}:{rel_posix}"]
            )
            val = out_b if rc_b == 0 else None
            blob_cache[rel_posix] = val
            return val

        return _build_snapshot_from_blobs(
            classified,
            _read_commit_blob,
            commit_sha=commit_sha,
            commit_timestamp=commit_ts,
        )

    def _load_git_history_snapshots(
        self, repo_path: Path, max_commits: int
    ) -> List[SbomSnapshot]:
        commits = self._list_lockfile_commits(repo_path, max_commits=max_commits)
        if not commits:
            return []

        if len(commits) == 1 or self.max_workers <= 1:
            return [
                self._load_commit_snapshot(repo_path, sha, ts)
                for sha, ts in commits
            ]

        ordered_results: List[Optional[SbomSnapshot]] = [None] * len(commits)
        workers = min(self.max_workers, len(commits))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(self._load_commit_snapshot, repo_path, sha, ts): idx
                for idx, (sha, ts) in enumerate(commits)
            }
            for fut in as_completed(future_map):
                idx = future_map[fut]
                ordered_results[idx] = fut.result()

        return [snap for snap in ordered_results if snap is not None]

    def scan_repository(
        self,
        repo_path: Union[str, Path],
        *,
        max_commits: int = 30,
        min_lockfile_commits: int = 10,
    ) -> Dict[str, Any]:
        """
        Scans a repository's dependency manifests and read-only git history using
        Layer 1 (deterministic rules) and, when `>= min_lockfile_commits` real
        lockfile commits exist, Layer 2 (per-package EMA-JEPA latent drift scorer).
        """
        root = Path(repo_path)
        if not root.exists() or not root.is_dir():
            return {
                "status": "error",
                "error": f"Repository path does not exist or is not a directory: {repo_path}",
                "repo_path": str(root),
                "ecosystems": [],
                "commits_analyzed": 0,
                "layer2_active": False,
                "cold_start_active": True,
                "total_findings": 0,
                "findings": [],
                "read_only_git": True,
            }

        resolved_root = root.resolve()
        current_snapshot = self._load_working_tree_snapshot(resolved_root)

        history_snapshots: List[SbomSnapshot] = []
        if self._is_git_repo(resolved_root):
            history_snapshots = self._load_git_history_snapshots(
                resolved_root, max_commits=max_commits
            )

        commits_analyzed = len(history_snapshots)
        has_uncommitted_changes = False
        latest_baseline: Optional[SbomSnapshot] = None
        latest_candidate: SbomSnapshot = current_snapshot
        training_snapshots: List[SbomSnapshot] = []

        if commits_analyzed >= 1:
            head_snap = history_snapshots[-1]
            if not _snapshots_equal(head_snap, current_snapshot):
                has_uncommitted_changes = True
                latest_baseline = head_snap
                latest_candidate = current_snapshot
                training_snapshots = history_snapshots
            elif commits_analyzed >= 2:
                latest_baseline = history_snapshots[-2]
                latest_candidate = head_snap
                # Strictly exclude candidate commit from training/calibration (zero leakage)
                training_snapshots = history_snapshots[:-1]
            else:
                latest_baseline = None
                latest_candidate = current_snapshot
                training_snapshots = []

        # Layer 1 — Always active deterministic high-precision supply-chain rules
        layer1_findings = evaluate_snapshot_diff(
            latest_baseline,
            latest_candidate,
            known_popular=self.known_popular,
        )

        # Layer 2 — Strictly gated per-package EMA-JEPA latent drift scorer
        scorer = PerPackageDriftScorer(
            min_lockfile_commits=min_lockfile_commits,
            quantile=self.quantile,
            seed=self.seed,
            use_numpy=self.use_numpy,
        )
        cal_meta = scorer.fit_from_snapshots(
            training_snapshots,
            total_lockfile_commits=commits_analyzed,
        )
        self.last_scorer = scorer

        layer2_findings: List[SbomDriftFinding] = []
        if scorer.calibrated and latest_baseline is not None:
            layer2_findings = scorer.score_snapshot_diff(latest_baseline, latest_candidate)

        all_findings = layer1_findings + layer2_findings
        all_findings.sort(
            key=lambda f: (
                -_SEVERITY_RANK.get(f.severity.upper(), 0),
                0 if f.layer == "deterministic_rule" else 1,
                f.rule_id,
                f.package_name.lower(),
            )
        )

        ecosystems = sorted(
            set(latest_candidate.ecosystems)
            | (set(latest_baseline.ecosystems) if latest_baseline is not None else set())
        )
        status = "ok" if (latest_candidate.manifest_paths or commits_analyzed > 0) else "no_manifests"

        return {
            "status": status,
            "repo_path": str(resolved_root),
            "ecosystems": ecosystems,
            "commits_analyzed": commits_analyzed,
            "layer2_active": bool(scorer.calibrated),
            "cold_start_active": bool(scorer.cold_start_active),
            "total_findings": len(all_findings),
            "layer1_findings_count": len(layer1_findings),
            "layer2_findings_count": len(layer2_findings),
            "packages_analyzed": len(latest_candidate.records),
            "manifests_analyzed": list(latest_candidate.manifest_paths),
            "has_uncommitted_manifest_changes": has_uncommitted_changes,
            "layer2_calibration": cal_meta,
            "read_only_git": True,
            "findings": [f.to_finding_dict() for f in all_findings],
        }


__all__ = [
    "DEFAULT_POPULAR_PACKAGES",
    "DependencyRecord",
    "PerPackageDriftScorer",
    "SbomDriftFinding",
    "SbomDriftGuard",
    "SbomSnapshot",
    "canonical_package_name",
    "classify_license",
    "evaluate_snapshot_diff",
    "extract_component_transition_vectors",
    "extract_registry_origin",
    "is_official_registry_origin",
    "is_unpinned_or_git_source",
    "levenshtein_distance",
    "parse_cargo_lock",
    "parse_cargo_toml_metadata",
    "parse_cyclonedx_json",
    "parse_package_json",
    "parse_package_lock",
    "parse_requirements_txt",
    "parse_semver",
    "run_git_readonly",
]
