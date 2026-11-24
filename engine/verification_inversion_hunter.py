"""
Static Verification-Inversion Security Auditor (`engine/verification_inversion_hunter.py`).

Adapts the five formal verification mechanisms from `google-deepmind/code-verification`
by inverting defensive proof-checking primitives into deterministic static AST and
forward/reverse call-graph vulnerability passes:

  1. Pass 1 (`DEV_INVERSION` — `DEVIATIONS.md` Inversion):
     - `INV-DEV-UNBOUNDED-LOOP` (CWE-834): Unbounded `while True` / `loop` / `for (;;)`
       rejection-sampling or stream/buffer parsing loops reachable from untrusted
       entry points without an explicit step counter, limit, or deadline.
     - `INV-DEV-REACHABLE-PANIC` (CWE-248): Reverse-BFS reachability from public entry
       points to panic/abort constructs (`.unwrap()`, `.expect()`, `panic!()`, or
       unclamped `Vec::with_capacity`) operating on untrusted input parameters.
     - `INV-DEV-CRYPTO-DOMAIN-SEP` (CWE-327): HKDF / KDF `expand` / `derive` calls
       with empty domain-separation `info` labels (`info=b""`, `info=""`, `&[]`).

  2. Pass 2 (`RULE5_TRUST_CLOSURE` — `TrustedClosure.lean` Rule 5 Inversion):
     - Traverses the forward call graph (`adj`) from security-enforcement gates
       (`verify_*`, `check_*`, `authorize*`, `validate_*`, `is_allowed*`, `enforce_*`,
       `authenticate*`, `eval_policy*`) to inspect every helper in the gate's
       transitive callee closure:
     - `INV-RULE5-FAIL-OPEN` (CWE-636): Broad exception/error handler inside a security
       gate's transitive closure returning a permissive decision (`return True`,
       `return true`, `Ok(true)`, `unwrap_or(true)`).
     - `INV-RULE5-UNCANONICAL-PATH` (CWE-22): Prefix containment check (`starts_with`,
       `startsWith`) inside a path/sandbox gate's transitive closure without any
       canonicalization call (`realpath`, `canonicalize`, `resolve`, `normpath`,
       `abspath`) in the closure.
     - `INV-RULE5-UNCHECKED-FFI` (CWE-252): Discarded OS/FFI security syscall return
       code inside a security gate's transitive closure.

  3. Pass 3 (`COMPARATOR_CONTRACT` — `comparator/` Challenge-vs-Solution Inversion):
     - Compares a handler's AST/CFG guard branches (`Solution`) against normative
       security contract checklists (`Challenge`):
     - `INV-COMP-MISSING-CLAIM` (CWE-345): JWT/OIDC verification handler that omits
       `audience`/`aud` or `issuer`/`iss` verification (or disables `verify_exp` /
       `verify_aud` / `verify_signature`), reporting exact `missing_predicates`.
     - `INV-COMP-WEAK-FRAMING-GUARD` (CWE-444): HTTP request framing handler inspecting
       both `Content-Length` and `Transfer-Encoding` without rejecting concurrent presence.

  4. Pass 4 (`REFINEMENT_GAP` — `Symbolic/` vs `Computational/` Refinement Gap Inversion):
     - `INV-REFINE-PATH-DECODE-SPLIT` (CWE-436): Authorization or filter check on raw
       undecoded URL/path followed by percent-decoding (`unquote`, `decodeURIComponent`,
       `QueryUnescape`, `percent_decode`) in the same module or forward call chain.
     - `INV-REFINE-DUPLICATE-KEY` (CWE-436): Header or parameter dictionary folding loop
       that silently overwrites duplicate keys without rejecting or normalizing ambiguity.

  5. Pass 5 (`RELEASE_ELISION` — `arm64-semantics` Compiler/Runtime Elision Inversion):
     - `INV-ELISION-DEBUG-ASSERT` (CWE-617): Security-critical authorization, permission,
       confinement, or bounds checks placed inside `debug_assert!()` (Rust), `assert ...`
       (Python, stripped under `-O`), or `assert(...)` (C/C++, stripped under `NDEBUG`).
     - `INV-ELISION-NON-CT-SECRET` (CWE-208): Direct `==` / `!=` / `===` equality on
       secrets, HMACs, signatures, or API tokens instead of constant-time comparison.
     - `INV-ELISION-DEAD-STORE-ZERO` (CWE-14): Plain `memset(secret, 0, ...)` or manual
       zero-assignment loop on secret buffers without `zeroize`, `explicit_bzero`,
       `SecureZeroMemory`, `memset_s`, or `write_volatile`.

Safety invariants:
  - Strictly static, deterministic, and CLI-only (zero GUI imports, zero `shell=True`,
    zero network sockets, zero target-repository mutations).
  - Every finding is truthfully labeled at `poe_level = 1`
    (`verification_status = "LEAD_PASSIVE_CORRELATION"`, `finding_tier = "MANUAL_REVIEW_LEAD"`).
"""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from engine.call_graph_slicer import CallEdge, CallGraphContext, CallGraphSlicer, SymbolNode

_TEST_DIR_NAMES = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "mocks", "benches", "examples"}
)
_TEST_FILE_RE = re.compile(
    r"(^test_.*|\.(test|spec)\.[A-Za-z0-9]+$|_test\.[A-Za-z0-9]+$|Test\.[A-Za-z0-9]+$|^conftest\.py$)",
    re.IGNORECASE,
)
_COMMENT_LINE_RE = re.compile(r"^\s*(///|//!|//|#|/\*|\*|--)")

# Security gate naming conventions for Pass 2 (Inverted Rule 5 Transitive Trust-Closure)
_SECURITY_GATE_NAME_RE = re.compile(
    r"^(verify|check|authorize|validate|is_allowed|is_authorized|is_valid|is_safe|enforce|authenticate|eval_policy|evaluate_policy|guard|allow_|can_access|require_auth|require_role|check_permission|verify_token|verify_jwt|validate_path|check_path|is_subpath|within_root)[A-Za-z0-9_]*$",
    re.IGNORECASE,
)
_PATH_GATE_NAME_RE = re.compile(
    r"(path|sandbox|confin|root|dir|file|subpath|jail|mount|traversal)",
    re.IGNORECASE,
)

# Pass 1 patterns (DEV-* Inversion)
_UNBOUNDED_LOOP_HEAD_RE = re.compile(
    r"(\bwhile\s+(?:True|true|1)\b|\bloop\s*\{|\bfor\s*\(\s*;\s*;\s*\))"
)
_LOOP_READ_OR_SAMPLE_RE = re.compile(
    r"(recv|read|readline|read_exact|next_chunk|sample|xof|squeeze|accept|poll|parse_next|step|retry|fetch_next)",
    re.IGNORECASE,
)
_LOOP_STEP_BOUND_RE = re.compile(
    r"\b(max_iter|max_steps|max_attempts|max_retries|max_rounds|max_chunks|max_loops|max_bytes|step_limit|iter_count|attempts|retries|deadline|timeout|budget|remaining|limit|steps\s*\+=|attempts\s*\+=|count\s*\+=|i\s*\+=)\b",
    re.IGNORECASE,
)
_RUST_PANIC_SINK_RE = re.compile(
    r"(\.(?:unwrap|expect)\s*\(|\bpanic!\s*\(|\bVec::with_capacity\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*\))"
)
_HKDF_CALL_RE = re.compile(
    r"\b(HKDF|Hkdf|hkdf|hkdf_expand|hkdfExpand|derive_key|expand_key)\b"
)
_EMPTY_INFO_RE = re.compile(
    r"""(\binfo\s*=\s*(?:b['"]{2}|['"]{2}|None)\b|\.expand\s*\(\s*&\s*\[\s*\]|hkdf(?:_expand|Expand)\s*\([^,\n]+,[^,\n]+,\s*(?:b['"]{2}|['"]{2}|&\s*\[\s*\]))"""
)

# Pass 2 patterns (Inverted Rule 5 Transitive Trust-Closure)
_CATCH_OR_ERR_RE = re.compile(
    r"(\bexcept\b[^:]*:|\bcatch\s*(?:\([^)]*\))?\s*\{|\bErr\s*\([^)]*\)\s*=>|\.unwrap_or\s*\(\s*true\s*\))"
)
_PERMISSIVE_RETURN_RE = re.compile(
    r"(\breturn\s+(?:True|true)\b|\bOk\s*\(\s*true\s*\)|\.unwrap_or\s*\(\s*true\s*\)|\ballow(?:ed)?\s*=\s*(?:True|true)\b)"
)
_PATH_PREFIX_CHECK_RE = re.compile(
    r"(\.(?:startswith|starts_with|startsWith)\s*\(|\bos\.path\.commonprefix\s*\()"
)
_PATH_CANONICALIZE_RE = re.compile(
    r"(\b(?:realpath|canonicalize|resolve|normpath|abspath|commonpath|is_relative_to|filepath\.Clean|filepath\.EvalSymlinks|Path::canonicalize|fs::canonicalize)\b)"
)
_FFI_SECURITY_CALL_RE = re.compile(
    r"^\s*(SetNamedSecurityInfo[AW]?|SetSecurityInfo|AssignProcessToJobObject|CreateAppContainerProfile|SetTokenInformation|AdjustTokenPrivileges|setuid|setgid|seteuid|setresuid|chroot|seccomp_load|prctl)\s*\("
)

# Pass 3 patterns (Inverted Comparator Predicate-vs-Contract)
_JWT_VERIFY_CALL_RE = re.compile(
    r"\b(jwt\.decode|jwt\.verify|verify_oauth2_token|verifyIdToken|verify_id_token|decode_jwt)\s*\("
)
_JWT_AUD_CHECK_RE = re.compile(
    r"""(\baudience\s*[=:]|['"]aud['"]|\.aud\b|\bverify_aud\b|\b check_aud\b|\bexpected_aud\b)""",
    re.IGNORECASE,
)
_JWT_ISS_CHECK_RE = re.compile(
    r"""(\bissuer\s*[=:]|['"]iss['"]|\.iss\b|\bverify_iss\b|\bexpected_iss\b)""",
    re.IGNORECASE,
)
_JWT_DISABLED_OPT_RE = re.compile(
    r"""(['"]verify_(?:signature|exp|aud|iss)['"]\s*:\s*False|\bverify\s*=\s*False\b|\bignoreExpiration\s*:\s*true\b)"""
)
_CL_TOKEN_RE = re.compile(r"content-length", re.IGNORECASE)
_TE_TOKEN_RE = re.compile(r"transfer-encoding", re.IGNORECASE)
_FRAMING_REJECT_RE = re.compile(
    r"(\b400\b|\braise\b|\breturn\s+(?:False|false|None|Err\b)|\breject|\bsmuggl|\bambig|\bconflict|\bboth\b)",
    re.IGNORECASE,
)

# Pass 4 patterns (Inverted Refinement Gap)
_RAW_PATH_AUTH_RE = re.compile(
    r"\b(raw_path|originalUrl|req\.url|request\.url|unparsed_uri|raw_uri)\b"
)
_PATH_DECODE_CALL_RE = re.compile(
    r"\b(unquote|unquote_plus|decodeURIComponent|decodeURI|QueryUnescape|PathUnescape|percent_decode|percent_decode_str)\s*\("
)
_HEADER_LOOP_RE = re.compile(
    r"\bfor\s+[^\n:]+\bin\s+[^\n:]*\b(?:headers|header_lines|raw_headers|lines)\b",
    re.IGNORECASE,
)
_DICT_OVERWRITE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_().']*)\s*\]\s*=\s*([^=\n].*)$"
)

# Pass 5 patterns (Inverted arm64-semantics Release/FFI Elision)
_RUST_DEBUG_ASSERT_RE = re.compile(r"\bdebug_assert(?:_eq|_ne)?!\s*\((.+)\)")
_C_ASSERT_RE = re.compile(r"^\s*assert\s*\((.+)\)\s*;")
_SECURITY_ASSERT_EXPR_RE = re.compile(
    r"(auth|admin|perm|role|allow|token|sandbox|path|root|owner|acl|sid|valid|verify|is_safe|is_allowed|in_scope|within|bound|cap|priv)",
    re.IGNORECASE,
)
_SECRET_VAR_TOKEN_RE = re.compile(
    r"^(?:expected_|computed_|provided_|received_|client_|server_|user_|header_|raw_)?(?:hmac|mac|signature|sig|digest|api_key|apikey|secret|secret_key|secret_token|auth_token|bearer_token|webhook_secret|csrf_token|access_token)(?:_hex|_bytes|_str|_val)?$",
    re.IGNORECASE,
)
_CT_COMPARE_CALL_RE = re.compile(
    r"\b(compare_digest|timingSafeEqual|ConstantTimeEq|ct_eq|ConstantTimeCompare|CRYPTO_memcmp|sodium_memcmp|constant_time_eq)\b"
)
_RAW_MEMSET_ZERO_RE = re.compile(
    r"\bmemset\s*\(\s*([A-Za-z_][A-Za-z0-9_.->]*)\s*,\s*0\s*,"
)
_RUST_MANUAL_ZERO_LOOP_RE = re.compile(
    r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+(?:&mut\s+)?([A-Za-z_][A-Za-z0-9_.]*)(?:\.iter_mut\(\))?\s*\{\s*\*[A-Za-z_][A-Za-z0-9_]*\s*=\s*0\s*;?\s*\}"
)
_SAFE_ZEROIZE_RE = re.compile(
    r"\b(zeroize|Zeroize|explicit_bzero|SecureZeroMemory|memset_s|OPENSSL_cleanse|sodium_memzero|write_volatile)\b"
)
_SECRET_BUF_NAME_RE = re.compile(
    r"(key|secret|priv|seed|nonce|password|passwd|token|master|hmac)",
    re.IGNORECASE,
)


def _is_test_rel_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/").strip("/")
    parts = [p.lower() for p in PurePosixPath(norm).parts]
    if any(p in _TEST_DIR_NAMES for p in parts[:-1]):
        return True
    fname = parts[-1] if parts else ""
    return bool(_TEST_FILE_RE.match(fname))


@dataclass
class VerificationInversionFinding:
    rule_id: str
    primitive: str
    severity: str
    cwe: str
    file_path: str
    line_number: int
    title: str
    description: str
    evidence: str
    remediation: str
    call_chain: List[str] = field(default_factory=list)
    missing_predicates: List[str] = field(default_factory=list)
    counterexample_witness: str = ""
    counterexample_trace: List[str] = field(default_factory=list)
    violated_invariant_formula: str = ""
    poe_level: int = 1
    verification_status: str = "LEAD_PASSIVE_CORRELATION"
    finding_tier: str = "MANUAL_REVIEW_LEAD"
    scanner: str = "VerificationInversionHunter"
    category: str = "verification_inversion"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _synthesize_counterexample_trace_and_formula(f: VerificationInversionFinding) -> Tuple[List[str], str]:
    """
    Synthesizes a 3-step counterexample execution trace and formal invariant formula
    for `VerificationInversionFinding`.
    """
    rid = f.rule_id
    loc = f"{Path(f.file_path).name}:{f.line_number}"
    chain_str = " -> ".join(f.call_chain) if f.call_chain else loc
    if rid == "INV-COMP-ECHO-METHOD-CRED-LEAK":
        return (
            [
                f"1. [Entry] Untrusted request `TRACE / HTTP/1.1` enters `{chain_str}` with `filterRequest == undefined`.",
                f"2. [Inverted Guard @ {loc}] Method check is skipped when `filterRequest` is unset; proxy injects outbound `Authorization`/`Cookie` headers.",
                "3. [Sink] Upstream `message/http` response echoes injected secret headers back to sandboxed caller.",
            ],
            "forall req: method(req) in {TRACE, TRACK} => Denied(req) || Stripped(AuthHeaders(req))",
        )
    if rid == "INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS":
        return (
            [
                f"1. [Entry] Client sends TLS ClientHello with outer record header `16 03 04 ...` (`buf[2] = 0x04`).",
                f"2. [Inverted Guard @ {loc}] `{chain_str}` requires `buf[2] <= 0x03` and returns `false` (not a ClientHello).",
                "3. [Sink] Proxy falls back to an uninspected opaque TCP tunnel, bypassing TLS MITM and `filterRequest`.",
            ],
            "forall buf: (buf[0] == 0x16 && buf[1] == 0x03) => ClassifiedAsTLSClientHello(buf)",
        )
    if rid == "INV-REFINE-TLS-FRAGMENT-SNI-BYPASS":
        return (
            [
                f"1. [Entry] Client fragments TLS ClientHello across two TLS records split before `extensions_length`.",
                f"2. [Inverted Guard @ {loc}] `{chain_str}` checks 16-bit record length `5 + readUInt16BE(3)` instead of 24-bit Handshake length `9 + readUIntBE(6, 3)`.",
                "3. [Sink] Parser returns `{ kind: 'absent' }` instead of `{ kind: 'unreadable' }`.",
            ],
            "forall rec: HandshakeEnd(9 + uint24(rec[6..9])) > RecordEnd(5 + uint16(rec[3..5])) => Status == UNREADABLE",
        )
    if rid == "INV-REFINE-CASE-INSENSITIVE-FS-POLICY":
        return (
            [
                f"1. [Entry] Sandbox opens `/workspace/.Git/hooks/pre-commit` on default case-insensitive macOS APFS.",
                f"2. [Inverted Guard @ {loc}] Seatbelt profile in `{chain_str}` matches case-sensitive `(literal \".../.git/hooks\")` without `(?i)`.",
                "3. [Sink] macOS kernel evaluates Seatbelt rule case-sensitively (no match), while APFS resolves `.Git` to `.git`.",
            ],
            "forall p1, p2: APFS_ResolvesSameNode(p1, p2) => (SeatbeltDeny(p1) <=> SeatbeltDeny(p2))",
        )
    if rid == "INV-ALG-MISSING-SHELL-STARTUP-DENY":
        return (
            [
                f"1. [Entry] Sandboxed process writes payload to `~/.zshenv`.",
                f"2. [Inverted Guard @ {loc}] Mandatory startup deny list blocks `.zshrc` and `.bashrc` but omits `.zshenv`.",
                "3. [Sink] Next non-interactive `zsh -c` invocation sources `~/.zshenv` automatically outside the sandbox.",
            ],
            "forall f in ShellAutoSourcedFiles(zsh, bash): f in MandatoryWriteDenySet",
        )
    return (
        [
            f"1. [Entry] Input reaches `{chain_str}`.",
            f"2. [Inversion @ {loc}] {f.title} ({f.evidence[:100]}).",
            f"3. [Violation] Security contract `{f.primitive}` ({f.cwe}) fails closed invariant.",
        ],
        f"forall x in Domain({chain_str}): Challenge_{f.primitive}(x) => Solution_{f.rule_id}(x)",
    )


def _synthesize_counterexample_witness(f: VerificationInversionFinding) -> str:
    """
    Synthesizes a deterministic counterexample witness expression `x` satisfying
    `Challenge(x) = Deny/Safe` while `Solution(x) = Allow/Unsafe`.
    """
    if f.counterexample_witness:
        return f.counterexample_witness
    rid = f.rule_id
    if rid == "INV-DEV-UNBOUNDED-LOOP":
        return '{"stream_input": "infinite_non_terminating_byte_sequence", "step_bound": null}'
    if rid == "INV-DEV-REACHABLE-PANIC":
        return f'{{"entry_chain": {f.call_chain!r}, "input": "malformed_or_oversized_payload_triggering_panic"}}'
    if rid == "INV-DEV-CRYPTO-DOMAIN-SEP":
        return '{"kdf_info": "", "collision": "Subkey(ctx_A, info=\'\') == Subkey(ctx_B, info=\'\')"}'
    if rid == "INV-RULE5-FAIL-OPEN":
        return f'{{"closure_chain": {f.call_chain!r}, "fault_injected": "Exception/Err", "solution_decision": true, "challenge_decision": false}}'
    if rid == "INV-RULE5-UNCANONICAL-PATH":
        return '{"raw_path": "/sandbox/allowed/../../etc/shadow", "prefix_match": true, "canonical_inside_root": false}'
    if rid == "INV-RULE5-UNCHECKED-FFI":
        return '{"syscall_return": "ERROR_ACCESS_DENIED (-1)", "checked": false}'
    if rid == "INV-COMP-MISSING-CLAIM":
        return f'{{"jwt_claims": {{"sub": "attacker", "omitted_or_unverified": {f.missing_predicates!r}}}, "challenge_decision": "Reject", "solution_decision": "Accept"}}'
    if rid == "INV-COMP-WEAK-FRAMING-GUARD":
        return '{"headers": {"Content-Length": "12", "Transfer-Encoding": "chunked"}, "rfc9112_challenge": "400 Bad Request", "solution_decision": "Accepted"}'
    if rid == "INV-REFINE-PATH-DECODE-SPLIT":
        return '{"wire_path": "/public/%2e%2e/admin", "pre_decode_filter": "ALLOW", "post_decode_target": "/admin"}'
    if rid == "INV-REFINE-DUPLICATE-KEY":
        return '{"wire_headers": [["Host", "allowed.local"], ["Host", "internal.local"]], "map_folded_value": "internal.local"}'
    if rid == "INV-ELISION-DEBUG-ASSERT":
        return '{"build_profile": "release (-O / NDEBUG)", "assert_evaluated": false}'
    if rid == "INV-ELISION-NON-CT-SECRET":
        return '{"lhs_prefix": "secret[0..k]", "timing_oracle_delta_ns": "proportional_to_matching_prefix_length_k"}'
    if rid == "INV-ELISION-DEAD-STORE-ZERO":
        return '{"optimizer_pass": "DeadStoreElimination (DSE)", "residual_heap_stack_bytes": "non_zero_secret"}'
    if rid == "INV-STATE-EPOCH-ROLLBACK":
        return '{"current_epoch": 5, "replayed_epoch": 2, "monotonic_check_present": false, "resulting_epoch": 2}'
    return f'{{"rule_id": "{rid}", "primitive": "{f.primitive}"}}'


@dataclass
class VerificationInversionReport:
    repo_path: str
    files_scanned: int
    symbols_analyzed: int
    security_gates_audited: int
    findings: List[VerificationInversionFinding] = field(default_factory=list)
    pass_counts: Dict[str, int] = field(default_factory=dict)
    elapsed_sec: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "completed",
            "repo_path": self.repo_path,
            "files_scanned": self.files_scanned,
            "symbols_analyzed": self.symbols_analyzed,
            "security_gates_audited": self.security_gates_audited,
            "findings_count": len(self.findings),
            "pass_counts": dict(self.pass_counts),
            "findings": [f.to_dict() for f in self.findings],
            "elapsed_sec": round(self.elapsed_sec, 3),
        }


class VerificationInversionHunter:
    """
    Deterministic 5-pass static AST & call-graph auditor adapting inverted
    formal verification primitives from `google-deepmind/code-verification`.
    """

    def __init__(
        self,
        *,
        max_closure_depth: int = 6,
        include_tests: bool = False,
    ) -> None:
        self.max_closure_depth = max(2, int(max_closure_depth))
        self.include_tests = bool(include_tests)

    def analyze_repository(
        self,
        repo_path: Union[str, Path],
        *,
        cg_context: Optional[CallGraphContext] = None,
    ) -> VerificationInversionReport:
        t0 = time.perf_counter()
        root = Path(repo_path).resolve(strict=False)
        if cg_context is None:
            slicer = CallGraphSlicer(max_depth=self.max_closure_depth, max_slices=100)
            cg_context = slicer.build_graph_context(root)

        findings: List[VerificationInversionFinding] = []
        pass_counts: Dict[str, int] = {
            "DEV_INVERSION": 0,
            "RULE5_TRUST_CLOSURE": 0,
            "COMPARATOR_CONTRACT": 0,
            "REFINEMENT_GAP": 0,
            "RELEASE_ELISION": 0,
            "STATE_MACHINE_ORDERING": 0,
        }

        p1 = self._run_pass1_dev_inversion(root, cg_context)
        p2, gates_audited = self._run_pass2_rule5_trust_closure(root, cg_context)
        p3 = self._run_pass3_comparator_contract(root, cg_context)
        p4 = self._run_pass4_refinement_gap(root, cg_context)
        p5 = self._run_pass5_release_elision(root, cg_context)
        p6 = self._run_pass6_state_machine_ordering(root, cg_context)

        for batch, key in (
            (p1, "DEV_INVERSION"),
            (p2, "RULE5_TRUST_CLOSURE"),
            (p3, "COMPARATOR_CONTRACT"),
            (p4, "REFINEMENT_GAP"),
            (p5, "RELEASE_ELISION"),
            (p6, "STATE_MACHINE_ORDERING"),
        ):
            pass_counts[key] = len(batch)
            findings.extend(batch)

        # Deduplicate by (rule_id, normalized file_path, line_number) and synthesize counterexample witnesses
        deduped: List[VerificationInversionFinding] = []
        seen: Set[Tuple[str, str, int]] = set()
        for f in findings:
            if not f.counterexample_witness:
                f.counterexample_witness = _synthesize_counterexample_witness(f)
            if not f.counterexample_trace or not f.violated_invariant_formula:
                trace_steps, inv_formula = _synthesize_counterexample_trace_and_formula(f)
                if not f.counterexample_trace:
                    f.counterexample_trace = trace_steps
                if not f.violated_invariant_formula:
                    f.violated_invariant_formula = inv_formula
            key = (f.rule_id, f.file_path.replace("\\", "/").lower(), int(f.line_number))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        deduped.sort(key=lambda x: (sev_rank.get(x.severity, 9), x.file_path.lower(), x.line_number))

        return VerificationInversionReport(
            repo_path=str(root),
            files_scanned=len(cg_context.parsed_files),
            symbols_analyzed=len(cg_context.symbols_by_id),
            security_gates_audited=gates_audited,
            findings=deduped,
            pass_counts=pass_counts,
            elapsed_sec=time.perf_counter() - t0,
        )

    @staticmethod
    def _symbol_body_lines(pf: Any, sym: SymbolNode) -> List[Tuple[int, str]]:
        start = max(1, int(sym.start_line))
        end = min(len(pf.lines), max(start, int(sym.end_line)))
        return [(ln_no, pf.lines[ln_no - 1]) for ln_no in range(start, end + 1)]

    def _build_entry_reachability(
        self,
        cg_context: CallGraphContext,
    ) -> Dict[str, List[str]]:
        """
        Computes shortest call-chain paths from public/untrusted entry points
        (`entry_point` role or `source_indicators`) to every reachable symbol
        within `self.max_closure_depth` hops.
        """
        reach: Dict[str, List[str]] = {}
        queue: List[str] = []
        in_deg: Dict[str, int] = {sid: 0 for sid in cg_context.symbols_by_id}
        for elist in cg_context.adj.values():
            for e in elist:
                if e.callee_id in in_deg:
                    in_deg[e.callee_id] += 1

        for sid, sym in cg_context.symbols_by_id.items():
            if not self.include_tests and _is_test_rel_path(sym.file_path):
                continue
            if (
                "entry_point" in sym.roles
                or bool(sym.route_pattern)
                or (bool(sym.source_indicators) and in_deg.get(sid, 0) == 0)
            ):
                reach[sid] = [sym.name]
                queue.append(sid)

        # Fallback: if no explicit route decorators exist, seed root callers (in-degree == 0)
        # taking request/buf/raw/token/input/packet/seed parameters as entry points.
        if not queue:
            _UNTRUSTED_PARAM_RE = re.compile(
                r"(req|request|buf|buffer|raw|data|payload|packet|frame|input|header|token|seed|msg|body|query|path|url)",
                re.IGNORECASE,
            )
            for sid, sym in cg_context.symbols_by_id.items():
                if not self.include_tests and _is_test_rel_path(sym.file_path):
                    continue
                if in_deg.get(sid, 0) > 0:
                    continue
                pf = cg_context.parsed_files.get(sym.file_path)
                if pf is None:
                    continue
                sig_line = pf.lines[max(0, sym.start_line - 1)] if pf.lines else ""
                if _UNTRUSTED_PARAM_RE.search(sig_line):
                    reach[sid] = [sym.name]
                    queue.append(sid)

        q_idx = 0
        while q_idx < len(queue):
            cur_sid = queue[q_idx]
            q_idx += 1
            cur_chain = reach[cur_sid]
            if len(cur_chain) >= self.max_closure_depth:
                continue
            for edge in cg_context.adj.get(cur_sid, ()):
                nxt_sid = edge.callee_id
                if nxt_sid not in reach and nxt_sid in cg_context.symbols_by_id:
                    nxt_sym = cg_context.symbols_by_id[nxt_sid]
                    if not self.include_tests and _is_test_rel_path(nxt_sym.file_path):
                        continue
                    reach[nxt_sid] = cur_chain + [nxt_sym.name]
                    queue.append(nxt_sid)
        return reach

    # =========================================================================
    # Pass 1: DEV-* Inversion (Unbounded Loops, Reachable Panics, HKDF Info)
    # =========================================================================
    def _run_pass1_dev_inversion(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> List[VerificationInversionFinding]:
        out: List[VerificationInversionFinding] = []
        reach = self._build_entry_reachability(cg_context)

        for sid, sym in cg_context.symbols_by_id.items():
            if not self.include_tests and _is_test_rel_path(sym.file_path):
                continue
            pf = cg_context.parsed_files.get(sym.file_path)
            if pf is None:
                continue
            abs_fp = str((root / sym.file_path).resolve(strict=False))
            body_lines = self._symbol_body_lines(pf, sym)
            body_text = "\n".join(text for _, text in body_lines if not _COMMENT_LINE_RE.match(text))
            chain = reach.get(sid)

            # 1A. INV-DEV-UNBOUNDED-LOOP (DEV-CLI22 SampleNTT / XOF / parser retry loop inversion)
            if chain:
                for idx_local, (ln_no, line) in enumerate(body_lines):
                    if _COMMENT_LINE_RE.match(line):
                        continue
                    if _UNBOUNDED_LOOP_HEAD_RE.search(line):
                        loop_window = "\n".join(
                            txt
                            for _, txt in body_lines[idx_local : min(len(body_lines), idx_local + 18)]
                            if not _COMMENT_LINE_RE.match(txt)
                        )
                        if _LOOP_READ_OR_SAMPLE_RE.search(loop_window) and not _LOOP_STEP_BOUND_RE.search(loop_window):
                            out.append(
                                VerificationInversionFinding(
                                    rule_id="INV-DEV-UNBOUNDED-LOOP",
                                    primitive="DEV_INVERSION",
                                    severity="HIGH",
                                    cwe="CWE-834",
                                    file_path=abs_fp,
                                    line_number=ln_no,
                                    title=f"Unbounded stream/rejection-sampling loop reachable from entry point in {sym.file_path}:{ln_no}",
                                    description=(
                                        f"Inverts DEV-CLI22 (non-terminating rejection/stream loop under adversarial input): "
                                        f"function `{sym.name}` enters an unbounded loop reading or sampling input without an "
                                        f"explicit iteration counter, step limit, or deadline along call chain `{' -> '.join(chain)}`."
                                    ),
                                    evidence=line.strip()[:200],
                                    remediation=(
                                        "Enforce a deterministic maximum iteration counter or byte/step budget inside "
                                        "every parser and rejection-sampling loop and fail closed when exceeded."
                                    ),
                                    call_chain=list(chain),
                                )
                            )

            # 1B. INV-DEV-REACHABLE-PANIC (DEV-E7 & DEV-CLI15 reachable Rust panic / unclamped allocation)
            if chain and pf.language == "rust":
                has_bounds_guard = bool(
                    re.search(r"\b(\.min\s*\(|<=?\s*MAX_|if\s+[^\n{]*>\s*MAX_|\.checked_)", body_text)
                )
                for ln_no, line in body_lines:
                    if _COMMENT_LINE_RE.match(line):
                        continue
                    m_panic = _RUST_PANIC_SINK_RE.search(line)
                    if m_panic:
                        tok = m_panic.group(1)
                        if "with_capacity" in tok and has_bounds_guard:
                            continue
                        # Ignore mutex lock unwraps or static regex compile unwraps
                        if any(benign in line for benign in (".lock().unwrap()", "Regex::new(", "OnceLock", "LazyLock")):
                            continue
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-DEV-REACHABLE-PANIC",
                                primitive="DEV_INVERSION",
                                severity="HIGH",
                                cwe="CWE-248",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"Entry-reachable Rust panic/unclamped allocation in {sym.file_path}:{ln_no}",
                                description=(
                                    f"Inverts DEV-E7 / DEV-CLI15 (intercepted Rust panic / OOM abort entry points): "
                                    f"`{sym.name}` invokes `{tok.strip()}` along entry-reachable call chain "
                                    f"`{' -> '.join(chain)}`, allowing malformed wire input to trigger a process abort."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Replace `.unwrap()`/`.expect()`/`panic!()` on untrusted input paths with "
                                    "`Result`/`Option` propagation (`?`) and clamp `Vec::with_capacity` against a hard constant."
                                ),
                                call_chain=list(chain),
                            )
                        )

            # 1C. INV-DEV-CRYPTO-DOMAIN-SEP (DEV-CLI16 HKDF random-oracle domain separation)
            if _HKDF_CALL_RE.search(body_text):
                for idx_local, (ln_no, line) in enumerate(body_lines):
                    if _COMMENT_LINE_RE.match(line):
                        continue
                    win = "\n".join(
                        txt
                        for _, txt in body_lines[idx_local : min(len(body_lines), idx_local + 6)]
                        if not _COMMENT_LINE_RE.match(txt)
                    )
                    if _HKDF_CALL_RE.search(line) and _EMPTY_INFO_RE.search(win):
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-DEV-CRYPTO-DOMAIN-SEP",
                                primitive="DEV_INVERSION",
                                severity="MEDIUM",
                                cwe="CWE-327",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"HKDF key derivation omits domain-separation info label in {sym.file_path}:{ln_no}",
                                description=(
                                    f"Inverts DEV-CLI16 (`KeyIndRoGap` HKDF random-oracle domain-separation premise): "
                                    f"`{sym.name}` derives key material with an empty `info` context label, risking "
                                    "cross-protocol or cross-phase key-indistinguishability collisions."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Pass a distinct, protocol- and phase-specific non-empty `info` byte label "
                                    "(e.g., `b\"RFCHunt-v1-SessionKey\"`) to every HKDF-Expand invocation."
                                ),
                                call_chain=list(chain) if chain else [sym.name],
                            )
                        )
        return out

    # =========================================================================
    # Pass 2: Inverted Rule 5 Transitive Trust-Closure Auditor
    # =========================================================================
    def _run_pass2_rule5_trust_closure(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> Tuple[List[VerificationInversionFinding], int]:
        out: List[VerificationInversionFinding] = []
        gate_symbols: List[SymbolNode] = []
        for sym in cg_context.symbols_by_id.values():
            if not self.include_tests and _is_test_rel_path(sym.file_path):
                continue
            if _SECURITY_GATE_NAME_RE.match(sym.name) or "sanitizer" in sym.roles:
                gate_symbols.append(sym)

        for gate in gate_symbols:
            # Forward BFS over `adj` to collect the gate's transitive callee closure
            closure_chains: Dict[str, List[str]] = {gate.symbol_id: [gate.name]}
            queue: List[str] = [gate.symbol_id]
            q_idx = 0
            while q_idx < len(queue):
                cur_sid = queue[q_idx]
                q_idx += 1
                cur_chain = closure_chains[cur_sid]
                if len(cur_chain) >= self.max_closure_depth:
                    continue
                for edge in cg_context.adj.get(cur_sid, ()):
                    callee_id = edge.callee_id
                    if callee_id not in closure_chains and callee_id in cg_context.symbols_by_id:
                        callee_sym = cg_context.symbols_by_id[callee_id]
                        if not self.include_tests and _is_test_rel_path(callee_sym.file_path):
                            continue
                        closure_chains[callee_id] = cur_chain + [callee_sym.name]
                        queue.append(callee_id)

            # Check if ANY function in the gate's transitive closure (or same module) performs path canonicalization
            closure_has_canonicalize = False
            for c_sid in closure_chains:
                c_sym = cg_context.symbols_by_id[c_sid]
                c_pf = cg_context.parsed_files.get(c_sym.file_path)
                if c_pf is None:
                    continue
                c_text = "\n".join(txt for _, txt in self._symbol_body_lines(c_pf, c_sym))
                file_text = "\n".join(c_pf.lines)
                if _PATH_CANONICALIZE_RE.search(c_text) or _PATH_CANONICALIZE_RE.search(file_text):
                    closure_has_canonicalize = True
                    break

            is_path_gate = bool(_PATH_GATE_NAME_RE.search(gate.name)) and not gate.name.lower().startswith("strip")

            for c_sid, chain in closure_chains.items():
                c_sym = cg_context.symbols_by_id[c_sid]
                c_pf = cg_context.parsed_files.get(c_sym.file_path)
                if c_pf is None:
                    continue
                abs_fp = str((root / c_sym.file_path).resolve(strict=False))
                body_lines = self._symbol_body_lines(c_pf, c_sym)

                for idx_local, (ln_no, line) in enumerate(body_lines):
                    if _COMMENT_LINE_RE.match(line):
                        continue

                    # 2A. INV-RULE5-FAIL-OPEN: Catch/except/Err block in security gate's closure returning True
                    if _CATCH_OR_ERR_RE.search(line):
                        catch_lines: List[str] = [line]
                        brace_depth = line.count("{") - line.count("}")
                        for _, nxt_txt in body_lines[idx_local + 1 : min(len(body_lines), idx_local + 8)]:
                            if _COMMENT_LINE_RE.match(nxt_txt):
                                continue
                            catch_lines.append(nxt_txt)
                            brace_depth += nxt_txt.count("{") - nxt_txt.count("}")
                            if "}" in nxt_txt and brace_depth <= 0:
                                break
                        handler_win = "\n".join(catch_lines)
                        has_fail_closed_return = bool(
                            re.search(r"\b(?:return\s+(?:false|False|None|null|undefined|Err\s*\()|throw\b|raise\b)", handler_win)
                        )
                        if _PERMISSIVE_RETURN_RE.search(handler_win) and not has_fail_closed_return:
                            out.append(
                                VerificationInversionFinding(
                                    rule_id="INV-RULE5-FAIL-OPEN",
                                    primitive="RULE5_TRUST_CLOSURE",
                                    severity="HIGH",
                                    cwe="CWE-636",
                                    file_path=abs_fp,
                                    line_number=ln_no,
                                    title=f"Transitive trust-closure helper `{c_sym.name}` fails open in {c_sym.file_path}:{ln_no}",
                                    description=(
                                        f"Inverts TrustedClosure Rule 5 (untrusted proof-tree pollution in security statement closure): "
                                        f"security gate `{gate.name}` transitively depends on `{c_sym.name}` along "
                                        f"`{' -> '.join(chain)}`, which catches an error/exception and returns a permissive `True` decision."
                                    ),
                                    evidence=handler_win.splitlines()[0].strip()[:200],
                                    remediation=(
                                        "Enforce fail-closed semantics (`return False` / `Err(...)`) inside every exception "
                                        "or error branch within a security gate's transitive callee closure."
                                    ),
                                    call_chain=list(chain),
                                )
                            )

                    # 2B. INV-RULE5-UNCANONICAL-PATH: Prefix check in path gate's closure without canonicalization
                    if (
                        is_path_gate
                        and not closure_has_canonicalize
                        and not c_sym.name.lower().startswith("strip")
                        and _PATH_PREFIX_CHECK_RE.search(line)
                    ):
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-RULE5-UNCANONICAL-PATH",
                                primitive="RULE5_TRUST_CLOSURE",
                                severity="HIGH",
                                cwe="CWE-22",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"Path gate `{gate.name}` closure checks prefix without canonicalization in {c_sym.file_path}:{ln_no}",
                                description=(
                                    f"Inverts TrustedClosure Rule 5: path confinement gate `{gate.name}` (closure "
                                    f"`{' -> '.join(chain)}`) performs string prefix matching (`starts_with`/`startsWith`) "
                                    f"in `{c_sym.name}` without invoking `realpath`/`canonicalize`/`resolve` anywhere in its transitive closure."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Canonicalize both the candidate path and sandbox root via `realpath`/`canonicalize` "
                                    "and use path-component containment (`is_relative_to`) instead of raw string prefixes."
                                ),
                                call_chain=list(chain),
                            )
                        )

                    # 2C. INV-RULE5-UNCHECKED-FFI: Bare FFI security syscall in gate's closure with discarded return value
                    m_ffi = _FFI_SECURITY_CALL_RE.match(line)
                    if m_ffi:
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-RULE5-UNCHECKED-FFI",
                                primitive="RULE5_TRUST_CLOSURE",
                                severity="HIGH",
                                cwe="CWE-252",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"Unchecked OS/FFI security call `{m_ffi.group(1)}` in `{gate.name}` closure ({c_sym.file_path}:{ln_no})",
                                description=(
                                    f"Inverts TrustedClosure Rule 5: security gate `{gate.name}` depends on `{c_sym.name}` "
                                    f"(`{' -> '.join(chain)}`), which invokes `{m_ffi.group(1)}` without capturing or checking its return status."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    f"Capture the return code of `{m_ffi.group(1)}` and abort/fail closed immediately on any non-success status."
                                ),
                                call_chain=list(chain),
                            )
                        )

        return out, len(gate_symbols)

    # =========================================================================
    # Pass 3: Inverted Comparator Predicate-vs-Contract Differential Checker
    # =========================================================================
    def _run_pass3_comparator_contract(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> List[VerificationInversionFinding]:
        out: List[VerificationInversionFinding] = []
        for sid, sym in cg_context.symbols_by_id.items():
            if not self.include_tests and _is_test_rel_path(sym.file_path):
                continue
            pf = cg_context.parsed_files.get(sym.file_path)
            if pf is None:
                continue
            abs_fp = str((root / sym.file_path).resolve(strict=False))
            body_lines = self._symbol_body_lines(pf, sym)
            clean_lines = [txt for _, txt in body_lines if not _COMMENT_LINE_RE.match(txt)]
            body_text = "\n".join(clean_lines)

            # Include 1-hop callee bodies so helper claim validators are credited
            closure_text = body_text
            for edge in cg_context.adj.get(sid, ()):
                c_sym = cg_context.symbols_by_id.get(edge.callee_id)
                if c_sym is not None:
                    c_pf = cg_context.parsed_files.get(c_sym.file_path)
                    if c_pf is not None:
                        closure_text += "\n" + "\n".join(
                            txt for _, txt in self._symbol_body_lines(c_pf, c_sym) if not _COMMENT_LINE_RE.match(txt)
                        )

            # 3A. INV-COMP-MISSING-CLAIM: JWT / OIDC verification contract challenge
            for ln_no, line in body_lines:
                if _COMMENT_LINE_RE.match(line):
                    continue
                if _JWT_VERIFY_CALL_RE.search(line):
                    missing: List[str] = []
                    if not _JWT_AUD_CHECK_RE.search(closure_text):
                        missing.append("aud (audience binding)")
                    if not _JWT_ISS_CHECK_RE.search(closure_text):
                        missing.append("iss (issuer binding)")
                    if _JWT_DISABLED_OPT_RE.search(closure_text):
                        missing.append("verify_signature/verify_exp enabled")
                    if missing:
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-COMP-MISSING-CLAIM",
                                primitive="COMPARATOR_CONTRACT",
                                severity="HIGH",
                                cwe="CWE-345",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"JWT/OIDC handler `{sym.name}` omits required contract claims ({', '.join(missing)}) in {sym.file_path}:{ln_no}",
                                description=(
                                    f"Inverts `comparator/` Challenge-vs-Solution check: normative JWT/OIDC Challenge "
                                    f"requires `{['sig', 'exp', 'aud', 'iss']}`, but `{sym.name}` Solution omits `{missing}`, "
                                    "permitting cross-audience or cross-issuer token confusion."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Enforce explicit `audience` (`aud`), `issuer` (`iss`), `exp`, and signature verification "
                                    "in every JWT/OIDC decoding call."
                                ),
                                call_chain=[sym.name],
                                missing_predicates=missing,
                            )
                        )
                    break

            # 3B. INV-COMP-WEAK-FRAMING-GUARD: RFC 9112 §6.3 CL + TE mutual exclusion contract challenge
            if _CL_TOKEN_RE.search(body_text) and _TE_TOKEN_RE.search(body_text):
                is_boolean_body_presence_only = bool(
                    re.search(
                        r"(?:declaresBody|hasBody|clientDeclaredBody)\s*=\s*(?:Boolean\s*\()?\s*[^;]*content-length[^;]*\|\|[^;]*transfer-encoding",
                        body_text,
                        re.IGNORECASE | re.DOTALL,
                    )
                )
                if not _FRAMING_REJECT_RE.search(body_text) and not is_boolean_body_presence_only:
                    first_ln = body_lines[0][0] if body_lines else sym.start_line
                    for ln_no, line in body_lines:
                        if _CL_TOKEN_RE.search(line) or _TE_TOKEN_RE.search(line):
                            first_ln = ln_no
                            break
                    out.append(
                        VerificationInversionFinding(
                            rule_id="INV-COMP-WEAK-FRAMING-GUARD",
                            primitive="COMPARATOR_CONTRACT",
                            severity="HIGH",
                            cwe="CWE-444",
                            file_path=abs_fp,
                            line_number=first_ln,
                            title=f"HTTP framing handler `{sym.name}` accepts both Content-Length and Transfer-Encoding in {sym.file_path}:{first_ln}",
                            description=(
                                f"Inverts `comparator/` Challenge-vs-Solution check against RFC 9112 §6.3: "
                                f"`{sym.name}` inspects both `Content-Length` and `Transfer-Encoding` without a mutual-exclusion "
                                "rejection branch (`!(has_cl && has_te)`), enabling CL.TE / TE.CL request smuggling."
                            ),
                            evidence=pf.lines[max(0, first_ln - 1)].strip()[:200],
                            remediation=(
                                "Reject any HTTP request containing both `Transfer-Encoding` and `Content-Length` "
                                "with `400 Bad Request` (RFC 9112 §6.3)."
                            ),
                            call_chain=[sym.name],
                            missing_predicates=["reject_concurrent_content_length_and_transfer_encoding"],
                        )
                    )

            # 3C. INV-COMP-ECHO-METHOD-CRED-LEAK: Credential injection/SigV4 runs when filterRequest (which blocks TRACE/TRACK) is unset
            if (
                ("mutateHeaders" in body_text or "planSigv4" in body_text)
                and "decideAndRespond" in body_text
                and re.search(r"if\s*\(\s*(?:options\.)?filterRequest\s*\)", body_text)
                and not re.search(r"\b(?:ECHO_METHODS|isEchoMethod|'TRACE'|\"TRACE\")", body_text)
            ):
                cred_ln = body_lines[0][0] if body_lines else sym.start_line
                for ln_no, line in body_lines:
                    if "mutateHeaders" in line or "planSigv4" in line:
                        cred_ln = ln_no
                        break
                out.append(
                    VerificationInversionFinding(
                        rule_id="INV-COMP-ECHO-METHOD-CRED-LEAK",
                        primitive="COMPARATOR_CONTRACT",
                        severity="HIGH",
                        cwe="CWE-200",
                        file_path=abs_fp,
                        line_number=cred_ln,
                        title=f"Proxy handler `{sym.name}` injects masked credentials/SigV4 without blocking TRACE/TRACK when `filterRequest` is unset ({sym.file_path}:{cred_ln})",
                        description=(
                            f"Inverts `comparator/` Challenge-vs-Solution check: `{sym.name}` gates `decideAndRespond` "
                            "(which enforces the `ECHO_METHODS` `TRACE`/`TRACK` block) behind `if (filterRequest)`, "
                            "but still executes `mutateHeaders` / `planSigv4` when `filterRequest` is undefined, "
                            "allowing `TRACE` requests to echo injected credentials back to the sandboxed client."
                        ),
                        evidence=pf.lines[max(0, cred_ln - 1)].strip()[:200],
                        remediation=(
                            "Enforce the `ECHO_METHODS` (`TRACE`/`TRACK`) 405 refusal unconditionally before "
                            "`if (filterRequest)` and before `mutateHeaders` / `planSigv4`."
                        ),
                        call_chain=[sym.name],
                        missing_predicates=["reject_echo_methods_before_credential_injection"],
                    )
                )
        return out

    # =========================================================================
    # Pass 4: Inverted Symbolic-vs-Byte Refinement Gap Auditor
    # =========================================================================
    def _run_pass4_refinement_gap(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> List[VerificationInversionFinding]:
        out: List[VerificationInversionFinding] = []
        for rel_path, pf in cg_context.parsed_files.items():
            if not self.include_tests and _is_test_rel_path(rel_path):
                continue
            abs_fp = str((root / rel_path).resolve(strict=False))

            # 4A. INV-REFINE-PATH-DECODE-SPLIT: Auth check on raw URL/path before percent-decoding
            raw_auth_line: Optional[Tuple[int, str, str]] = None
            decode_line: Optional[Tuple[int, str, str]] = None
            for sym in pf.symbols:
                body_lines = self._symbol_body_lines(pf, sym)
                body_text = "\n".join(txt for _, txt in body_lines if not _COMMENT_LINE_RE.match(txt))
                is_auth_or_filter = bool(
                    _SECURITY_GATE_NAME_RE.match(sym.name)
                    or re.search(r"(auth|admin|allow|deny|block|filter|guard|acl|middleware)", sym.name, re.IGNORECASE)
                )
                for ln_no, line in body_lines:
                    if _COMMENT_LINE_RE.match(line):
                        continue
                    if (
                        is_auth_or_filter
                        and _RAW_PATH_AUTH_RE.search(line)
                        and not _PATH_DECODE_CALL_RE.search(body_text)
                        and raw_auth_line is None
                    ):
                        raw_auth_line = (ln_no, line, sym.name)
                    if _PATH_DECODE_CALL_RE.search(line) and decode_line is None:
                        decode_line = (ln_no, line, sym.name)

            if raw_auth_line is not None and decode_line is not None:
                ln_no, line, auth_fn = raw_auth_line
                dec_ln, _, dec_fn = decode_line
                out.append(
                    VerificationInversionFinding(
                        rule_id="INV-REFINE-PATH-DECODE-SPLIT",
                        primitive="REFINEMENT_GAP",
                        severity="HIGH",
                        cwe="CWE-436",
                        file_path=abs_fp,
                        line_number=ln_no,
                        title=f"Raw-vs-decoded URL path refinement split between `{auth_fn}` and `{dec_fn}` in {rel_path}:{ln_no}",
                        description=(
                            f"Inverts `comp_refines_cli` (byte-to-symbolic message refinement): security filter `{auth_fn}` "
                            f"(line {ln_no}) inspects the raw undecoded request URL/path while `{dec_fn}` (line {dec_ln}) "
                            "percent-decodes the path, allowing `%2e%2e` or `%2fadmin` to bypass the filter."
                        ),
                        evidence=line.strip()[:200],
                        remediation=(
                            "Perform URL percent-decoding and path canonicalization once before evaluating any "
                            "route-based authorization or blocklist filter."
                        ),
                        call_chain=[auth_fn, dec_fn] if auth_fn != dec_fn else [auth_fn],
                    )
                )

            # 4B. INV-REFINE-DUPLICATE-KEY: Header/parameter dictionary loop silently overwriting duplicate keys
            for sym in pf.symbols:
                body_lines = self._symbol_body_lines(pf, sym)
                for idx_local, (ln_no, line) in enumerate(body_lines):
                    if _COMMENT_LINE_RE.match(line):
                        continue
                    if _HEADER_LOOP_RE.search(line):
                        loop_win = body_lines[idx_local + 1 : min(len(body_lines), idx_local + 10)]
                        win_text = "\n".join(txt for _, txt in loop_win if not _COMMENT_LINE_RE.match(txt))
                        if re.search(r"\b(if\s+[^\n:]*\bin\s+|setdefault|append|duplicate|reject)", win_text):
                            continue
                        for sub_ln, sub_line in loop_win:
                            if _COMMENT_LINE_RE.match(sub_line):
                                continue
                            m_ov = _DICT_OVERWRITE_RE.match(sub_line)
                            if m_ov:
                                out.append(
                                    VerificationInversionFinding(
                                        rule_id="INV-REFINE-DUPLICATE-KEY",
                                        primitive="REFINEMENT_GAP",
                                        severity="MEDIUM",
                                        cwe="CWE-436",
                                        file_path=abs_fp,
                                        line_number=sub_ln,
                                        title=f"Header parser `{sym.name}` silently overwrites duplicate keys in {rel_path}:{sub_ln}",
                                        description=(
                                            f"Inverts `comp_refines_cli` (non-injective wire-to-map parsing): `{sym.name}` "
                                            f"assigns `{m_ov.group(1)}[{m_ov.group(2)}]` inside a header loop with last-write-wins "
                                            "semantics instead of rejecting duplicate framing/security headers."
                                        ),
                                        evidence=sub_line.strip()[:200],
                                        remediation=(
                                            "Reject duplicate single-valued headers (`Content-Length`, `Host`, `Authorization`) "
                                            "or combine comma-list headers per RFC 9110 §5.3."
                                        ),
                                        call_chain=[sym.name],
                                    )
                                )
                                break

                    # 4C. INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS: Over-restrictive TLS ClientHello outer record version check (buf[2] <= 0x03)
                    if (
                        "0x16" in line
                        and "0x03" in line
                        and re.search(r"\[2\]!?[\s]*<=\s*0x03", line)
                    ):
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-REFINE-TLS-SNIFF-OPAQUE-BYPASS",
                                primitive="REFINEMENT_GAP",
                                severity="HIGH",
                                cwe="CWE-436",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"TLS ClientHello sniffer `{sym.name}` rejects valid outer record versions `0x0304..0x03ff` in {rel_path}:{ln_no}",
                                description=(
                                    f"Inverts `comp_refines_cli` (wire-to-protocol refinement): `{sym.name}` requires "
                                    "`buf[2] <= 0x03` on the initial TLS record header, whereas OpenSSL/BoringSSL/Go TLS "
                                    "servers accept any `0x03XX` outer `legacy_record_version` per RFC 8446 §5.1. "
                                    "When `refuseOpaqueTunnels` is false, setting byte 2 to `0x04` causes the proxy to "
                                    "fall back to an uninspected opaque TCP tunnel, bypassing TLS termination and `filterRequest`."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Match any `buf[0] === 0x16 && buf[1] === 0x03` on the outer record header and let "
                                    "the TLS terminator validate the handshake rather than falling back to an opaque tunnel."
                                ),
                                call_chain=[sym.name],
                            )
                        )

                    # 4D. INV-REFINE-TLS-FRAGMENT-SNI-BYPASS: Fragmented ClientHello checks 16-bit TLS record length instead of 24-bit Handshake length
                    if (
                        "readUInt16BE(3)" in line
                        and "kind: 'absent'" in line
                        and "readUIntBE(6, 3)" not in "\n".join(txt for _, txt in body_lines)
                    ):
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-REFINE-TLS-FRAGMENT-SNI-BYPASS",
                                primitive="REFINEMENT_GAP",
                                severity="MEDIUM",
                                cwe="CWE-436",
                                file_path=abs_fp,
                                line_number=ln_no,
                                title=f"TLS ClientHello SNI parser `{sym.name}` conflates record length with handshake length in {rel_path}:{ln_no}",
                                description=(
                                    f"Inverts `comp_refines_cli` (record-layer vs handshake-layer refinement): `{sym.name}` "
                                    "checks `end === 5 + record.readUInt16BE(3)` (TLS record length) without verifying "
                                    "the 24-bit TLS Handshake message length (`9 + record.readUIntBE(6, 3)`), misclassifying "
                                    "a multi-record fragmented ClientHello split before `extensions_length` as `{ kind: 'absent' }`."
                                ),
                                evidence=line.strip()[:200],
                                remediation=(
                                    "Compare against the 24-bit handshake message length (`9 + record.readUIntBE(6, 3)`) "
                                    "and return `{ kind: 'unreadable' }` whenever `handshakeEnd > end`."
                                ),
                                call_chain=[sym.name],
                            )
                        )

            # 4E. File-level sandbox policy refinement checks (macOS Seatbelt case sensitivity & shell startup deny completeness)
            file_text = "\n".join(pf.lines)
            if (
                ("'.zshrc'" in file_text or '".zshrc"' in file_text)
                and ("'.bashrc'" in file_text or '".bashrc"' in file_text)
                and ("'.zshenv'" not in file_text and '".zshenv"' not in file_text)
                and "DANGEROUS_FILES" in file_text
            ):
                for idx_ln, raw_ln in enumerate(pf.lines, start=1):
                    if "'.zshrc'" in raw_ln or '".zshrc"' in raw_ln:
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-ALG-MISSING-SHELL-STARTUP-DENY",
                                primitive="COMPARATOR_CONTRACT",
                                severity="MEDIUM",
                                cwe="CWE-732",
                                file_path=abs_fp,
                                line_number=idx_ln,
                                title=f"Mandatory shell-startup deny list blocks `.zshrc`/`.bashrc` but omits `.zshenv` in {rel_path}:{idx_ln}",
                                description=(
                                    "Inverts `comparator` set-completeness contract: `DANGEROUS_FILES` protects `.zshrc` "
                                    "and `.bashrc` from sandboxed writes, but omits `.zshenv`, which `zsh` sources "
                                    "unconditionally on every interactive and non-interactive (`zsh -c`) invocation."
                                ),
                                evidence=raw_ln.strip()[:200],
                                remediation="Add `'.zshenv'` and `'.zlogin'` to `DANGEROUS_FILES` mandatory write-deny list.",
                                missing_predicates=[".zshenv"],
                            )
                        )
                        break

            if (
                "(deny file-write*" in file_text
                and "(literal " in file_text
                and "(?i)" not in file_text
                and ("macos" in rel_path.lower() or "seatbelt" in file_text.lower())
            ):
                for idx_ln, raw_ln in enumerate(pf.lines, start=1):
                    if "(deny file-write*" in raw_ln:
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-REFINE-CASE-INSENSITIVE-FS-POLICY",
                                primitive="REFINEMENT_GAP",
                                severity="MEDIUM",
                                cwe="CWE-178",
                                file_path=abs_fp,
                                line_number=idx_ln,
                                title=f"macOS Seatbelt profile emits case-sensitive `(literal ...)` deny rules on case-insensitive APFS in {rel_path}:{idx_ln}",
                                description=(
                                    "Inverts `comp_refines_cli` (policy-vs-filesystem refinement): macOS Seatbelt `(literal ...)` "
                                    "and `(regex ...)` path rules are evaluated case-sensitively by the kernel filter, while "
                                    "default macOS APFS resolves paths case-insensitively (e.g. `.Git/hooks` resolves to `.git/hooks`)."
                                ),
                                evidence=raw_ln.strip()[:200],
                                remediation="Emit case-insensitive Seatbelt regex rules (`(?i)`) or normalize case-variant deny patterns on macOS.",
                            )
                        )
                        break
        return out

    # =========================================================================
    # Pass 5: Inverted arm64-semantics Release-Build & FFI Elision Detector
    # =========================================================================
    def _run_pass5_release_elision(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> List[VerificationInversionFinding]:
        out: List[VerificationInversionFinding] = []
        for rel_path, pf in cg_context.parsed_files.items():
            if not self.include_tests and _is_test_rel_path(rel_path):
                continue
            abs_fp = str((root / rel_path).resolve(strict=False))

            # Python AST pass for `assert <security_check>` and `secret == token`
            if pf.language == "python":
                src_text = "\n".join(pf.lines)
                try:
                    tree = ast.parse(src_text)
                except SyntaxError:
                    tree = None
                if tree is not None:
                    for node in ast.walk(tree):
                        # 5A (Python): `assert` used for security/auth/sandbox enforcement
                        if isinstance(node, ast.Assert):
                            ln_no = int(getattr(node, "lineno", 1))
                            line_s = pf.lines[max(0, ln_no - 1)].strip() if pf.lines else ""
                            if _SECURITY_ASSERT_EXPR_RE.search(line_s):
                                out.append(
                                    VerificationInversionFinding(
                                        rule_id="INV-ELISION-DEBUG-ASSERT",
                                        primitive="RELEASE_ELISION",
                                        severity="HIGH",
                                        cwe="CWE-617",
                                        file_path=abs_fp,
                                        line_number=ln_no,
                                        title=f"Security check inside elidable Python `assert` in {rel_path}:{ln_no}",
                                        description=(
                                            "Inverts `arm64-semantics` source-vs-binary verification: Python removes `assert` "
                                            "statements when executed with `-O` / `PYTHONOPTIMIZE=1`, completely eliding this "
                                            "authorization/boundary guard in optimized deployments."
                                        ),
                                        evidence=line_s[:200],
                                        remediation=(
                                            "Replace `assert` on security, authorization, or input-validation invariants "
                                            "with an explicit `if not ...: raise PermissionError(...)` / `ValueError(...)`."
                                        ),
                                    )
                                )
                        # 5B (Python): Direct `==` / `!=` on secret/HMAC/signature/token variables
                        elif isinstance(node, ast.Compare) and any(
                            isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops
                        ):
                            ln_no = int(getattr(node, "lineno", 1))
                            line_s = pf.lines[max(0, ln_no - 1)].strip() if pf.lines else ""
                            if _CT_COMPARE_CALL_RE.search(line_s):
                                continue
                            operands = [node.left, *node.comparators]
                            has_empty_or_none = any(
                                (isinstance(opnd, ast.Constant) and opnd.value in (None, "", b""))
                                for opnd in operands
                            )
                            if has_empty_or_none:
                                continue
                            var_names: List[str] = []
                            for opnd in operands:
                                if isinstance(opnd, ast.Name):
                                    var_names.append(opnd.id)
                                elif isinstance(opnd, ast.Attribute):
                                    var_names.append(opnd.attr)
                            if len(var_names) >= 2 and any(_SECRET_VAR_TOKEN_RE.match(v) for v in var_names):
                                out.append(
                                    VerificationInversionFinding(
                                        rule_id="INV-ELISION-NON-CT-SECRET",
                                        primitive="RELEASE_ELISION",
                                        severity="HIGH",
                                        cwe="CWE-208",
                                        file_path=abs_fp,
                                        line_number=ln_no,
                                        title=f"Non-constant-time secret comparison (`==`/`!=`) in {rel_path}:{ln_no}",
                                        description=(
                                            "Inverts `arm64-semantics` timing/instruction audit: direct `==`/`!=` comparison "
                                            f"on secret/MAC/signature operand(s) `{var_names}` short-circuits on the first "
                                            "mismatched byte, leaking secret material via timing side channels."
                                        ),
                                        evidence=line_s[:200],
                                        remediation=(
                                            "Use `hmac.compare_digest(a, b)` for all HMAC, signature, API key, and token comparisons."
                                        ),
                                    )
                                )

            # Line-based checks across Rust, C/C++, TypeScript/JavaScript, Go, and Python
            for idx, raw_line in enumerate(pf.lines, start=1):
                if _COMMENT_LINE_RE.match(raw_line):
                    continue
                line_s = raw_line.strip()

                # 5A (Rust & C/C++): `debug_assert!()` or C `assert()` on security invariant
                m_dbg = _RUST_DEBUG_ASSERT_RE.search(line_s) if pf.language == "rust" else (
                    _C_ASSERT_RE.match(line_s) if pf.language in ("c", "cpp") else None
                )
                if m_dbg and _SECURITY_ASSERT_EXPR_RE.search(m_dbg.group(1)):
                    out.append(
                        VerificationInversionFinding(
                            rule_id="INV-ELISION-DEBUG-ASSERT",
                            primitive="RELEASE_ELISION",
                            severity="HIGH",
                            cwe="CWE-617",
                            file_path=abs_fp,
                            line_number=idx,
                            title=f"Release-elided `debug_assert!`/`assert` on security invariant in {rel_path}:{idx}",
                            description=(
                                "Inverts `arm64-semantics` binary-vs-source verification: `debug_assert!` (Rust `--release`) "
                                "and `assert()` (C/C++ `-DNDEBUG`) are stripped from release binaries, removing this "
                                "security check in production machine code."
                            ),
                            evidence=line_s[:200],
                            remediation=(
                                "Use an unconditional runtime check (`if !cond { return Err(...); }` or `assert!`) "
                                "that remains active in release builds."
                            ),
                        )
                    )

                # 5B (Non-Python): Direct `==` / `===` on secret/MAC/signature identifiers
                if pf.language in ("rust", "typescript", "javascript", "go", "c", "cpp") and not _CT_COMPARE_CALL_RE.search(line_s):
                    for m_cmp in re.finditer(
                        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(===|!==|==|!=)\s*([A-Za-z_][A-Za-z0-9_]*)\b",
                        line_s,
                    ):
                        lhs, _, rhs = m_cmp.group(1), m_cmp.group(2), m_cmp.group(3)
                        if rhs.lower() in ("null", "nil", "none", "undefined", "true", "false") or lhs.lower() in ("null", "nil", "none", "undefined", "true", "false"):
                            continue
                        if _SECRET_VAR_TOKEN_RE.match(lhs) or _SECRET_VAR_TOKEN_RE.match(rhs):
                            out.append(
                                VerificationInversionFinding(
                                    rule_id="INV-ELISION-NON-CT-SECRET",
                                    primitive="RELEASE_ELISION",
                                    severity="HIGH",
                                    cwe="CWE-208",
                                    file_path=abs_fp,
                                    line_number=idx,
                                    title=f"Non-constant-time secret comparison (`{lhs}` vs `{rhs}`) in {rel_path}:{idx}",
                                    description=(
                                        "Inverts `arm64-semantics` constant-time instruction verification: standard equality "
                                        f"on `{lhs}` and `{rhs}` compiles to an early-exit branch or `memcmp`, exposing a timing oracle."
                                    ),
                                    evidence=line_s[:200],
                                    remediation=(
                                        "Use `subtle::ConstantTimeEq` (`ct_eq`) in Rust, `crypto.timingSafeEqual` in Node/TS, "
                                        "`subtle.ConstantTimeCompare` in Go, or `CRYPTO_memcmp` in C/C++."
                                    ),
                                )
                            )
                            break

                # 5C: Dead-store-eliminated `memset(secret, 0, ...)` or manual Rust zero loop
                if not _SAFE_ZEROIZE_RE.search(line_s):
                    m_ms = _RAW_MEMSET_ZERO_RE.search(line_s)
                    m_rz = _RUST_MANUAL_ZERO_LOOP_RE.search(line_s)
                    buf_name = m_ms.group(1) if m_ms else (m_rz.group(1) if m_rz else None)
                    if buf_name and _SECRET_BUF_NAME_RE.search(buf_name):
                        out.append(
                            VerificationInversionFinding(
                                rule_id="INV-ELISION-DEAD-STORE-ZERO",
                                primitive="RELEASE_ELISION",
                                severity="MEDIUM",
                                cwe="CWE-14",
                                file_path=abs_fp,
                                line_number=idx,
                                title=f"Compiler-elidable secret zeroization on `{buf_name}` in {rel_path}:{idx}",
                                description=(
                                    "Inverts `arm64-semantics` dead-store elimination check: LLVM/GCC dead-store elimination "
                                    f"(CWE-14) can strip plain `memset` or manual zero loops on `{buf_name}` when the buffer "
                                    "is not read again before going out of scope, leaving secret material in stack/heap memory."
                                ),
                                evidence=line_s[:200],
                                remediation=(
                                    "Use `zeroize::Zeroize` (`buf.zeroize()`) or `std::ptr::write_volatile` in Rust, and "
                                    "`explicit_bzero`, `SecureZeroMemory`, or `memset_s` in C/C++."
                                ),
                            )
                        )
        return out

    # =========================================================================
    # Pass 6: State-Machine Epoch & Ratchet Monotonicity Auditor
    # =========================================================================
    def _run_pass6_state_machine_ordering(
        self,
        root: Path,
        cg_context: CallGraphContext,
    ) -> List[VerificationInversionFinding]:
        out: List[VerificationInversionFinding] = []
        epoch_fn_re = re.compile(
            r"(?:set_epoch|update_epoch|apply_epoch|sync_epoch|ratchet_step|set_generation|update_sequence)",
            re.IGNORECASE,
        )
        epoch_assign_re = re.compile(
            r"\b(?:self|this|state)\.(?:epoch|generation_epoch|ratchet_epoch|seq_num)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)"
        )
        monotonic_guard_re = re.compile(
            r"(?:>\s*(?:self|this|state)\.|>=\s*(?:self|this|state)\.|<\s*(?:self|this|state)\.|<=\s*(?:self|this|state)\.|\+\s*1\b|checked_add)"
        )

        for _, sym in cg_context.symbols_by_id.items():
            if not self.include_tests and _is_test_rel_path(sym.file_path):
                continue
            if not epoch_fn_re.search(sym.name):
                continue
            pf = cg_context.parsed_files.get(sym.file_path)
            if pf is None:
                continue
            abs_fp = str((root / sym.file_path).resolve(strict=False))
            body_lines = self._symbol_body_lines(pf, sym)
            body_text = "\n".join(txt for _, txt in body_lines if not _COMMENT_LINE_RE.match(txt))
            if monotonic_guard_re.search(body_text):
                continue
            for ln_no, line in body_lines:
                if _COMMENT_LINE_RE.match(line):
                    continue
                m_asgn = epoch_assign_re.search(line)
                if m_asgn:
                    rhs = m_asgn.group(1)
                    if rhs.isdigit():
                        continue
                    out.append(
                        VerificationInversionFinding(
                            rule_id="INV-STATE-EPOCH-ROLLBACK",
                            primitive="STATE_MACHINE_ORDERING",
                            severity="HIGH",
                            cwe="CWE-362",
                            file_path=abs_fp,
                            line_number=ln_no,
                            title=f"State-machine mutator `{sym.name}` overwrites epoch without monotonic guard in {sym.file_path}:{ln_no}",
                            description=(
                                f"Inverts temporal state-machine transition invariant (`N -> N + 1`): `{sym.name}` "
                                f"assigns `{line.strip()}` directly from `{rhs}` without verifying `new_epoch > current_epoch`, "
                                "allowing stale or compromised handles to roll back the generation epoch."
                            ),
                            evidence=line.strip()[:200],
                            remediation=(
                                "Enforce strict monotonic epoch progression (`if new_epoch <= self.epoch: raise ValueError(...)`) "
                                "before updating generation or ratchet state."
                            ),
                            call_chain=[sym.name],
                            missing_predicates=["new_epoch > current_epoch"],
                            counterexample_witness='{"current_epoch": 5, "replayed_epoch": 2, "monotonic_check_present": false, "resulting_epoch": 2}',
                        )
                    )
                    break
        return out


def run_verification_inversion_audit(
    repo_path: Union[str, Path],
    *,
    cg_context: Optional[CallGraphContext] = None,
    max_closure_depth: int = 6,
    include_tests: bool = False,
) -> Dict[str, Any]:
    """Convenience runner returning a JSON-serializable VerificationInversionReport dict."""
    hunter = VerificationInversionHunter(
        max_closure_depth=max_closure_depth,
        include_tests=include_tests,
    )
    report = hunter.analyze_repository(repo_path, cg_context=cg_context)
    return report.to_dict()
