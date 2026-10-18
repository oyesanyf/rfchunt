"""
Adversarial Empirical Challenge Suite: Milestone 2 (Challenger M2-1)
Focus: Multi-line ABNF grammar extraction and 4-Parser Differential Matrix under adversarial inputs & fuzzing.
"""

import sys
import time
from pathlib import Path
import pytest

from engine.abnf_engine import ABNFGrammarEngine, _strip_abnf_comment
from engine.differential_oracle import (
    AsyncMicroserviceParser,
    CDNProxyParser,
    MultiImplementationDifferentialOracle,
    PermissiveLegacyParser,
    StrictRFC7230Parser,
)
from engine.taxonomy import AnomalyCategory


# ==============================================================================
# SECTION 1: PASSING ADVERSARIAL STRESS TESTS (ROBUSTNESS)
# ==============================================================================

def test_abnf_semicolons_and_dquotes():
    """Tests ABNF comment stripping with tricky quotes and semicolons."""
    assert _strip_abnf_comment('rule = ";" ; comment') == 'rule = ";"'
    assert _strip_abnf_comment('rule = "foo;bar;baz"') == 'rule = "foo;bar;baz"'
    assert _strip_abnf_comment('rule = elem ; comment ; nested ; comment') == 'rule = elem'
    assert _strip_abnf_comment('rule = elem ;') == 'rule = elem'
    assert _strip_abnf_comment('rule = elem') == 'rule = elem'


def test_abnf_multiline_empty_first_line_continuation():
    """Tests multi-line rule where definition begins on the continuation line."""
    engine = ABNFGrammarEngine()
    rfc_text = """
    my-rule =
        elem1 / elem2
        / elem3
    """
    reqs = engine.extract_from_rfc_text("TEST", rfc_text)
    assert len(reqs) >= 1
    assert "my-rule" in engine.extracted_rules
    defn = engine.extracted_rules["my-rule"]["definition"]
    assert "elem1 / elem2 / elem3" in defn


def test_abnf_multiline_with_pure_comment_lines():
    """Tests multi-line continuation with comments on their own indented lines."""
    engine = ABNFGrammarEngine()
    rfc_text = """
    complex-rule = part1
                   ; this is an explanatory comment
                   part2
                   ; another comment
                   part3
    """
    reqs = engine.extract_from_rfc_text("TEST", rfc_text)
    assert len(reqs) >= 1
    assert "complex-rule" in engine.extracted_rules
    defn = engine.extracted_rules["complex-rule"]["definition"]
    assert "part1 part2 part3" in defn


def test_abnf_incremental_alternatives_case_and_unseen():
    """Tests incremental alternatives (=/) with new rules and case variations."""
    engine = ABNFGrammarEngine()
    rfc_text = """
    brand-new-rule =/ "extension1"
    brand-new-rule =/ "extension2"
    """
    reqs = engine.extract_from_rfc_text("TEST", rfc_text)
    assert len(reqs) == 2
    assert "brand-new-rule" in engine.extracted_rules
    defn = engine.extracted_rules["brand-new-rule"]["definition"]
    assert '"extension1"' in defn
    assert '"extension2"' in defn


def test_abnf_massive_continuation_lines():
    """Stress tests ABNF extractor with 2000 continuation lines (no stack overflow, fast execution)."""
    engine = ABNFGrammarEngine()
    lines = ["massive-rule = base"]
    for i in range(2000):
        lines.append(f"               / alt-{i}")
    rfc_text = "\n".join(lines)

    t0 = time.time()
    reqs = engine.extract_from_rfc_text("TEST", rfc_text)
    elapsed = time.time() - t0

    assert elapsed < 1.0, f"Extraction of 2000 lines took {elapsed:.2f}s, expected < 1s"
    assert len(reqs) == 1
    assert "massive-rule" in engine.extracted_rules
    defn = engine.extracted_rules["massive-rule"]["definition"]
    assert "alt-1999" in defn


def test_abnf_real_rfc9110_and_rfc7230_extraction():
    """Tests ABNF extraction against real RFC 9110 and RFC 7230 text files."""
    rfcs_dir = Path(__file__).resolve().parent.parent / "rfcs"
    for rfc_name in ["rfc9110.txt", "rfc7230.txt"]:
        rfc_path = rfcs_dir / rfc_name
        if not rfc_path.exists():
            continue
        with open(rfc_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        engine = ABNFGrammarEngine()
        reqs = engine.extract_from_rfc_text(rfc_name.split(".")[0].upper(), content)
        assert len(reqs) > 10, f"Failed to extract rules from {rfc_name}"
        assert len(engine.extracted_rules) > 5


def test_abnf_malformed_and_adversarial_grammar():
    """Tests ABNF extractor on malformed, fuzzy, and adversarial strings."""
    engine = ABNFGrammarEngine()
    malformed_inputs = [
        "",  # empty string
        "    \n\n\t\t\n   ",  # whitespace only
        "// C++ comment\n/* C comment */\n",
        "= no rule name",
        "123 = starts with digit",
        "valid-rule = \n\n",
        "valid-rule = // comment only",
        "valid-rule = /* c-comment */",
        "a" * 10000 + " = foo",  # very long rule name
        "rule = " + "x" * 50000,  # very long body
    ]
    for text in malformed_inputs:
        reqs = engine.extract_from_rfc_text("FUZZ", text)
        assert isinstance(reqs, list)


def test_differential_matrix_giant_chunk_extension():
    """Tests 4 parsers on 64KB chunk extension (valid RFC syntax, stress payload)."""
    oracle = MultiImplementationDifferentialOracle([])
    chunk_ext = b";" + (b"param=" + b"A" * 1000 + b";") * 64
    payload = (
        b"POST /api/upload HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"5" + chunk_ext + b"\r\nHELLO\r\n0\r\n\r\n"
    )
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(payload)
    assert isinstance(has_div, bool)
    assert "StrictRFC7230" in matrix
    assert "AsyncMicroservice" in matrix
    assert matrix["StrictRFC7230"]["status"] in (200, 400)


def test_differential_matrix_dangling_bytes_scenarios():
    """Tests dangling body bytes across 4 parsers."""
    oracle = MultiImplementationDifferentialOracle([])
    dangling_probe = (
        b"POST /data HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"Content-Length: 100\r\n\r\n"
        b"SHORT"
    )
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(dangling_probe)
    assert has_div is True
    assert matrix["AsyncMicroservice"]["socket_state"] == "TIMEOUT"
    assert matrix["AsyncMicroservice"]["status"] == 408
    assert matrix["StrictRFC7230"]["status"] == 200


def test_differential_matrix_rhi_injections():
    """Tests Request Header Injection (RHI) variants in URI path."""
    oracle = MultiImplementationDifferentialOracle([])
    rhi_expect = b"GET /path%0d%0aExpect:%20asdf HTTP/1.1\r\nHost: target.local\r\n\r\n"
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(rhi_expect)
    assert has_div is True
    assert matrix["CDNProxy"]["status"] == 417

    rhi_te = b"GET /path%0d%0aTransfer-Encoding:%20chunked HTTP/1.1\r\nHost: target.local\r\n\r\n"
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(rhi_te)
    assert has_div is True
    assert matrix["CDNProxy"]["status"] == 501


def test_differential_matrix_conflicting_headers():
    """Tests conflicting Content-Length and Transfer-Encoding headers."""
    oracle = MultiImplementationDifferentialOracle([])
    dual_cl = (
        b"POST / HTTP/1.1\r\n"
        b"Host: test.local\r\n"
        b"Content-Length: 10\r\n"
        b"Content-Length: 20\r\n\r\n"
        b"0123456789"
    )
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(dual_cl)
    assert has_div is True
    assert matrix["StrictRFC7230"]["status"] == 400
    assert matrix["PermissiveLegacy"]["status"] == 200


def test_differential_matrix_reproducibility():
    """Verifies that offline 4-parser evaluations are 100% deterministic across repeated runs."""
    oracle = MultiImplementationDifferentialOracle([])
    probe = b"GET / HTTP/1.1\r\nHost : test.local\r\n\r\n"

    results = []
    for _ in range(5):
        has_div, anom, matrix = oracle.evaluate_matrix_4parsers(probe)
        results.append((has_div, matrix["StrictRFC7230"]["status"], matrix["PermissiveLegacy"]["status"]))

    assert len(set(results)) == 1
    assert results[0] == (True, 400, 200)


# ==============================================================================
# ==============================================================================
# SECTION 2: REMEDIATED CONFORMANCE TESTS (CHALLENGER M2-1 FINDINGS MITIGATED)
# ==============================================================================

def test_challenge_finding_1_huge_content_length_crashes_matrix():
    """
    REMEDIATED CHALLENGE 1 [CRITICAL]:
    Adversarial prober sends >4300 digits of Content-Length (common integer wrap fuzzing).
    AsyncMicroserviceParser shields against ValueError/OverflowError, returning 400 Bad Request.
    MultiImplementationDifferentialOracle.evaluate_matrix_4parsers safely evaluates without crashing.
    """
    oracle = MultiImplementationDifferentialOracle([])
    probe_huge_cl = b"POST / HTTP/1.1\r\nHost: test.local\r\nContent-Length: " + (b"9" * 5000) + b"\r\n\r\nbody"

    # Confirms the crash is prevented and 400 Bad Request is returned by AsyncMicroservice
    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(probe_huge_cl)
    assert "AsyncMicroservice" in matrix
    assert matrix["AsyncMicroservice"]["status"] == 400
    assert matrix["AsyncMicroservice"]["socket_state"] == "OK"


def test_challenge_finding_2_custom_content_length_header_false_timeout():
    r"""
    REMEDIATED CHALLENGE 2 [HIGH]:
    AsyncMicroserviceParser uses line-anchored regex `rb"(?:^|\r\n)content-length:\s*(\d+)"`.
    Custom headers like `X-Content-Length: 99999` are not misidentified as body length,
    preventing false 408 TIMEOUT and returning 200 OK.
    """
    parser = AsyncMicroserviceParser()
    probe = b"GET / HTTP/1.1\r\nHost: test.local\r\nX-Content-Length: 99999\r\n\r\n"
    resp = parser.parse(probe)

    # Confirms the remediation: X-Content-Length returns 200 OK without timeout
    assert resp.status_code == 200
    assert resp.socket_state == "OK"


def test_challenge_finding_3_abnf_rule_swallowing_deeper_indentation():
    """
    REMEDIATED CHALLENGE 3 [HIGH]:
    In ABNFGrammarEngine.extract_from_rfc_text, encountering any rule header unconditionally
    breaks continuation. Sub-rules indented deeper than parent rules are extracted independently.
    """
    engine = ABNFGrammarEngine()
    text = (
        "rule1 = val1\n"
        "  rule2 = val2\n"
    )
    reqs = engine.extract_from_rfc_text("TEST", text)
    extracted_keys = [k for k in engine.extracted_rules if "rule" in k]

    # Confirms the remediation: rule2 is extracted independently and not swallowed into rule1
    assert "rule1" in extracted_keys
    assert "rule2" in extracted_keys
    assert engine.extracted_rules["rule1"]["definition"] == "val1"
    assert engine.extracted_rules["rule2"]["definition"] == "val2"


def test_challenge_finding_4_strict_parser_accepts_bare_lf_and_cr():
    r"""
    REMEDIATED CHALLENGE 4 [MEDIUM]:
    StrictRFC7230Parser checks `head.replace(b"\r\n", b"")` for bare CR or bare LF.
    A bare LF or bare CR in a header value (e.g. `Host: example.local\nInjected: evil`)
    is strictly rejected with 400 Bad Request per RFC 7230 §3.2.4 / RFC 9112 §2.2.
    """
    parser = StrictRFC7230Parser()
    probe_bare_lf = b"GET / HTTP/1.1\r\nHost: example.local\nInjected: evil\r\n\r\n"
    resp_lf = parser.parse(probe_bare_lf)

    # Confirms the remediation: bare LF is rejected with 400 Bad Request
    assert resp_lf.status_code == 400
    assert b"Bare delimiter error" in resp_lf.raw_response

    probe_bare_cr = b"GET / HTTP/1.1\r\nHost: example.local\rInjected: evil\r\n\r\n"
    resp_cr = parser.parse(probe_bare_cr)

    # Confirms the remediation: bare CR is rejected with 400 Bad Request
    assert resp_cr.status_code == 400
    assert b"Bare delimiter error" in resp_cr.raw_response
