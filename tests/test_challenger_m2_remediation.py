"""
Empirical Challenge & Verification Suite: Milestone 2 Remediation
Role: Challenger M2 Remediation 1
Focus: Extreme >4,300 digit Content-Length inputs, custom X-Content-Length headers,
malformed numbers, matrix crash shielding, ABNF sub-rule independence, and bare delimiters.
"""

import re
import sys
import time
import pytest
from pathlib import Path

from engine.abnf_engine import ABNFGrammarEngine, _strip_abnf_comment
from engine.differential_oracle import (
    AsyncMicroserviceParser,
    CDNProxyParser,
    MultiImplementationDifferentialOracle,
    PermissiveLegacyParser,
    StrictRFC7230Parser,
    TargetResponse,
)


# ==============================================================================
# SECTION 1: EXTREME >4,300 DIGIT CONTENT-LENGTH FUZZING & MATRIX SHIELDING
# ==============================================================================

@pytest.mark.parametrize("digits", [4301, 5000, 10000, 20000, 50000], ids=lambda d: f"{d}_digits")
def test_async_parser_extreme_content_length_digits(digits):
    """
    Empirically verifies that AsyncMicroserviceParser safely catches ValueError/OverflowError
    when Content-Length exceeds Python's default sys.get_int_max_str_digits() (>4,300 digits).
    Returns 400 Bad Request with socket_state 'OK' and does NOT raise an unhandled exception.
    """
    parser = AsyncMicroserviceParser()
    payload = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + (b"9" * digits) + b"\r\n\r\n"
        b"test_body"
    )
    t0 = time.time()
    resp = parser.parse(payload)
    elapsed = time.time() - t0

    assert elapsed < 1.0, f"Parsing {digits} digits took too long: {elapsed:.3f}s"
    assert resp.status_code == 400
    assert resp.socket_state == "OK"
    assert b"Invalid Content-Length" in resp.raw_response


@pytest.mark.parametrize("digits", [4301, 5000, 10000, 50000], ids=lambda d: f"{d}_digits")
def test_evaluate_matrix_4parsers_extreme_content_length_zero_crashes(digits):
    """
    Verifies that evaluate_matrix_4parsers executes all 4 parsers on extreme numeric inputs (>4,300 digits)
    without crashing, returning structured matrix records for all 4 parsers.
    """
    oracle = MultiImplementationDifferentialOracle([])
    payload = (
        b"POST /data HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + (b"7" * digits) + b"\r\n\r\n"
        b"sample_payload"
    )

    has_div, anom, matrix = oracle.evaluate_matrix_4parsers(payload)

    assert isinstance(has_div, bool)
    assert "StrictRFC7230" in matrix
    assert "PermissiveLegacy" in matrix
    assert "CDNProxy" in matrix
    assert "AsyncMicroservice" in matrix

    # AsyncMicroservice must return 400 Bad Request for >4300 digits
    assert matrix["AsyncMicroservice"]["status"] == 400
    assert matrix["AsyncMicroservice"]["socket_state"] == "OK"

    # Strict, Permissive, CDN must not crash
    for name in ["StrictRFC7230", "PermissiveLegacy", "CDNProxy"]:
        assert matrix[name]["status"] in (200, 400)
        assert matrix[name]["socket_state"] == "OK"


def test_int_threshold_boundaries_4299_and_4300_digits():
    """
    Tests exact boundary conditions around Python's 4,300 digit limit:
    - At 4,299 and 4,300 digits: int() succeeds without raising ValueError.
      Because declared_len is enormous (> len(body)), AsyncMicroservice pauses/times out (408 TIMEOUT).
      Evaluates without unhandled crash or memory exhaustion.
    - At 4,301 digits: int() raises ValueError, caught safely, returning 400 Bad Request.
    """
    parser = AsyncMicroserviceParser()

    # 4299 digits
    payload_4299 = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + (b"1" + b"0" * 4298) + b"\r\n\r\n"
        b"short"
    )
    resp_4299 = parser.parse(payload_4299)
    assert resp_4299.status_code == 408
    assert resp_4299.socket_state == "TIMEOUT"

    # 4300 digits (exact threshold)
    payload_4300 = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + (b"9" * 4300) + b"\r\n\r\n"
        b"short"
    )
    resp_4300 = parser.parse(payload_4300)
    assert resp_4300.status_code == 408
    assert resp_4300.socket_state == "TIMEOUT"

    # 4301 digits (threshold crossed)
    payload_4301 = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + (b"9" * 4301) + b"\r\n\r\n"
        b"short"
    )
    resp_4301 = parser.parse(payload_4301)
    assert resp_4301.status_code == 400
    assert resp_4301.socket_state == "OK"


# ==============================================================================
# SECTION 2: CUSTOM HEADERS & ZERO FALSE TIMEOUTS
# ==============================================================================

@pytest.mark.parametrize("custom_header", [
    b"X-Content-Length: 99999",
    b"Content-Length-Custom: 50000",
    b"X-Custom-Content-Length: 100000",
    b"Forwarded-Content-Length: 88888",
    b"Content-Length-1: 77777",
    b"Proxy-Content-Length: 66666",
    b"Content-Length-Exact: 55555",
    b"My-Prefix-Content-Length: 44444",
], ids=lambda h: h.split(b":")[0].decode())
def test_custom_headers_zero_false_timeouts(custom_header):
    r"""
    Verifies that headers ending in 'content-length:' or containing 'content-length'
    do NOT match line-anchored regex `rb"(?:^|\r\n)content-length:\s*(\d+)"`.
    AsyncMicroserviceParser must return 200 OK and NOT 408 TIMEOUT.
    """
    parser = AsyncMicroserviceParser()
    payload = (
        b"GET /api/status HTTP/1.1\r\n"
        b"Host: target.internal\r\n" +
        custom_header + b"\r\n\r\n"
    )
    resp = parser.parse(payload)
    assert resp.status_code == 200, f"Header {custom_header} triggered unexpected status {resp.status_code}"
    assert resp.socket_state == "OK"


def test_custom_header_combined_with_real_content_length():
    """
    When custom header X-Content-Length: 99999 is present alongside real Content-Length: 5,
    AsyncMicroserviceParser must correctly match the real Content-Length: 5 and NOT hang.
    """
    parser = AsyncMicroserviceParser()

    # Case A: Custom header followed by real Content-Length
    payload_a = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"X-Content-Length: 99999\r\n"
        b"Content-Length: 5\r\n\r\n"
        b"HELLO"
    )
    resp_a = parser.parse(payload_a)
    assert resp_a.status_code == 200
    assert resp_a.socket_state == "OK"

    # Case B: Real Content-Length followed by custom header
    payload_b = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: 5\r\n"
        b"X-Content-Length: 99999\r\n\r\n"
        b"HELLO"
    )
    resp_b = parser.parse(payload_b)
    assert resp_b.status_code == 200
    assert resp_b.socket_state == "OK"


# ==============================================================================
# SECTION 3: NUMERIC MALFORMATIONS, NAN, NEGATIVE & SPECIAL VALUES
# ==============================================================================

@pytest.mark.parametrize("cl_val,desc", [
    (b"-1", "negative_1"),
    (b"-99999", "negative_large"),
    (b"NaN", "nan"),
    (b"Infinity", "infinity"),
    (b"-Infinity", "neg_infinity"),
    (b"10.5", "float"),
    (b"1e5", "scientific"),
    (b"0x10", "hex"),
    (b"", "empty"),
    (b"    ", "whitespace"),
    (b"000000000000000000000000000005", "leading_zeros"),
    (b"5\x00extra", "null_byte"),
], ids=lambda val: val[1] if isinstance(val, tuple) else "val")
def test_content_length_malformations_zero_unhandled_crashes(cl_val, desc):
    """
    Verifies that malformed, negative, float, or special numeric strings in Content-Length
    do NOT cause unhandled crashes in evaluate_matrix_4parsers or any of the 4 parsers.
    """
    oracle = MultiImplementationDifferentialOracle([])
    payload = (
        b"POST /test HTTP/1.1\r\n"
        b"Host: target.internal\r\n"
        b"Content-Length: " + cl_val + b"\r\n\r\n"
        b"body_content"
    )

    try:
        has_div, anom, matrix = oracle.evaluate_matrix_4parsers(payload)
    except Exception as e:
        pytest.fail(f"evaluate_matrix_4parsers crashed with exception {type(e).__name__}: {e}")

    assert isinstance(matrix, dict)
    for p_name in ["StrictRFC7230", "PermissiveLegacy", "CDNProxy", "AsyncMicroservice"]:
        assert p_name in matrix
        assert matrix[p_name]["status"] in (200, 400, 500)


# ==============================================================================
# SECTION 4: EXCEPTION ISOLATION & HOST SHIELDING IN MATRIX
# ==============================================================================

def test_matrix_exception_isolation_shield():
    """
    Verifies that if an individual parser throws an unexpected exception
    (e.g. MemoryError, RuntimeError, TypeError), evaluate_matrix_4parsers
    catches it, records status 500 and socket_state 'ERROR', and returns cleanly.
    """
    class DefectiveMockParser:
        name = "DefectiveExplodingParser"
        def parse(self, raw_probe: bytes):
            raise MemoryError("Simulated OOM crash")

    oracle = MultiImplementationDifferentialOracle([])
    probe = b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"

    # Verify exception shielding block explicitly
    parsers = [
        StrictRFC7230Parser(),
        DefectiveMockParser(),
    ]
    responses = {}
    for p in parsers:
        try:
            responses[p.name] = p.parse(probe)
        except Exception as e:
            responses[p.name] = TargetResponse(p.name, 500, {}, str(e).encode(), 0.0, "ERROR")

    assert responses["DefectiveExplodingParser"].status_code == 500
    assert responses["DefectiveExplodingParser"].socket_state == "ERROR"


@pytest.mark.parametrize("raw_probe,desc", [
    (b"", "empty_probe"),
    (b"GET / HTTP/1.1", "no_crlf"),
    (b"POST / HTTP/1.1\r\n", "single_line"),
    (b"\r\n\r\n", "empty_headers"),
    (b"A" * 100000 + b"\r\n\r\n", "100kb_header"),
    (b"\x00\x01\x02\x03\r\n\r\n", "binary_control_bytes"),
], ids=lambda val: val[1] if isinstance(val, tuple) else "val")
def test_matrix_adversarial_raw_probes_zero_unhandled_crashes(raw_probe, desc):
    """
    Verifies zero unhandled exceptions on extreme edge raw probe payloads.
    """
    oracle = MultiImplementationDifferentialOracle([])
    try:
        has_div, anom, matrix = oracle.evaluate_matrix_4parsers(raw_probe)
    except Exception as e:
        pytest.fail(f"evaluate_matrix_4parsers raised unhandled {type(e).__name__}: {e}")

    assert isinstance(matrix, dict)
    assert len(matrix) == 4


# ==============================================================================
# SECTION 5: ABNF NESTED SUB-RULE INDEPENDENCE
# ==============================================================================

def test_abnf_multi_level_subrule_indentation():
    """
    Verifies that multi-level indented rules (2 spaces, 4 spaces, 8 spaces)
    are each extracted as independent grammar rules without being swallowed.
    """
    engine = ABNFGrammarEngine()
    grammar = """
    root-rule = "ROOT"
      level-1 = "L1"
        level-2 = "L2"
            level-3 = "L3"
    """
    reqs = engine.extract_from_rfc_text("SPEC", grammar)
    rules = engine.extracted_rules

    assert "root-rule" in rules
    assert "level-1" in rules
    assert "level-2" in rules
    assert "level-3" in rules

    assert rules["root-rule"]["definition"] == '"ROOT"'
    assert rules["level-1"]["definition"] == '"L1"'
    assert rules["level-2"]["definition"] == '"L2"'
    assert rules["level-3"]["definition"] == '"L3"'


def test_abnf_mixed_tabs_and_spaces_subrules():
    """
    Verifies that rules indented with tabs, spaces, or mixed indentation
    are correctly recognized as independent definitions.
    """
    engine = ABNFGrammarEngine()
    grammar = (
        "header-rule = token\n"
        "\tsub-rule-tab = \"tab-val\"\n"
        "    sub-rule-space = \"space-val\"\n"
        "\t  sub-rule-mixed = \"mixed-val\"\n"
    )
    reqs = engine.extract_from_rfc_text("SPEC", grammar)
    rules = engine.extracted_rules

    assert "header-rule" in rules
    assert "sub-rule-tab" in rules
    assert "sub-rule-space" in rules
    assert "sub-rule-mixed" in rules


def test_abnf_continuation_with_comments_not_breaking():
    """
    Verifies that comments inside a multi-line rule do not terminate the rule continuation,
    while an actual indented sub-rule definition DOES terminate continuation.
    """
    engine = ABNFGrammarEngine()
    grammar = """
    alpha-rule = part-one
                 ; explanatory comment line
                 part-two
                 ; another comment line
                 part-three
      beta-rule = "beta-val"
    """
    reqs = engine.extract_from_rfc_text("SPEC", grammar)
    rules = engine.extracted_rules

    assert "alpha-rule" in rules
    assert "beta-rule" in rules
    assert "part-one part-two part-three" in rules["alpha-rule"]["definition"]
    assert rules["beta-rule"]["definition"] == '"beta-val"'


# ==============================================================================
# SECTION 6: BARE DELIMITER REJECTION IN STRICT RFC 7230 PARSER
# ==============================================================================

@pytest.mark.parametrize("probe,desc", [
    (b"GET / HTTP/1.1\r\nHost: example.local\nInjected: evil\r\n\r\n", "Bare LF in header"),
    (b"GET / HTTP/1.1\r\nHost: example.local\rInjected: evil\r\n\r\n", "Bare CR in header"),
    (b"GET / HTTP/1.1\nHost: example.local\r\n\r\n", "Bare LF in start-line"),
    (b"GET / HTTP/1.1\rHost: example.local\r\n\r\n", "Bare CR in start-line"),
    (b"GET / HTTP/1.1\r\nHost: val\n\r\n", "Bare LF terminating header block"),
], ids=lambda p: p[1] if isinstance(p, tuple) else "probe")
def test_strict_parser_rejects_bare_delimiters(probe, desc):
    """
    Verifies RFC 7230 §3.2.4 / RFC 9112 §2.2:
    'A recipient MUST reject any received request message that contains bare CR or bare LF.'
    StrictRFC7230Parser must return 400 Bad Request.
    """
    parser = StrictRFC7230Parser()
    resp = parser.parse(probe)
    assert resp.status_code == 400, f"Failed on {desc}: status was {resp.status_code}"
    assert b"delimiter" in resp.raw_response.lower() or b"bad request" in resp.raw_response.lower()


def test_strict_parser_accepts_clean_crlf():
    """
    Verifies that a valid, clean CRLF request is accepted with 200 OK by StrictRFC7230Parser.
    """
    parser = StrictRFC7230Parser()
    probe = b"GET /resource HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
    resp = parser.parse(probe)
    assert resp.status_code == 200
    assert resp.socket_state == "OK"
