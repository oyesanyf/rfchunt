"""
Adversarial Empirical Challenge Suite: Milestone 2 Remediation 2 (Challenger M2-Rem-2).
Focus:
1. Multi-line ABNF extraction under complex nested indentation and multi-alternative rules.
2. Strict RFC 7230 parser with bare \r, bare \n, mixed terminators, and trailing/leading whitespace.
3. Metamorphic 4-parser differential matrix behavior and multi-trial reproducibility.
"""

import time
import pytest
from pathlib import Path
from typing import Dict, List, Tuple

from engine.abnf_engine import ABNFGrammarEngine, _strip_abnf_comment
from engine.differential_oracle import (
    StrictRFC7230Parser,
    PermissiveLegacyParser,
    CDNProxyParser,
    AsyncMicroserviceParser,
    MultiImplementationDifferentialOracle,
)
from engine.taxonomy import AnomalyCategory


# ==============================================================================
# SECTION 1: EMPIRICAL STRESS TESTS — COMPLEX NESTED INDENTATION & ABNF RULES
# ==============================================================================

def test_abnf_complex_nested_indentation_hierarchy():
    """
    Stress-tests multi-level nested indentation:
    Parent rule (indent 0) -> Child rule (indent 2) -> Grandchild rule (indent 4) -> Sibling (indent 0).
    Ensures no child rule is swallowed into its parent or ancestor continuation.
    """
    engine = ABNFGrammarEngine()
    grammar = """
parent-rule = token /
    ( sub-token-1
      sub-token-2 )
  child-rule = "child-val-1" /
      "child-val-2"
    grandchild-rule = "grandchild-val"
sibling-rule = "sibling-val"
"""
    reqs = engine.extract_from_rfc_text("TEST", grammar)
    rules = engine.extracted_rules

    assert "parent-rule" in rules
    assert "child-rule" in rules
    assert "grandchild-rule" in rules
    assert "sibling-rule" in rules

    # Verify each rule contains only its elements
    assert "token / ( sub-token-1 sub-token-2 )" == rules["parent-rule"]["definition"]
    assert '"child-val-1" / "child-val-2"' == rules["child-rule"]["definition"]
    assert '"grandchild-val"' == rules["grandchild-rule"]["definition"]
    assert '"sibling-val"' == rules["sibling-rule"]["definition"]


def test_abnf_multi_alternative_incremental_rules():
    """
    Stress-tests RFC 5234 §2.3 incremental alternatives (=/) with multiple continuations,
    interleaved comments, and multi-line extensions.
    """
    engine = ABNFGrammarEngine()
    grammar = """
http-method = "GET" /
              "POST"
http-method =/ "PUT" /
               "DELETE"
http-method =/ "HEAD"
http-method =/ "OPTIONS" /
               ; comment before final extension
               "TRACE"
"""
    reqs = engine.extract_from_rfc_text("TEST", grammar)
    assert "http-method" in engine.extracted_rules
    defn = engine.extracted_rules["http-method"]["definition"]

    # Verify all alternatives are concatenated with ' / '
    expected_tokens = ['"GET"', '"POST"', '"PUT"', '"DELETE"', '"HEAD"', '"OPTIONS"', '"TRACE"']
    for token in expected_tokens:
        assert token in defn, f"Missing token {token} in definition: {defn}"
    assert defn.count("/") >= 6


def test_abnf_tab_and_mixed_indentation_continuations():
    """
    Stress-tests continuation lines indented with tabs, mixed spaces and tabs,
    and varying depth continuations under RFC 5234 §2.1.
    """
    engine = ABNFGrammarEngine()
    grammar = (
        "rule-with-tabs = elem1\n"
        "\telem2\n"
        "\t\telem3\n"
        "  \telem4\n"
        "rule-after = next-elem\n"
    )
    reqs = engine.extract_from_rfc_text("TEST", grammar)
    rules = engine.extracted_rules

    assert "rule-with-tabs" in rules
    assert "rule-after" in rules
    assert rules["rule-with-tabs"]["definition"] == "elem1 elem2 elem3 elem4"
    assert rules["rule-after"]["definition"] == "next-elem"


def test_abnf_quoted_strings_with_special_characters():
    """
    Stress-tests ABNF extraction when rule bodies contain quoted strings with:
    equals signs '=', incremental operators '=/', semicolons ';', slashes '/', and spaces.
    """
    engine = ABNFGrammarEngine()
    grammar = """
cookie-pair = cookie-name "=" cookie-value
boundary-param = "boundary=" ( token / quoted-string )
tricky-rule = "a=b;c=/d" /
              "part2;not-comment" ; actual comment
"""
    reqs = engine.extract_from_rfc_text("TEST", grammar)
    rules = engine.extracted_rules

    assert "cookie-pair" in rules
    assert 'cookie-name "=" cookie-value' in rules["cookie-pair"]["definition"]

    assert "boundary-param" in rules
    assert '"boundary=" ( token / quoted-string )' in rules["boundary-param"]["definition"]

    assert "tricky-rule" in rules
    assert '"a=b;c=/d" / "part2;not-comment"' == rules["tricky-rule"]["definition"]


def test_abnf_real_rfc_framing_structures():
    """
    Verifies extraction of critical framing rules from real RFC 9112 and RFC 7230 texts.
    """
    rfc9112_path = Path("rfcs/rfc9112.txt")
    if rfc9112_path.exists():
        text = rfc9112_path.read_text(encoding="utf-8", errors="ignore")
        engine = ABNFGrammarEngine()
        reqs = engine.extract_from_rfc_text("RFC9112", text)
        rules = engine.extracted_rules

        # Verify core rules extracted without truncation
        assert "HTTP-message" in rules
        assert "start-line CRLF *( field-line CRLF ) CRLF [ message-body ]" in rules["HTTP-message"]["definition"]
        assert "request-line" in rules
        assert "status-line" in rules
        assert "chunk-ext" in rules


# ==============================================================================
# SECTION 2: EMPIRICAL STRESS TESTS — STRICT RFC 7230 BARE DELIMITER REJECTION
# ==============================================================================

@pytest.mark.parametrize("bad_probe,desc", [
    (b"G\rET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "bare CR in method"),
    (b"G\nET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "bare LF in method"),
    (b"GET /a\rb HTTP/1.1\r\nHost: example.com\r\n\r\n", "bare CR in target"),
    (b"GET /a\nb HTTP/1.1\r\nHost: example.com\r\n\r\n", "bare LF in target"),
    (b"GET / HTTP/1.\r1\r\nHost: example.com\r\n\r\n", "bare CR in version"),
    (b"GET / HTTP/1.\n1\r\nHost: example.com\r\n\r\n", "bare LF in version"),
    (b"GET / HTTP/1.1\r\nHo\rst: example.com\r\n\r\n", "bare CR in header name"),
    (b"GET / HTTP/1.1\r\nHo\nst: example.com\r\n\r\n", "bare LF in header name"),
    (b"GET / HTTP/1.1\r\nHost: exam\rple.com\r\n\r\n", "bare CR in header value"),
    (b"GET / HTTP/1.1\r\nHost: exam\nple.com\r\n\r\n", "bare LF in header value"),
    (b"GET / HTTP/1.1\r\nHost: a\r\nInjected:\reval\r\n\r\n", "bare CR in header value 2"),
    (b"GET / HTTP/1.1\r\nHost: a\r\nInjected:\neval\r\n\r\n", "bare LF in header value 2"),
])
def test_strict_parser_rejects_bare_delimiters_in_all_header_positions(bad_probe, desc):
    """
    RFC 7230 §3.2.4 / RFC 9112 §2.2:
    A recipient MUST reject any received request message that contains bare CR or bare LF.
    StrictRFC7230Parser must reject every such payload with 400 Bad Request.
    """
    strict = StrictRFC7230Parser()
    resp = strict.parse(bad_probe)
    assert resp.status_code == 400, f"Failed for {desc}: got status {resp.status_code}"
    assert b"Bare delimiter error" in resp.raw_response or b"Malformed Request-Line" in resp.raw_response


@pytest.mark.parametrize("mixed_probe,desc", [
    (b"GET / HTTP/1.1\r\r\nHost: example.com\r\n\r\n", "mixed CR-CR-LF in reqline terminator"),
    (b"GET / HTTP/1.1\n\r\nHost: example.com\r\n\r\n", "mixed LF-CR-LF in reqline terminator"),
    (b"GET / HTTP/1.1\r\nHost: example.com\r\r\n\r\n", "mixed CR-CR-LF in header terminator"),
    (b"GET / HTTP/1.1\r\nHost: example.com\r\n\n", "incomplete with trailing bare LF delimiter"),
    (b"GET / HTTP/1.1\r\nHost: example.com\n\n", "bare LF-LF double terminator"),
    (b"GET / HTTP/1.1\r\nHost: example.com\r\r", "bare CR-CR double terminator"),
    (b"GET / HTTP/1.1\r\n\r\n", "valid minimal request"),
])
def test_strict_parser_mixed_and_boundary_terminators(mixed_probe, desc):
    """
    Tests line terminator combinations. All non-CRLF delimiters must be rejected (400),
    while genuine CRLF CRLF minimal requests are accepted (200).
    """
    strict = StrictRFC7230Parser()
    resp = strict.parse(mixed_probe)
    if desc == "valid minimal request":
        assert resp.status_code == 200
    else:
        assert resp.status_code == 400, f"Expected 400 for {desc}, got {resp.status_code}"


def test_strict_parser_whitespace_around_colon_and_values():
    """
    RFC 7230 §3.2.4:
    - No whitespace is allowed between the header field-name and colon.
    - OWS (optional whitespace) is allowed after the colon and before CRLF.
    """
    strict = StrictRFC7230Parser()

    # Reject space before colon
    resp_space = strict.parse(b"GET / HTTP/1.1\r\nHost : example.com\r\n\r\n")
    assert resp_space.status_code == 400
    assert b"Whitespace before colon" in resp_space.raw_response

    # Reject tab before colon
    resp_tab = strict.parse(b"GET / HTTP/1.1\r\nHost\t: example.com\r\n\r\n")
    assert resp_tab.status_code == 400
    assert b"Whitespace before colon" in resp_tab.raw_response

    # Reject multiple spaces/tabs before colon
    resp_multi = strict.parse(b"GET / HTTP/1.1\r\nHost  \t : example.com\r\n\r\n")
    assert resp_multi.status_code == 400
    assert b"Whitespace before colon" in resp_multi.raw_response

    # Accept OWS spaces and tabs in field value
    resp_valid_spaces = strict.parse(b"GET / HTTP/1.1\r\nHost:   example.com   \r\n\r\n")
    assert resp_valid_spaces.status_code == 200
    assert resp_valid_spaces.headers["host"] == "example.com"

    resp_valid_tabs = strict.parse(b"GET / HTTP/1.1\r\nHost:\t\texample.com\t\t\r\n\r\n")
    assert resp_valid_tabs.status_code == 200
    assert resp_valid_tabs.headers["host"] == "example.com"


# ==============================================================================
# SECTION 3: 4-PARSER DIFFERENTIAL MATRIX & MULTI-TRIAL REPRODUCIBILITY
# ==============================================================================

def test_differential_matrix_bare_delimiter_divergence():
    """
    Probes containing bare delimiters (bare LF, bare CR, mixed terminators) must trigger
    divergence across the 4-parser differential matrix:
    Strict RFC 7230 strictly rejects with 400 Bad Request, while Permissive Legacy tolerates them (200 OK).
    """
    oracle = MultiImplementationDifferentialOracle([])

    bare_probes = [
        b"GET / HTTP/1.1\r\nHost: example.com\nInjected: value\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\rInjected: value\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\n\n",
    ]

    for probe in bare_probes:
        has_div, anom, matrix = oracle.evaluate_matrix_4parsers(probe)
        assert has_div is True
        assert anom is not None
        assert anom.category == AnomalyCategory.PARSER_DIVERGENCE
        assert matrix["StrictRFC7230"]["status"] == 400
        # Permissive parser normalizes bare delimiters and accepts
        assert matrix["PermissiveLegacy"]["status"] == 200


def test_differential_matrix_multi_trial_reproducibility():
    """
    Protocol Research Reproducibility Invariant:
    Differential matrix evaluation across the 4 parsers must be 100% stable and reproducible
    across repeated trials (minimum 3 repeated trials).
    """
    oracle = MultiImplementationDifferentialOracle([])
    test_probe = b"GET / HTTP/1.1\r\nHost: example.com\nInjected: evil\r\n\r\n"

    trials = []
    for _ in range(5):
        has_div, anom, matrix = oracle.evaluate_matrix_4parsers(test_probe)
        trial_summary = (
            has_div,
            matrix["StrictRFC7230"]["status"],
            matrix["PermissiveLegacy"]["status"],
            matrix["CDNProxy"]["status"],
            matrix["AsyncMicroservice"]["status"],
        )
        trials.append(trial_summary)

    # Assert 100% reproducibility across all 5 trials
    assert len(set(trials)) == 1
    assert trials[0] == (True, 400, 200, 200, 200)
