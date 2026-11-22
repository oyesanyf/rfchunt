"""
Tests for AIxCC Upgrade #4: Canonical Structural Fingerprinting,
Offline Known-Technique Novelty Corpus, and Strict 3-Condition Novelty Gating.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sqlite3
import urllib.request

import pytest

from database import Database
from engine.causal_classifier import CausalAnomalyClassifier
from engine.exploit_exporter import ExploitExporter
from engine.novelty_corpus import (
    DEFAULT_NOVELTY_THRESHOLD,
    CanonicalStructuralFingerprinter,
    NoveltyCorpusIndex,
    refresh_novelty_corpus,
)
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    RFCRequirement,
    ReproducibleVulnerability,
    RequirementType,
)


def _make_vuln(
    probe: bytes,
    *,
    vuln_id: str = "VULN-TEST-001",
    impact: ImpactClass = ImpactClass.DESYNCHRONIZATION,
    attempts: int = 3,
    successes: int = 3,
    rate: float = 1.0,
) -> ReproducibleVulnerability:
    return ReproducibleVulnerability(
        vuln_id=vuln_id,
        anomaly_id=f"ANOM-{vuln_id}",
        impact=impact,
        minimized_probe=probe,
        reproducibility_rate=rate,
        verification_attempts=attempts,
        successful_reproductions=successes,
        delta_debug_steps=2,
    )


# ---------------------------------------------------------------------------
# 1. Legacy 4-Entry KNOWN_PATTERNS Replaced
# ---------------------------------------------------------------------------

def test_legacy_known_patterns_removed_and_corpus_wired():
    assert not hasattr(CausalAnomalyClassifier, "KNOWN_PATTERNS")
    classifier = CausalAnomalyClassifier(include_workspace_templates=False)
    assert not hasattr(classifier, "KNOWN_PATTERNS")
    assert isinstance(classifier.fingerprinter, CanonicalStructuralFingerprinter)
    assert isinstance(classifier.novelty_corpus, NoveltyCorpusIndex)
    assert classifier.novelty_threshold == DEFAULT_NOVELTY_THRESHOLD
    assert len(classifier.novelty_corpus) >= 35


# ---------------------------------------------------------------------------
# 2. Canonical Wire & AST Fingerprinting Invariance & Discrimination
# ---------------------------------------------------------------------------

def test_wire_fingerprinting_normalizes_superficial_changes_and_distinguishes_structures():
    fp_engine = CanonicalStructuralFingerprinter()

    # Same CL.TE structure with completely different hosts, paths, query nonces, noise headers, and smuggled target
    probe_a = (
        b"POST /api/v1/orders?nonce=11111&ts=1700000 HTTP/1.1\r\n"
        b"Host: alpha-prod.example.com\r\n"
        b"User-Agent: ProbeBot/1.0\r\n"
        b"X-Request-Id: deadbeef-0001\r\n"
        b"Content-Length: 44\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n"
        b"GET /404 HTTP/1.1\r\nHost: alpha-prod.example.com\r\n\r\n"
    )
    probe_b = (
        b"POST /checkout/confirm?session=zzz999 HTTP/1.1\r\n"
        b"Host: beta-edge.internal:8443\r\n"
        b"X-Nonce: 999888777\r\n"
        b"Cookie: sid=abc123\r\n"
        b"Content-Length: 52\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n"
        b"GET /admin/secret HTTP/1.1\r\nHost: beta-edge.internal\r\n\r\n"
    )
    fp_a = fp_engine.fingerprint_wire(probe_a)
    fp_b = fp_engine.fingerprint_wire(probe_b)
    assert fp_a.fingerprint_id == fp_b.fingerprint_id
    assert fp_a.canonical_form == fp_b.canonical_form
    assert fp_engine.jaccard_similarity(fp_a, fp_b) == 1.0

    # Structurally distinct techniques must have low pairwise similarity
    probe_obs_fold = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Foo: a\r\n b\r\n\r\n"
    probe_pre_colon = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Bar : b\r\n\r\n"
    probe_h2_cl = (
        b":method: POST\r\n:path: /\r\n:scheme: https\r\n:authority: example.com\r\n"
        b"content-length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    probe_spc = b"HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n"

    fp_obs = fp_engine.fingerprint_wire(probe_obs_fold)
    fp_pre = fp_engine.fingerprint_wire(probe_pre_colon)
    fp_h2 = fp_engine.fingerprint_wire(probe_h2_cl)
    fp_spc = fp_engine.fingerprint_wire(probe_spc)

    assert fp_engine.jaccard_similarity(fp_obs, fp_pre) < 0.50
    assert fp_engine.jaccard_similarity(fp_a, fp_h2) < 0.50
    assert fp_engine.jaccard_similarity(fp_a, fp_spc) < 0.30
    assert fp_engine.jaccard_similarity(fp_obs, fp_spc) < 0.30

    # Divergence vector tokens are captured deterministically
    div_mat = {
        "StrictRFC7230": {"status": 400, "socket_state": "OK"},
        "PermissiveLegacy": {"status": 200, "socket_state": "OK"},
    }
    fp_with_div = fp_engine.fingerprint_wire(probe_obs_fold, divergence_matrix=div_mat)
    assert "DIV:PARSER_DIVERGENCE" in fp_with_div.tokens
    assert "DIV:ACCEPT_VS_REJECT" in fp_with_div.tokens


def test_ast_fingerprinting_normalizes_identifiers_and_distinguishes_cwe_classes():
    fp_engine = CanonicalStructuralFingerprinter()

    sqli_1 = {
        "file_path": "app/routes/users.py",
        "line_number": 42,
        "cwe_id": "CWE-89",
        "source": "request.args.get('user_id')",
        "sink": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
        "sanitizers": [],
    }
    sqli_2 = {
        "file_path": "services/billing/orders.py",
        "line_number": 199,
        "cwe": "89",
        "source": "req.query.order_key",
        "sink": "db.execute('SELECT * FROM orders WHERE key=' + order_key)",
        "sanitizers": "none",
    }
    cmdi = {
        "file_path": "app/routes/tools.py",
        "line_number": 17,
        "cwe_id": "CWE-78",
        "source": "request.form['host']",
        "sink": "subprocess.run(cmd, shell=True)",
        "sanitizers": [],
    }
    sqli_sanitized = {
        "file_path": "app/routes/safe.py",
        "line_number": 88,
        "cwe_id": "CWE-89",
        "source": "request.args.get('user_id')",
        "sink": "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
        "sanitizers": ["parameterized_statement"],
    }

    fp_s1 = fp_engine.fingerprint_ast(sqli_1)
    fp_s2 = fp_engine.fingerprint_ast(sqli_2)
    fp_cmd = fp_engine.fingerprint_ast(cmdi)
    fp_safe = fp_engine.fingerprint_ast(sqli_sanitized)

    assert fp_s1.fingerprint_id == fp_s2.fingerprint_id
    assert fp_engine.jaccard_similarity(fp_s1, fp_s2) == 1.0
    assert fp_engine.jaccard_similarity(fp_s1, fp_cmd) < 0.45
    assert fp_engine.jaccard_similarity(fp_s1, fp_safe) < 0.65


# ---------------------------------------------------------------------------
# 3. Known PortSwigger & CWE Techniques Score >= Threshold (NOT Novel)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,probe",
    [
        (
            "CL.TE",
            b"POST /submit?r=99 HTTP/1.1\r\nHost: shop.victim.test\r\nContent-Length: 48\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /secret HTTP/1.1\r\nHost: shop.victim.test\r\n\r\n",
        ),
        (
            "TE.CL",
            b"POST /upload HTTP/1.1\r\nHost: api.victim.test\r\nContent-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n2f\r\nGET /private HTTP/1.1\r\nHost: api.victim.test\r\n\r\n\r\n0\r\n\r\n",
        ),
        (
            "TE.TE_duplicate",
            b"POST /login HTTP/1.1\r\nHost: auth.victim.test\r\nContent-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: bogus\r\n\r\n0\r\n\r\n",
        ),
        (
            "TE.TE_vtab_obfuscation",
            b"POST /api HTTP/1.1\r\nHost: edge.victim.test\r\nContent-Length: 6\r\n"
            b"Transfer-Encoding:\x0bchunked\r\n\r\n0\r\n\r\nG",
        ),
        (
            "H2.CL",
            b":method: POST\r\n:path: /v2/pay\r\n:scheme: https\r\n:authority: pay.victim.test\r\n"
            b"content-length: 0\r\n\r\nGET /internal HTTP/1.1\r\nHost: pay.victim.test\r\n\r\n",
        ),
        (
            "H2.TE",
            b":method: POST\r\n:path: /v2/pay\r\n:scheme: https\r\n:authority: pay.victim.test\r\n"
            b"transfer-encoding: chunked\r\n\r\n0\r\n\r\nGET /internal HTTP/1.1\r\nHost: pay.victim.test\r\n\r\n",
        ),
        (
            "H2.0_tunnel",
            b":method: GET\r\n:path: / HTTP/1.1\\r\\nHost: x.test\\r\\n\\r\\nGET /admin HTTP/1.1\r\n"
            b":scheme: https\r\n:authority: x.test\r\n\r\n",
        ),
        (
            "H2.0_connect_tunnel",
            b":method: CONNECT\r\n:authority: edge.victim.test:443\r\n\r\n"
            b"GET /admin HTTP/1.1\r\nHost: internal.local\r\n\r\n",
        ),
        (
            "CL.0_browser_desync",
            b"GET /assets/logo.png HTTP/1.1\r\nHost: cdn.victim.test\r\nConnection: keep-alive\r\n"
            b"Content-Length: 45\r\n\r\nGET /poison HTTP/1.1\r\nHost: cdn.victim.test\r\n\r\n",
        ),
        (
            "pause_based_desync",
            b"POST /slow HTTP/1.1\r\nHost: origin.victim.test\r\nExpect: 100-continue\r\nContent-Length: 120\r\n\r\n",
        ),
        (
            "chunk_ext",
            b"POST /stream HTTP/1.1\r\nHost: s.victim.test\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5;foo=bar\r\nhello\r\n0;done=true\r\n\r\n",
        ),
        (
            "chunk_trailer",
            b"POST /stream HTTP/1.1\r\nHost: s.victim.test\r\nTransfer-Encoding: chunked\r\n"
            b"Trailer: X-Real-IP\r\n\r\n0\r\nX-Real-IP: 127.0.0.1\r\n\r\n",
        ),
        (
            "obs_fold",
            b"GET /home?k=1 HTTP/1.1\r\nHost: legacy.victim.test\r\nX-Header: line1\r\n\tline2\r\n\r\n",
        ),
        (
            "pre_colon_ws",
            b"GET /profile HTTP/1.1\r\nHost: edge.victim.test\r\nX-Any-Name : val\r\n\r\n",
        ),
        (
            "bare_lf",
            b"GET /items HTTP/1.1\nHost: bare.victim.test\n\n",
        ),
        (
            "crlf_header_injection",
            b"GET /search?q=1%0d%0aX-Injected:%20evil HTTP/1.1\r\nHost: web.victim.test\r\n\r\n",
        ),
    ],
)
def test_known_portswigger_techniques_not_tagged_novel(label, probe):
    classifier = CausalAnomalyClassifier(include_workspace_templates=False)
    vuln = _make_vuln(probe, vuln_id=f"VULN-{label}", attempts=4, successes=4, rate=1.0)
    is_novel, tech = classifier.classify_novelty(vuln, oracle_violated=True)

    assert is_novel is False, f"Known technique {label} was falsely tagged novel: {classifier.last_novelty_assessment}"
    assert tech is None
    assert classifier.last_novelty_assessment is not None
    assert classifier.last_novelty_assessment["tag"] == "known_technique"
    assert classifier.last_novelty_assessment["max_similarity"] >= classifier.novelty_threshold
    assert classifier.last_novelty_assessment["nearest_known_technique"] is not None


def test_known_cwe_ast_finding_scores_above_threshold_and_not_novel():
    classifier = CausalAnomalyClassifier(include_workspace_templates=False)
    ast_finding = {
        "file_path": "pkg/api/search.py",
        "line_number": 91,
        "cwe_id": "CWE-89",
        "source": "request.args.get('q')",
        "sink": "cursor.execute('SELECT * FROM items WHERE name=' + q)",
        "sanitizers": [],
    }
    vuln = _make_vuln(b"", vuln_id="VULN-AST-SQLI", impact=ImpactClass.PARSER_CONFUSION)
    is_novel, tech = classifier.classify_novelty(vuln, ast_finding=ast_finding, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["max_similarity"] >= classifier.novelty_threshold
    assert classifier.last_novelty_assessment["nearest_known_technique"]["entry_id"] == "CWE-89-SQL-INJECTION"


# ---------------------------------------------------------------------------
# 4. Workspace Nuclei Templates & terminator.db Prior Findings Prevent Re-Tagging
# ---------------------------------------------------------------------------

def test_workspace_nuclei_templates_indexed_offline(tmp_path):
    defense_dir = tmp_path / "defense_rules"
    defense_dir.mkdir(parents=True, exist_ok=True)

    # Create a custom Nuclei YAML template for a rare protocol extension combination
    nuclei_yaml = """id: rfchunt-custom-early-data-desync

info:
  name: Custom Early-Data Alt-Used Desync
  author: security-research
  severity: high
  description: Known workspace template for Early-Data + Alt-Used + Priority framing bug.
  classification:
    cwe-id: CWE-444
  tags: rfchunt,custom,early-data

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Early-Data: 1
        Alt-Used: {{Hostname}}
        Priority: u=0, i

    unsafe: true
"""
    (defense_dir / "custom_early_data.yaml").write_text(nuclei_yaml, encoding="utf-8")

    # Also verify ExploitExporter output format parses cleanly without error
    exported_vuln = _make_vuln(
        b"GET / HTTP/1.1\r\nHost: target.local\r\nContent-Digest: sha-256=:xyz:\r\nRepr-Digest: sha-256=:abc:\r\n\r\n",
        vuln_id="VULN-EXP-01",
    )
    (defense_dir / "exported_template.yaml").write_text(
        ExploitExporter.export_nuclei_template(exported_vuln),
        encoding="utf-8",
    )

    classifier = CausalAnomalyClassifier(workspace_root=tmp_path, include_workspace_templates=True)
    summary = classifier.novelty_corpus.summary()
    assert summary["by_source"].get("workspace_nuclei", 0) >= 2

    # Same structure with different host/path/nonce must match the workspace Nuclei template -> NOT novel
    matching_probe = (
        b"GET /checkout?nonce=777 HTTP/1.1\r\n"
        b"Host: prod.acme.org\r\n"
        b"X-Request-Id: abc-123\r\n"
        b"Early-Data: 1\r\n"
        b"Alt-Used: prod.acme.org\r\n"
        b"Priority: u=3\r\n\r\n"
    )
    vuln = _make_vuln(matching_probe, vuln_id="VULN-NUCLEI-DUP")
    is_novel, tech = classifier.classify_novelty(vuln, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["nearest_known_technique"]["source"] == "workspace_nuclei"
    assert classifier.last_novelty_assessment["max_similarity"] >= classifier.novelty_threshold


def test_terminator_db_prior_findings_loaded_and_deduplicated(tmp_path):
    db_file = tmp_path / "terminator.db"
    db = Database(db_path=str(db_file), encrypt_at_rest=False)
    try:
        # 1. Confirmed prior vulnerability in `reproducible_vulnerabilities`
        prior_probe = (
            "GET / HTTP/1.1\r\nHost: old-target.local\r\n"
            "Early-Data: 1\r\nContent-Digest: sha-256=:111:\r\n\r\n"
        )
        db.save_reproducible_vulnerability(
            vuln_id="VULN-PRIOR-DB-1",
            anomaly_id="ANOM-PRIOR-DB-1",
            impact=ImpactClass.PARSER_CONFUSION.value,
            minimized_probe=prior_probe,
            reproducibility_rate=1.0,
            verification_attempts=3,
            successful_reproductions=3,
            delta_debug_steps=2,
            provenance_chain=["test"],
        )

        # Transient / unverified row in DB MUST be ignored by corpus ingestion
        transient_probe = (
            "GET / HTTP/1.1\r\nHost: transient.local\r\n"
            "X-Unique-Transient-Proto: v9\r\n\r\n"
        )
        db.save_reproducible_vulnerability(
            vuln_id="VULN-TRANSIENT-IGNORE",
            anomaly_id="ANOM-TRANS",
            impact=ImpactClass.NON_REPRODUCIBLE_TRANSIENT.value,
            minimized_probe=transient_probe,
            reproducibility_rate=0.33,
            verification_attempts=3,
            successful_reproductions=1,
            delta_debug_steps=1,
            provenance_chain=[],
        )

        # 2. Prior `novel_techniques` row (Shared-Parser Confusion already discovered previously!)
        db.save_novel_technique(
            technique_id="TECH-SHARED-PARSER-CONFUSION",
            title="Shared-Parser Confusion (Response-to-Request Inversion)",
            conceptual_model="Previously discovered shared-parser confusion.",
            inversion_pattern="Status-line sent as request",
            affected_architectures=["Unified Parsers"],
            supporting_vulnerabilities=[],
            recommended_mitigation="Segregate request and response parsers.",
        )

        # 3. Prior `blackboard_nodes` FACT row carrying a confirmed wire probe
        fact_probe = (
            "GET / HTTP/1.1\r\nHost: bb-host.local\r\n"
            "Alt-Svc: h3=\":443\"\r\nKeep-Alive: timeout=5\r\n\r\n"
        )
        db.add_fact(
            "Confirmed Alt-Svc Keep-Alive framing anomaly",
            node_id="fact:vuln:alt-svc-01",
            task_id="task-1",
            domain="rfc9112",
            rfc_id="RFC9112",
            source_agent="triage_debugger_agent",
            payload={
                "vuln_id": "VULN-FACT-01",
                "impact": "PARSER_CONFUSION",
                "minimized_probe": fact_probe,
            },
        )

        classifier = CausalAnomalyClassifier(db=db, include_workspace_templates=False)
        src_counts = classifier.novelty_corpus.summary()["by_source"]
        assert src_counts.get("terminator_db_vuln", 0) == 1
        assert src_counts.get("terminator_db_novel", 0) == 1
        assert src_counts.get("terminator_db_fact", 0) == 1

        # Prior DB vuln with different Host & nonce -> NOT novel
        v_dup_vuln = _make_vuln(
            b"GET /v2?n=8 HTTP/1.1\r\nHost: new-target.org\r\nEarly-Data: 1\r\nContent-Digest: sha-256=:999:\r\n\r\n",
            vuln_id="VULN-NEW-DUP",
        )
        is_novel_1, _ = classifier.classify_novelty(v_dup_vuln, oracle_violated=True)
        assert is_novel_1 is False
        assert classifier.last_novelty_assessment["nearest_known_technique"]["source"] == "terminator_db_vuln"

        # Prior DB novel_technique (Shared-Parser Confusion) -> NOT re-tagged novel against same DB
        v_dup_spc = _make_vuln(
            b"HTTP/1.1 200 OK\r\nHost: another.org\r\n\r\n",
            vuln_id="VULN-SPC-DUP",
            impact=ImpactClass.PARSER_CONFUSION,
        )
        is_novel_2, _ = classifier.classify_novelty(v_dup_spc, oracle_violated=True)
        assert is_novel_2 is False
        assert classifier.last_novelty_assessment["nearest_known_technique"]["source"] == "terminator_db_novel"

        # Prior DB blackboard FACT -> NOT novel
        v_dup_fact = _make_vuln(
            b"GET /other HTTP/1.1\r\nHost: fresh.org\r\nAlt-Svc: h3=\":8443\"\r\nKeep-Alive: timeout=9\r\n\r\n",
            vuln_id="VULN-FACT-DUP",
        )
        is_novel_3, _ = classifier.classify_novelty(v_dup_fact, oracle_violated=True)
        assert is_novel_3 is False
        assert classifier.last_novelty_assessment["nearest_known_technique"]["source"] == "terminator_db_fact"

        # Transient DB row was ignored -> verified 3-trial discovery of that structure CAN be tagged novel!
        v_trans_now_confirmed = _make_vuln(
            b"GET / HTTP/1.1\r\nHost: confirmed.local\r\nX-Unique-Transient-Proto: v9\r\n\r\n",
            vuln_id="VULN-NOW-CONFIRMED",
        )
        is_novel_4, tech_4 = classifier.classify_novelty(v_trans_now_confirmed, oracle_violated=True)
        assert is_novel_4 is True
        assert tech_4 is not None
    finally:
        db.close()


def test_generic_vulnerabilities_table_name_supported(tmp_path):
    """Also supports SQLite schemas using a `vulnerabilities` table name directly."""
    db_path = tmp_path / "custom_findings.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "CREATE TABLE vulnerabilities ("
            "vuln_id TEXT PRIMARY KEY, impact TEXT, minimized_probe TEXT, "
            "verification_attempts INTEGER, reproducibility_rate REAL)"
        )
        conn.execute(
            "INSERT INTO vulnerabilities VALUES (?, ?, ?, ?, ?)",
            (
                "V-GEN-1",
                "PARSER_CONFUSION",
                "GET / HTTP/1.1\r\nHost: a.local\r\nX-Custom-Mesh-Cap: 1\r\n\r\n",
                3,
                1.0,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    corpus = NoveltyCorpusIndex(db_path=db_path, include_workspace_templates=False)
    res = corpus.query_wire(b"GET /x HTTP/1.1\r\nHost: b.local\r\nX-Custom-Mesh-Cap: 2\r\n\r\n")
    assert res.is_known is True
    assert res.nearest_matches[0].entry_id == "DB-VULN-V-GEN-1"


# ---------------------------------------------------------------------------
# 5. Genuinely Novel Findings & Strict 3-Condition Novelty Gate
# ---------------------------------------------------------------------------

def test_genuinely_novel_3_trial_invariant_violating_findings_tagged_novel_with_provenance():
    classifier = CausalAnomalyClassifier(include_workspace_templates=False)
    rfc_req = RFCRequirement(
        requirement_id="REQ-RFC9112-CUSTOM",
        rfc_id="RFC9112",
        section="Section 3.1",
        req_type=RequirementType.SEMANTIC_NORMATIVE,
        raw_statement="A server MUST NOT interpret response status lines as client requests.",
        formal_expression="request-line = method SP request-target SP HTTP-version",
        normative_keyword="MUST NOT",
    )

    # 1. Shared-Parser Confusion (3+ trials, invariant violated, below threshold)
    v_spc = _make_vuln(
        b"HTTP/1.1 200 OK\r\nHost: target.example\r\n\r\n",
        vuln_id="VULN-NOVEL-SPC",
        impact=ImpactClass.PARSER_CONFUSION,
        attempts=3,
        successes=3,
        rate=1.0,
    )
    is_novel, tech = classifier.classify_novelty(v_spc, rfc_context=rfc_req)
    assert is_novel is True
    assert tech is not None
    assert tech.technique_id == "TECH-SHARED-PARSER-CONFUSION"
    assert getattr(tech, "novelty_tag", None) == "novel"
    assert isinstance(getattr(tech, "structural_fingerprint", None), dict)
    assert tech.structural_fingerprint["fingerprint_id"].startswith("FP-WIRE-")
    assert tech.max_known_similarity < classifier.novelty_threshold
    assert len(tech.nearest_known_techniques) >= 1
    assert tech.provenance["gates"] == {
        "three_trial_confirmed": True,
        "oracle_or_invariant_violated": True,
        "below_similarity_threshold": True,
    }
    assert classifier.get_technique_provenance(tech.technique_id) == tech.provenance

    # 2. Novel wire framing with differential parser divergence
    novel_wire_probe = (
        b"QPACK-FRAME /stream HTTP/3.0\r\n"
        b"Host: edge.example\r\n"
        b"Capsule-Protocol: ?1\r\n"
        b"Quic-Transport-Params: v9\r\n\r\n"
    )
    div_matrix = {
        "StrictRFC7230": {"status": 400, "socket_state": "OK"},
        "CDNProxy": {"status": 200, "socket_state": "OK"},
    }
    anom = ImplementationAnomaly(
        anomaly_id="ANOM-NOVEL-H3",
        target_engine="4ParserDifferentialMatrix",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="Divergence across parsers on HTTP/3 Capsule-Protocol downgrade",
        expected_behavior="Consistent rejection",
        raw_probe=novel_wire_probe,
        raw_response=b"HTTP/1.1 200 OK\r\n\r\n",
        divergence_matrix=div_matrix,
    )
    v_h3 = _make_vuln(
        novel_wire_probe,
        vuln_id="VULN-NOVEL-H3",
        impact=ImpactClass.PARSER_CONFUSION,
        attempts=3,
        successes=3,
        rate=1.0,
    )
    is_novel_h3, tech_h3 = classifier.classify_novelty(v_h3, anomaly=anom)
    assert is_novel_h3 is True
    assert tech_h3 is not None
    assert tech_h3.technique_id.startswith("TECH-NOVEL-WIRE-")
    assert tech_h3.max_known_similarity < classifier.novelty_threshold
    assert "FP-WIRE-" in tech_h3.inversion_pattern

    # 3. Novel AST taint pattern (not in built-in CWE catalog)
    novel_ast = {
        "cwe_id": "CWE-9999",
        "source": "ebpf_ringbuf_packet",
        "sink": "wasm_jit_trampoline_patch",
        "sanitizers": [],
    }
    v_ast = _make_vuln(b"", vuln_id="VULN-NOVEL-AST", impact=ImpactClass.PARSER_CONFUSION, attempts=3, successes=3, rate=1.0)
    is_novel_ast, tech_ast = classifier.classify_novelty(v_ast, ast_finding=novel_ast, oracle_violated=True)
    assert is_novel_ast is True
    assert tech_ast is not None
    assert tech_ast.technique_id.startswith("TECH-NOVEL-AST-")
    assert tech_ast.max_known_similarity < classifier.novelty_threshold

    # 4. Null-Byte Frame Truncation (2/3 = 0.6667 >= 0.66 confirmation threshold)
    v_nul = _make_vuln(
        b"GET / HTTP/1.1\r\nHost: target.example\r\nX-Frame: a\x00b\r\n\r\n",
        vuln_id="VULN-NOVEL-NUL",
        impact=ImpactClass.DESYNCHRONIZATION,
        attempts=3,
        successes=2,
        rate=2.0 / 3.0,
    )
    is_novel_nul, tech_nul = classifier.classify_novelty(v_nul)
    assert is_novel_nul is True
    assert tech_nul is not None
    assert tech_nul.technique_id == "TECH-NULL-BYTE-FRAME-DESYNC"
    assert tech_nul.max_known_similarity < classifier.novelty_threshold


def test_strict_novelty_gate_rejects_unverified_under_3_trials_and_non_violating():
    classifier = CausalAnomalyClassifier(include_workspace_templates=False)
    novel_probe = b"HTTP/1.1 200 OK\r\nHost: target.example\r\n\r\n"

    # A. < 3 verification attempts -> NEVER novel
    v_two_trials = _make_vuln(novel_probe, vuln_id="V-2TRIALS", attempts=2, successes=2, rate=1.0)
    is_novel, tech = classifier.classify_novelty(v_two_trials, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_unverified"
    assert classifier.last_novelty_assessment["gates"]["three_trial_confirmed"] is False

    # B. Low reproducibility rate (< 0.66) -> NEVER novel
    v_low_rate = _make_vuln(novel_probe, vuln_id="V-LOWRATE", attempts=3, successes=1, rate=0.33)
    is_novel, tech = classifier.classify_novelty(v_low_rate, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_unverified"

    # C. NonReproducibleTransient -> NEVER novel
    v_transient = _make_vuln(
        novel_probe,
        vuln_id="V-TRANS",
        impact=ImpactClass.NON_REPRODUCIBLE_TRANSIENT,
        attempts=5,
        successes=5,
        rate=1.0,
    )
    is_novel, tech = classifier.classify_novelty(v_transient, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_unverified"

    # D. Explicit oracle_violated=False -> NEVER novel even with 5/5 trials & low similarity
    v_no_oracle = _make_vuln(novel_probe, vuln_id="V-NO-ORACLE", attempts=5, successes=5, rate=1.0)
    is_novel, tech = classifier.classify_novelty(v_no_oracle, oracle_violated=False)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_no_invariant_violation"
    assert classifier.last_novelty_assessment["gates"]["oracle_or_invariant_violated"] is False

    # E. Benign plain HTTP/1.1 request with no divergence or explicit oracle violation -> NEVER novel
    benign_probe = b"GET /index.html HTTP/1.1\r\nHost: clean.example\r\n\r\n"
    v_benign = _make_vuln(benign_probe, vuln_id="V-BENIGN", impact=ImpactClass.PARSER_CONFUSION, attempts=5, successes=5, rate=1.0)
    is_novel, tech = classifier.classify_novelty(v_benign)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_no_invariant_violation"

    # F. Framing artifact (leftover HTML) -> NEVER novel even if oracle_violated=True
    artifact_anom = ImplementationAnomaly(
        anomaly_id="ANOM-ART",
        target_engine="example.com:443",
        category=AnomalyCategory.PIPELINE_LEAK,
        observed_behavior="Residual Pipeline Leak: 5000 bytes",
        expected_behavior="Clean separation",
        raw_probe=novel_probe,
        raw_response=b"<!DOCTYPE html><html><body>leftover</body></html>",
    )
    v_art = _make_vuln(novel_probe, vuln_id="V-ART", attempts=5, successes=5, rate=1.0)
    is_novel, tech = classifier.classify_novelty(v_art, anomaly=artifact_anom, oracle_violated=True)
    assert is_novel is False
    assert tech is None
    assert classifier.last_novelty_assessment["tag"] == "rejected_no_invariant_violation"


# ---------------------------------------------------------------------------
# 6. Offline-By-Default (Zero Network Calls) & Opt-In Catalog Refresh
# ---------------------------------------------------------------------------

def test_offline_default_makes_zero_network_calls_and_local_refresh_works(monkeypatch, tmp_path):
    def _forbid_network(*args, **kwargs):
        raise AssertionError(f"Network call forbidden in offline mode: args={args}, kwargs={kwargs}")

    monkeypatch.setattr(socket, "socket", _forbid_network)
    monkeypatch.setattr(socket, "create_connection", _forbid_network)
    monkeypatch.setattr(urllib.request, "urlopen", _forbid_network)

    # Default offline initialization, fingerprinting, querying, and classification make 0 network calls
    classifier = CausalAnomalyClassifier(workspace_root=tmp_path, include_workspace_templates=True)
    probe = b"GET / HTTP/1.1\r\nHost: offline.test\r\nX-Custom-Wire-Proto: alpha\r\n\r\n"
    vuln = _make_vuln(probe, vuln_id="V-OFFLINE-1", impact=ImpactClass.PARSER_CONFUSION)

    # Before ingesting external file catalog, this custom protocol header is novel
    is_novel_before, tech_before = classifier.classify_novelty(vuln, oracle_violated=True)
    assert is_novel_before is True
    assert tech_before is not None

    # Create a local JSON catalog file containing this technique
    ext_catalog = tmp_path / "external_disclosures.json"
    ext_catalog.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "entry_id": "EXT-WIRE-ALPHA-2026",
                        "title": "Disclosed X-Custom-Wire-Proto Framing Bug",
                        "category": "PROTOCOL_EXTENSION",
                        "cwe_ids": ["CWE-444"],
                        "probe": "GET /api HTTP/1.1\r\nHost: disclosed.example\r\nX-Custom-Wire-Proto: beta\r\n\r\n",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Explicit local refresh with allow_network=False succeeds with zero network calls
    refresh_res = classifier.refresh_novelty_corpus([ext_catalog], allow_network=False)
    assert refresh_res["added"] == 1
    assert refresh_res["errors"] == []

    # After refresh, the exact same structural pattern is now known -> NOT novel!
    is_novel_after, tech_after = classifier.classify_novelty(vuln, oracle_violated=True)
    assert is_novel_after is False
    assert tech_after is None
    assert classifier.last_novelty_assessment["nearest_known_technique"]["entry_id"] == "EXT-WIRE-ALPHA-2026"

    # Passing a remote URL with allow_network=False MUST fail closed with PermissionError (0 sockets)
    with pytest.raises(PermissionError):
        classifier.refresh_novelty_corpus(["https://portswigger.net/research/feed.json"], allow_network=False)

    # Passing an SSRF private/metadata URL even with allow_network=True MUST fail closed with PermissionError
    with pytest.raises(PermissionError):
        classifier.refresh_novelty_corpus(["http://169.254.169.254/latest/meta-data/"], allow_network=True)
    with pytest.raises(PermissionError):
        classifier.refresh_novelty_corpus(["http://127.0.0.1:8080/internal.json"], allow_network=True)

    # CLI helper `refresh_novelty_corpus` exports merged offline catalog cleanly
    exported_file = tmp_path / "merged_catalog.json"
    cli_report = refresh_novelty_corpus(
        [ext_catalog],
        workspace_root=tmp_path,
        allow_network=False,
        output_path=exported_file,
    )
    assert cli_report["added"] == 1
    assert exported_file.is_file()
    exported_data = json.loads(exported_file.read_text(encoding="utf-8"))
    assert exported_data["schema"] == "rfchunt-novelty-corpus-v1"
    assert any(e["entry_id"] == "EXT-WIRE-ALPHA-2026" for e in exported_data["entries"])
