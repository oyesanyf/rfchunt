"""
Module 12: Continuous Regression and Defensive Intelligence Publisher (P0).

Transforms verified reproducible vulnerabilities into reusable defensive rules
and automated regression test suites, publishing them directly into
Agent Octopus Arm 106 (Defensive Hardening) and Arm 107 (Continuous Regression Testing).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from engine.taxonomy import (
    Arm106DefensiveRule,
    Arm107RegressionTest,
    ImpactClass,
    ReproducibleVulnerability,
)


class DefensiveIntelligencePublisher:
    """
    Synthesizes and exports defensive validation signatures for Arm 106
    and regression verification tests for Arm 107.
    """

    def __init__(
        self,
        output_dir: Optional[str] = None,
        db: Optional[Any] = None,
        containment_manager: Optional[Any] = None,
    ):
        self.output_dir = Path(output_dir or "data")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db = db
        self.containment_manager = containment_manager
        self.arm106_rules: List[Arm106DefensiveRule] = []
        self.arm107_tests: List[Arm107RegressionTest] = []

    def publish_finding(
        self,
        vuln: ReproducibleVulnerability,
        rfc_anchor: str = "RFC9112",
        evidence_verified: bool = True,
        auto_export: bool = True,
    ) -> Tuple[Optional[Arm106DefensiveRule], Optional[Arm107RegressionTest]]:
        """
        Processes a confirmed reproducible vulnerability and synthesizes both
        defensive hardening rules and continuous regression tests.
        Suspends automatic publication if evidence is not confirmed.
        """
        if not evidence_verified:
            print(f"[!] [SUSPENDED] Automatic publication suspended for {vuln.vuln_id}: unverified evidence or framing artifact.")
            return None, None

        # 1. Synthesize Arm 106 Defensive Hardening Rule
        arm106_rule = self._synthesize_arm106_rule(vuln, rfc_anchor)
        self.arm106_rules.append(arm106_rule)

        # 1b. Apply host containment rule if containment manager is configured
        if self.containment_manager is not None and hasattr(self.containment_manager, "apply_defensive_rule"):
            try:
                self.containment_manager.apply_defensive_rule(arm106_rule)
            except Exception as e:
                print(f"[!] Warning: Failed to apply containment rule: {e}")

        # 2. Synthesize Arm 107 Regression Test
        arm107_test = self._synthesize_arm107_test(vuln)
        self.arm107_tests.append(arm107_test)

        # 3. Persist directly to SQLite database
        if self.db and hasattr(self.db, "save_arm106_defensive_rule"):
            self.db.save_arm106_defensive_rule(
                rule_id=arm106_rule.rule_id,
                name=arm106_rule.name,
                rule_type=arm106_rule.rule_type,
                target_protocol=arm106_rule.target_protocol,
                specification_anchor=arm106_rule.specification_anchor,
                rule_body=arm106_rule.rule_body,
                severity=arm106_rule.severity,
            )
        if self.db and hasattr(self.db, "save_arm107_regression_test"):
            self.db.save_arm107_regression_test(
                test_id=arm107_test.test_id,
                vuln_id=arm107_test.vuln_id,
                protocol=arm107_test.protocol,
                expected_status_rejection=json.dumps(arm107_test.expected_status_rejection),
                probe_bytes_hex=arm107_test.probe_bytes.hex() if isinstance(arm107_test.probe_bytes, bytes) else str(arm107_test.probe_bytes),
                validation_logic=arm107_test.validation_logic,
            )

        # 4. Export to filesystem
        if auto_export:
            self.export_all()

        return arm106_rule, arm107_test

    def _synthesize_arm106_rule(self, vuln: ReproducibleVulnerability, rfc_anchor: str) -> Arm106DefensiveRule:
        """Constructs an Arm 106 parser defense rule (e.g. Rust/Regex/Suricata)."""
        probe_lower = vuln.minimized_probe.lower()
        idx = len(self.arm106_rules) + 1
        if self.db and hasattr(self.db, "conn"):
            try:
                cur = self.db.conn.cursor()
                db_cnt = cur.execute("SELECT COUNT(*) FROM arm106_defensive_rules").fetchone()[0]
                idx = max(idx, db_cnt + 1)
            except Exception:
                pass
        rule_id = f"OCTO-ARM106-{idx:04d}-{vuln.vuln_id[-4:]}" if len(self.arm106_rules) > 0 or (self.db and hasattr(self.db, "conn")) else f"OCTO-ARM106-{idx:04d}"

        if b" :" in probe_lower or b"\t:" in probe_lower:
            rule_type = "RUST_PARSER_GUARD"
            rule_body = (
                "// Arm 106 Defense: Pre-colon whitespace rejection\n"
                "if header_name.ends_with(' ') || header_name.ends_with('\\t') {\n"
                "    return Err(ProtocolError::IllegalHeaderWhitespace);\n"
                "}"
            )
            name = "Reject Pre-Colon Whitespace"
        elif b"transfer-encoding" in probe_lower and b"content-length" in probe_lower:
            rule_type = "RUST_PARSER_GUARD"
            rule_body = (
                "// Arm 106 Defense: TE/CL dual-header conflict resolution\n"
                "if headers.contains_key('transfer-encoding') && headers.contains_key('content-length') {\n"
                "    return Err(ProtocolError::ConflictingMessageFraming);\n"
                "}"
            )
            name = "Reject Dual TE/CL Framing"
        elif b"\x00" in vuln.minimized_probe:
            rule_type = "REGEX"
            rule_body = r"[\x00]"
            name = "Ingress Null Byte Stripping"
        else:
            rule_type = "WAF_MODSEC"
            rule_body = f'SecRule REQUEST_HEADERS_NAMES "@rx .*" "id:{idx:04d},phase:1,deny,status:400"'
            name = f"Hardening Rule for {vuln.impact.value}"

        return Arm106DefensiveRule(
            rule_id=rule_id,
            name=name,
            rule_type=rule_type,
            target_protocol="HTTP/1.1",
            specification_anchor=rfc_anchor,
            rule_body=rule_body,
            severity="CRITICAL" if vuln.impact in (ImpactClass.DESYNCHRONIZATION, ImpactClass.QUEUE_POISONING) else "HIGH",
        )

    def _synthesize_arm107_test(self, vuln: ReproducibleVulnerability) -> Arm107RegressionTest:
        """Constructs an Arm 107 continuous regression assertion."""
        idx = len(self.arm107_tests) + 1
        if self.db and hasattr(self.db, "conn"):
            try:
                cur = self.db.conn.cursor()
                db_cnt = cur.execute("SELECT COUNT(*) FROM arm107_regression_tests").fetchone()[0]
                idx = max(idx, db_cnt + 1)
            except Exception:
                pass
        test_id = f"OCTO-ARM107-TEST-{idx:04d}-{vuln.vuln_id[-4:]}" if len(self.arm107_tests) > 0 or (self.db and hasattr(self.db, "conn")) else f"OCTO-ARM107-TEST-{idx:04d}"

        validation_code = (
            f"# Arm 107 Regression Test for {vuln.vuln_id}\n"
            f"def test_{test_id.lower().replace('-', '_')}():\n"
            f"    res = client.send_raw(raw_probe)\n"
            f"    assert res.status_code in [400, 431], f'Expected rejection, got {{res.status_code}}'\n"
        )

        return Arm107RegressionTest(
            test_id=test_id,
            vuln_id=vuln.vuln_id,
            protocol="HTTP/1.1",
            expected_status_rejection=[400, 431],
            probe_bytes=vuln.minimized_probe,
            validation_logic=validation_code,
        )

    def export_all(self) -> Dict[str, str]:
        """Writes data files for Arms 106 and 107."""
        arm106_file = self.output_dir / "defensive_rules_arm106.json"
        arm107_file = self.output_dir / "regression_suite_arm107.json"

        # Serialize Arm 106
        arm106_data = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "type": r.rule_type,
                "anchor": r.specification_anchor,
                "body": r.rule_body,
                "severity": r.severity,
            }
            for r in self.arm106_rules
        ]
        with open(arm106_file, "w", encoding="utf-8") as f:
            json.dump(arm106_data, f, indent=2)

        # Serialize Arm 107
        arm107_data = [
            {
                "test_id": t.test_id,
                "vuln_id": t.vuln_id,
                "protocol": t.protocol,
                "expected_status": t.expected_status_rejection,
                "raw_probe_hex": t.probe_bytes.hex(),
                "validation_logic": t.validation_logic,
            }
            for t in self.arm107_tests
        ]
        with open(arm107_file, "w", encoding="utf-8") as f:
            json.dump(arm107_data, f, indent=2)

        return {
            "arm106_path": str(arm106_file),
            "arm107_path": str(arm107_file),
        }

    def sync_db_findings(self) -> int:
        """Ensures every confirmed vulnerability in reproducible_vulnerabilities has a corresponding Arm 106 rule and Arm 107 test."""
        if not self.db or not hasattr(self.db, "conn"):
            return 0
        synced = 0
        try:
            cur = self.db.conn.cursor()
            missing_rows = cur.execute(
                """
                SELECT vuln_id, anomaly_id, impact, minimized_probe, reproducibility_rate,
                       verification_attempts, successful_reproductions, delta_debug_steps
                FROM reproducible_vulnerabilities
                WHERE vuln_id NOT IN (SELECT vuln_id FROM arm107_regression_tests)
                """
            ).fetchall()
            for row in missing_rows:
                v_id, a_id, imp_str, min_probe, r_rate, v_att, s_rep, dd_steps = row
                try:
                    impact_enum = ImpactClass(imp_str)
                except Exception:
                    impact_enum = ImpactClass.PARSER_CONFUSION
                vuln = ReproducibleVulnerability(
                    vuln_id=v_id,
                    anomaly_id=a_id or "ANOM-SYNC",
                    impact=impact_enum,
                    minimized_probe=(min_probe or "").encode("latin-1", errors="replace"),
                    reproducibility_rate=float(r_rate or 1.0),
                    verification_attempts=int(v_att or 3),
                    successful_reproductions=int(s_rep or 3),
                    delta_debug_steps=int(dd_steps or 1),
                )
                self.publish_finding(vuln, rfc_anchor="RFC9112", evidence_verified=True, auto_export=False)
                synced += 1
        except Exception:
            pass
        return synced

