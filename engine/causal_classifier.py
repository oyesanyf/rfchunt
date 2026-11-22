"""
Module 9: Causal Anomaly and Novelty Classifier (P1) — AIxCC Upgrade #4.

Implements the 4-tier taxonomy classifier, counterfactual causal attribution,
environmental socket noise filtering, and structural-fingerprint novelty gating
backed by `CanonicalStructuralFingerprinter` and `NoveltyCorpusIndex`.

Strict 3-condition novelty gate: a finding is tagged `"novel"` ONLY when:
  1. Passed >= 3 reproduction trials (`verification_attempts >= 3`,
     `reproducibility_rate >= 0.66`, `successful_reproductions >= 2`, non-transient),
  2. Violates a real security invariant or differential oracle (never a benign
     request, framing artifact, or environmental noise), AND
  3. Maximum structural similarity against `NoveltyCorpusIndex` falls strictly
     below `novelty_threshold` (default `0.72`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from engine.novelty_corpus import (
    DEFAULT_NOVELTY_THRESHOLD,
    CanonicalStructuralFingerprinter,
    NoveltyCorpusIndex,
    NoveltyQueryResult,
)
from engine.taxonomy import (
    AnomalyCategory,
    ImpactClass,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
    RFCRequirement,
)


class CausalAnomalyClassifier:
    """
    Evaluates causal attribution (counterfactual validation), separates
    environmental noise / framing artifacts from genuine specification-level
    vulnerabilities, and performs corpus-backed structural novelty gating.
    """

    DEFAULT_NOVELTY_THRESHOLD: float = DEFAULT_NOVELTY_THRESHOLD
    MIN_NOVELTY_TRIALS: int = 3
    MIN_NOVELTY_REPRO_RATE: float = 0.66

    def __init__(
        self,
        db: Optional[Any] = None,
        novelty_threshold: float = DEFAULT_NOVELTY_THRESHOLD,
        *,
        corpus: Optional[NoveltyCorpusIndex] = None,
        fingerprinter: Optional[CanonicalStructuralFingerprinter] = None,
        workspace_root: Optional[Union[str, Path]] = None,
        include_workspace_templates: bool = True,
    ):
        self.db = db
        self.novelty_threshold: float = float(novelty_threshold)
        self.fingerprinter: CanonicalStructuralFingerprinter = (
            fingerprinter or CanonicalStructuralFingerprinter()
        )
        self.novelty_corpus: NoveltyCorpusIndex = corpus or NoveltyCorpusIndex(
            db=db,
            workspace_root=workspace_root,
            include_builtin_catalog=True,
            include_workspace_templates=include_workspace_templates,
            fingerprinter=self.fingerprinter,
            novelty_threshold=self.novelty_threshold,
        )
        self.novel_techniques: Dict[str, NovelTechnique] = {}
        self.technique_provenance: Dict[str, Dict[str, Any]] = {}
        self.last_novelty_assessment: Optional[Dict[str, Any]] = None

    def refresh_novelty_corpus(
        self,
        paths_or_urls: Union[str, Path, Sequence[Union[str, Path]]],
        *,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        """Explicit opt-in refresh of the underlying `NoveltyCorpusIndex`."""
        return self.novelty_corpus.refresh_from_sources(
            paths_or_urls,
            allow_network=allow_network,
        )

    def get_technique_provenance(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Returns stored structural fingerprint and nearest-known-technique provenance."""
        return self.technique_provenance.get(technique_id)

    def is_framing_artifact(
        self,
        anomaly: ImplementationAnomaly,
        baseline_resp: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """
        Validates whether anomalous bytes or reported pipeline leaks can be explained
        by ordinary HTTP response framing (e.g. unconsumed baseline HTML body,
        standard RFC 9112 400 Bad Request connection closure, or socket buffer leftovers).
        Returns (is_artifact, reason).
        """
        obs_lower = anomaly.observed_behavior.lower()
        raw_resp = anomaly.raw_response or b""
        raw_lower = raw_resp.lower()

        # Check for explicit scanner artifact indicator
        if "scanner artifact" in obs_lower:
            return True, "Scanner artifact: residual baseline response bytes detected on socket."

        # Check for residual HTML body fragment from previous baseline request
        html_markers = [b"<!doctype html", b"<html", b"<head", b"<title", b"<script", b"<style", b"<div", b"<body"]
        is_html_fragment = any(marker in raw_lower for marker in html_markers)
        is_residual_mention = (
            "residual pipeline leak" in obs_lower
            or "residual html body fragment" in obs_lower
            or "residual data leak" in obs_lower
            or "unconsumed response body" in obs_lower
        )

        if is_residual_mention or (is_html_fragment and not raw_resp.startswith(b"HTTP/")):
            return True, "Residual baseline HTML/body bytes from incomplete socket consumption; ordinary framing artifact, not a pipeline leak."

        # Compare directly against baseline response if available
        if baseline_resp:
            baseline_lower = baseline_resp.lower()
            if b"\r\n\r\n" in baseline_resp:
                _, baseline_body = baseline_resp.split(b"\r\n\r\n", 1)
                if baseline_body and raw_resp in baseline_body:
                    return True, "Residual body bytes matching baseline response; ordinary framing artifact."
            if raw_resp and raw_resp in baseline_lower:
                return True, "Anomalous response matches baseline content; ordinary framing artifact."

        # Check for ordinary connection closure after client error (400 Bad Request)
        if anomaly.category == AnomalyCategory.PIPELINE_LEAK:
            if (
                "connection closed by server after candidate probe" in obs_lower
                or "premature connection termination before canary" in obs_lower
            ):
                return True, "Ordinary RFC 9112 Section 9.3 connection teardown on client error rejection; not a vulnerability."
            if "client framing omission" in obs_lower:
                return True, "Client sent un-framed body without Content-Length or Transfer-Encoding; trailing bytes are an RFC 9112 Section 6.1 framing omission, not a pipeline leak."

        # Check if probe sent un-framed body without Content-Length or Transfer-Encoding
        raw_probe = anomaly.raw_probe or b""
        if b"\r\n\r\n" in raw_probe:
            probe_lower = raw_probe.lower()
            _, body = raw_probe.split(b"\r\n\r\n", 1)
            if len(body.strip()) > 0 and b"content-length" not in probe_lower and b"transfer-encoding" not in probe_lower:
                return True, "Probe contains body without Content-Length or Transfer-Encoding; trailing bytes are un-framed per RFC 9112 Section 6.1, not a server vulnerability."

        return False, ""

    def validate_evidence(
        self,
        vuln: ReproducibleVulnerability,
        anomaly: ImplementationAnomaly,
        baseline_resp: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """
        Evidence Validator: Confirms that anomalous bytes cannot be explained by
        ordinary response framing before allowing classification as a confirmed vulnerability
        or publication of defensive rules.
        """
        is_artifact, reason = self.is_framing_artifact(anomaly, baseline_resp)
        if is_artifact:
            return False, f"Anomalous bytes explained by ordinary response framing: {reason}"

        # Multi-Trial Confirmation Law (Protocol Research Reproducibility Invariant)
        if vuln.impact == ImpactClass.NON_REPRODUCIBLE_TRANSIENT:
            return False, "Finding was classified as NonReproducibleTransient; failed minimum 3-trial stability requirement."

        if vuln.verification_attempts < 3 or vuln.reproducibility_rate < 0.60:
            return False, f"Low reproducibility rate ({vuln.successful_reproductions}/{vuln.verification_attempts}, {vuln.reproducibility_rate:.1%}); failed minimum 3-trial stability requirement."

        # Stage 3: Metamorphic validity gate
        if anomaly.category == AnomalyCategory.METAMORPHIC_VIOLATION:
            obs_lower = anomaly.observed_behavior.lower()
            if (
                "200 vs 400" in obs_lower
                or "returned 400" in obs_lower
                or "rfc-compliant rejection" in obs_lower
            ):
                return False, (
                    "Stage 3 Metamorphic Validity Gate: Status difference (200 vs 400) reflects RFC-compliant "
                    "server rejection of modified syntax under RFC 9112 Section 5.1/5.5; not evidence of a vulnerability."
                )

        # For pipeline leaks / queue desync, verify that desynchronization was actually demonstrated
        if (
            vuln.impact in (ImpactClass.QUEUE_POISONING, ImpactClass.DESYNCHRONIZATION)
            or anomaly.category in (AnomalyCategory.PIPELINE_LEAK, AnomalyCategory.SOCKET_HANG)
            or "pipeline leak" in anomaly.observed_behavior.lower()
            or "timeout-based" in anomaly.observed_behavior.lower()
        ):
            probe_lower = vuln.minimized_probe.lower()
            obs_lower = anomaly.observed_behavior.lower()
            has_desync_vectors = (
                (b"transfer-encoding" in probe_lower and b"content-length" in probe_lower)
                or b"canary" in probe_lower
                or b"terminator_marker" in probe_lower
                or (b"transfer-encoding" in probe_lower and b"chunk" in probe_lower)
                or (b"content-length" in probe_lower and probe_lower.startswith(b"get "))
                or "timeout-based" in obs_lower
                or "cl.0" in obs_lower
            )
            if not has_desync_vectors:
                return False, "Unvalidated pipeline leak: does not exhibit verified cross-request queue desynchronization or conflicting framing headers."

        return True, "Evidence verified: anomaly cannot be explained by ordinary response framing."

    def filter_environmental_noise(
        self,
        anomaly: ImplementationAnomaly,
        baseline_is_healthy: bool,
        socket_error_type: Optional[str] = None,
        baseline_resp: Optional[bytes] = None,
    ) -> bool:
        """
        Determines if an anomaly is caused by environmental noise (e.g. OS port exhaustion,
        server crash/shutdown, transient connection refusal, or leftover framing bytes).
        Returns True if it IS environmental noise / framing artifact (should be discarded).
        """
        if not baseline_is_healthy:
            anomaly.is_environmental_noise = True
            return True

        if socket_error_type in ("WSAEADDRINUSE", "ECONNREFUSED", "WSAENOBUFS"):
            anomaly.is_environmental_noise = True
            return True

        is_artifact, reason = self.is_framing_artifact(anomaly, baseline_resp)
        if is_artifact:
            anomaly.is_environmental_noise = True
            anomaly.observed_behavior += f" [DISCARDED_AS_FRAMING_ARTIFACT: {reason}]"
            return True

        anomaly.is_environmental_noise = False
        return False

    def _evaluate_oracle_or_invariant_gate(
        self,
        vuln: ReproducibleVulnerability,
        query_res: NoveltyQueryResult,
        *,
        anomaly: Optional[ImplementationAnomaly],
        oracle_violated: Optional[bool],
        divergence_matrix: Optional[Dict[str, Any]],
        baseline_resp: Optional[bytes],
        ast_finding: Optional[Union[Dict[str, Any], Any]],
    ) -> Tuple[bool, str]:
        """
        Gate 2: Ensures the candidate finding violates a genuine security invariant
        or differential oracle and is NOT a benign request, framing artifact, or noise.
        """
        # Framing artifacts and environmental noise ALWAYS fail closed
        if anomaly is not None:
            if anomaly.is_environmental_noise:
                return False, "Rejected: anomaly flagged as environmental noise."
            is_artifact, art_reason = self.is_framing_artifact(anomaly, baseline_resp=baseline_resp)
            if is_artifact:
                return False, f"Rejected: framing artifact ({art_reason})."
            is_valid_ev, ev_reason = self.validate_evidence(vuln, anomaly, baseline_resp=baseline_resp)
            if not is_valid_ev:
                return False, f"Rejected: evidence validation failed ({ev_reason})."
        elif ast_finding is None:
            # Guard against un-framed HTTP/1.1 client body omission when anomaly is omitted
            raw_probe = vuln.minimized_probe or b""
            proto = query_res.query_fingerprint.features.get("protocol")
            if proto == "H1" and b"\r\n\r\n" in raw_probe:
                probe_low = raw_probe.lower()
                _, body = raw_probe.split(b"\r\n\r\n", 1)
                if len(body.strip()) > 0 and b"content-length" not in probe_low and b"transfer-encoding" not in probe_low:
                    return False, "Rejected: un-framed HTTP/1.1 body without Content-Length or Transfer-Encoding (RFC 9112 Section 6.1 client framing omission)."

        # Explicit caller verdict
        if oracle_violated is False:
            return False, "Rejected: oracle_violated=False (no security invariant or differential oracle violated)."
        if oracle_violated is True:
            return True, "Confirmed: explicit security invariant / differential oracle violation."

        # Inspect differential parser matrix if provided
        if divergence_matrix:
            _, div_info = self.fingerprinter.extract_divergence_tokens(divergence_matrix)
            if div_info.get("has_divergence"):
                return True, (
                    "Confirmed: differential parser matrix observed cross-implementation divergence "
                    f"(statuses={div_info.get('statuses')}, states={div_info.get('socket_states')})."
                )
            if anomaly is not None and anomaly.category == AnomalyCategory.PARSER_DIVERGENCE:
                return False, "Rejected: differential parser matrix showed identical behavior across implementations."

        # Verified non-artifact anomaly passed validate_evidence above
        if anomaly is not None:
            return True, f"Confirmed: verified non-artifact {anomaly.category.value} security invariant violation."

        # Check structural protocol anomaly or unmitigated AST taint flow
        if self.fingerprinter.has_structural_protocol_anomaly(query_res.query_fingerprint):
            return True, "Confirmed: structural fingerprint demonstrates verified protocol invariant violation or unmitigated taint flow."

        return False, "Rejected: benign or non-anomalous request without verified security invariant or differential oracle violation."

    def _synthesize_novel_technique(
        self,
        vuln: ReproducibleVulnerability,
        query_res: NoveltyQueryResult,
        *,
        rfc_context: Optional[RFCRequirement],
        provenance: Dict[str, Any],
    ) -> NovelTechnique:
        """Synthesizes a Tier-4 `NovelTechnique` with structured fingerprint & nearest-match provenance."""
        fp = query_res.query_fingerprint
        tok_set = set(fp.tokens)
        fp_short = fp.fingerprint_id.split("-")[-1][:12].upper()
        canon_tag = f"[FP:{fp.fingerprint_id}] [CANON:{fp.canonical_form}]"

        if "ANOM:RESPONSE_STATUS_IN_REQUEST" in tok_set or "INVERSION:SHARED_PARSER" in tok_set:
            technique_id = "TECH-SHARED-PARSER-CONFUSION"
            title = "Shared-Parser Confusion (Response-to-Request Inversion)"
            conceptual_model = "Intermediary or server evaluates incoming client requests using response parsing rules."
            inversion_pattern = (
                f"Applying response syntax tokens (Status-Line, Reason-Phrase) directly into client stream. {canon_tag}"
            )
            affected_architectures = ["Unified HTTP Parsers", "Reverse Proxy Duplex Channels"]
            recommended_mitigation = "Strictly segregate downstream request parsers from upstream response parsers."
        elif "ANOM:NUL_BYTE_TRUNCATION" in tok_set or "BYTE:NUL_FRAME" in tok_set:
            technique_id = "TECH-NULL-BYTE-FRAME-DESYNC"
            title = "Null-Byte Frame Truncation Desync"
            conceptual_model = "C-based string length termination discrepancies between proxy and backend parsers."
            inversion_pattern = (
                f"Injecting null bytes into ABNF header tokens to induce asymmetric length calculation. {canon_tag}"
            )
            affected_architectures = ["C/C++ Proxy Frontends with High-Level Managed Backends"]
            recommended_mitigation = "Enforce strict rejection of NUL (0x00) bytes across all request fields at ingress."
        elif fp.kind == "ast":
            src = str(fp.features.get("source") or "UNKNOWN")
            sink = str(fp.features.get("sink") or "UNKNOWN")
            cwes = ", ".join(fp.features.get("cwe_ids") or ["UNCLASSIFIED"])
            technique_id = f"TECH-NOVEL-AST-{fp_short}"
            title = f"Novel AST Taint Technique ({src} -> {sink})"
            conceptual_model = (
                f"Verified unmitigated AST taint flow ({src} -> {sink}; {cwes}) structurally distinct "
                f"from indexed known techniques (max_sim={query_res.max_similarity:.3f} < {self.novelty_threshold:.2f})."
            )
            inversion_pattern = f"Unmitigated taint propagation {src} -> {sink}. {canon_tag}"
            affected_architectures = ["Application Data-Flow & Parser Sinks"]
            recommended_mitigation = f"Enforce strict canonical validation and allowlisted sanitization between {src} and {sink}."
        else:
            impact_label = vuln.impact.value if hasattr(vuln.impact, "value") else str(vuln.impact)
            proto_label = str(fp.features.get("protocol") or "PROTOCOL")
            rfc_note = f" violating {rfc_context.rfc_id} {rfc_context.section}" if rfc_context is not None else ""
            technique_id = f"TECH-NOVEL-WIRE-{fp_short}"
            title = f"Novel {proto_label} Structural Technique ({impact_label})"
            conceptual_model = (
                f"3-trial confirmed {impact_label} defect{rfc_note} structurally distinct from "
                f"indexed disclosure corpus (max_sim={query_res.max_similarity:.3f} < {self.novelty_threshold:.2f})."
            )
            inversion_pattern = f"Canonical minimized wire structure: {canon_tag}"
            affected_architectures = [f"{proto_label} Implementations and Reverse-Proxy Boundaries"]
            recommended_mitigation = (
                "Reject non-conformant framing strictly at ingress and deploy Arm 106/107 structural guards."
            )

        existing = self.novel_techniques.get(technique_id)
        if existing is not None:
            if vuln.vuln_id not in existing.supporting_vulnerabilities:
                existing.supporting_vulnerabilities.append(vuln.vuln_id)
            technique = existing
        else:
            technique = NovelTechnique(
                technique_id=technique_id,
                title=title,
                conceptual_model=conceptual_model,
                inversion_pattern=inversion_pattern,
                affected_architectures=affected_architectures,
                supporting_vulnerabilities=[vuln.vuln_id],
                recommended_mitigation=recommended_mitigation,
            )
            self.novel_techniques[technique_id] = technique

        # Attach structured fingerprint & nearest-known-technique provenance metadata
        technique.novelty_tag = "novel"  # type: ignore[attr-defined]
        technique.structural_fingerprint = fp.to_dict()  # type: ignore[attr-defined]
        technique.max_known_similarity = round(query_res.max_similarity, 4)  # type: ignore[attr-defined]
        technique.novelty_threshold = round(self.novelty_threshold, 4)  # type: ignore[attr-defined]
        technique.nearest_known_techniques = [m.to_dict() for m in query_res.nearest_matches]  # type: ignore[attr-defined]
        technique.provenance = provenance  # type: ignore[attr-defined]
        technique.metadata = provenance  # type: ignore[attr-defined]
        self.technique_provenance[technique_id] = provenance
        return technique

    def classify_novelty_detailed(
        self,
        vuln: ReproducibleVulnerability,
        rfc_context: Optional[RFCRequirement] = None,
        *,
        anomaly: Optional[ImplementationAnomaly] = None,
        oracle_violated: Optional[bool] = None,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        baseline_resp: Optional[bytes] = None,
        ast_finding: Optional[Union[Dict[str, Any], Any]] = None,
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """
        Full structured novelty assessment returning tag, gate decisions,
        canonical structural fingerprint, nearest known corpus techniques,
        and synthesized `NovelTechnique` (when all 3 novelty gates pass).
        """
        effective_div = (
            divergence_matrix
            if divergence_matrix is not None
            else (anomaly.divergence_matrix if anomaly is not None else None)
        )
        rfc_label = f"{rfc_context.rfc_id}:{rfc_context.section}" if rfc_context is not None else None
        impact_val = vuln.impact.value if hasattr(vuln.impact, "value") else str(vuln.impact)

        if ast_finding is not None and not (vuln.minimized_probe or b""):
            query_res = self.novelty_corpus.query_ast(
                ast_finding,
                top_k=top_k,
                threshold=self.novelty_threshold,
            )
        elif ast_finding is not None and (vuln.minimized_probe or b""):
            hybrid_fp = self.fingerprinter.fingerprint_hybrid(
                raw_probe=vuln.minimized_probe,
                ast_finding=ast_finding,
                divergence_matrix=effective_div,
                impact=impact_val,
                rfc_context=rfc_label,
            )
            query_res = self.novelty_corpus.query(
                hybrid_fp,
                top_k=top_k,
                threshold=self.novelty_threshold,
            )
        else:
            query_res = self.novelty_corpus.query_wire(
                vuln.minimized_probe,
                divergence_matrix=effective_div,
                impact=impact_val,
                rfc_context=rfc_label,
                top_k=top_k,
                threshold=self.novelty_threshold,
            )

        # Gate 1: >= 3 reproduction trials with >= 0.66 reproducibility and non-transient impact
        passed_3_trials = (
            vuln.impact != ImpactClass.NON_REPRODUCIBLE_TRANSIENT
            and int(vuln.verification_attempts) >= self.MIN_NOVELTY_TRIALS
            and float(vuln.reproducibility_rate) >= self.MIN_NOVELTY_REPRO_RATE
            and int(vuln.successful_reproductions) >= 2
        )
        trial_reason = (
            f"Passed 3-trial confirmation ({vuln.successful_reproductions}/{vuln.verification_attempts}, {vuln.reproducibility_rate:.1%})."
            if passed_3_trials
            else (
                f"Failed 3-trial confirmation gate (impact={impact_val}, "
                f"attempts={vuln.verification_attempts}, successes={vuln.successful_reproductions}, "
                f"rate={vuln.reproducibility_rate:.1%}; requires >=3 attempts and >=66% rate)."
            )
        )

        # Gate 2: Real security invariant or differential oracle violation (not framing artifact / benign)
        violated_invariant, invariant_reason = self._evaluate_oracle_or_invariant_gate(
            vuln,
            query_res,
            anomaly=anomaly,
            oracle_violated=oracle_violated,
            divergence_matrix=effective_div,
            baseline_resp=baseline_resp,
            ast_finding=ast_finding,
        )

        # Gate 3: Structural similarity strictly below novelty_threshold
        below_threshold = query_res.max_similarity < self.novelty_threshold
        top_match = query_res.nearest_matches[0] if query_res.nearest_matches else None
        if below_threshold:
            sim_reason = (
                f"Below novelty threshold: max_similarity={query_res.max_similarity:.4f} < {self.novelty_threshold:.4f}"
                + (f" (nearest: {top_match.entry_id} [{top_match.source}] @ {top_match.similarity:.4f})." if top_match else ".")
            )
        else:
            sim_reason = (
                f"Matched known technique {top_match.entry_id} ({top_match.title}, source={top_match.source}) "
                f"with similarity={query_res.max_similarity:.4f} >= threshold={self.novelty_threshold:.4f}."
                if top_match
                else f"Similarity {query_res.max_similarity:.4f} >= threshold {self.novelty_threshold:.4f}."
            )

        is_novel = passed_3_trials and violated_invariant and below_threshold
        if is_novel:
            tag = "novel"
            summary_reason = f"Tagged novel: {trial_reason} {invariant_reason} {sim_reason}"
        elif not passed_3_trials:
            tag = "rejected_unverified"
            summary_reason = trial_reason
        elif not violated_invariant:
            tag = "rejected_no_invariant_violation"
            summary_reason = invariant_reason
        else:
            tag = "known_technique"
            summary_reason = sim_reason

        nearest_dicts = [m.to_dict() for m in query_res.nearest_matches]
        provenance: Dict[str, Any] = {
            "vuln_id": vuln.vuln_id,
            "tag": tag,
            "is_novel": is_novel,
            "fingerprint_id": query_res.query_fingerprint.fingerprint_id,
            "fingerprint_kind": query_res.query_fingerprint.kind,
            "canonical_form": query_res.query_fingerprint.canonical_form,
            "structural_fingerprint": query_res.query_fingerprint.to_dict(),
            "max_similarity": round(query_res.max_similarity, 4),
            "novelty_threshold": round(self.novelty_threshold, 4),
            "nearest_known_technique": nearest_dicts[0] if nearest_dicts else None,
            "nearest_known_techniques": nearest_dicts,
            "corpus_size": query_res.corpus_size,
            "sources_loaded": dict(query_res.sources_loaded),
            "gates": {
                "three_trial_confirmed": passed_3_trials,
                "oracle_or_invariant_violated": violated_invariant,
                "below_similarity_threshold": below_threshold,
            },
            "gate_reasons": {
                "three_trial": trial_reason,
                "oracle_or_invariant": invariant_reason,
                "similarity": sim_reason,
            },
            "reason": summary_reason,
        }

        technique: Optional[NovelTechnique] = None
        if is_novel:
            technique = self._synthesize_novel_technique(
                vuln,
                query_res,
                rfc_context=rfc_context,
                provenance=provenance,
            )

        assessment = {
            **provenance,
            "technique": technique,
            "technique_id": technique.technique_id if technique is not None else None,
        }
        self.last_novelty_assessment = assessment
        return assessment

    def classify_novelty(
        self,
        vuln: ReproducibleVulnerability,
        rfc_context: Optional[RFCRequirement] = None,
        *,
        anomaly: Optional[ImplementationAnomaly] = None,
        oracle_violated: Optional[bool] = None,
        divergence_matrix: Optional[Dict[str, Any]] = None,
        baseline_resp: Optional[bytes] = None,
        ast_finding: Optional[Union[Dict[str, Any], Any]] = None,
        top_k: int = 5,
    ) -> Tuple[bool, Optional[NovelTechnique]]:
        """
        Evaluates whether a reproducible vulnerability represents a genuinely novel
        technique by enforcing the 3-condition gate:
          1. >= 3 reproduction trials (`verification_attempts >= 3`, `reproducibility_rate >= 0.66`),
          2. Real security invariant or differential oracle violation (not framing artifact / noise),
          3. Maximum structural similarity against `NoveltyCorpusIndex` strictly < `novelty_threshold`.

        Returns `(is_novel, NovelTechnique | None)` with structured fingerprint and
        nearest-known-technique provenance attached to the returned `NovelTechnique`
        and recorded on `self.last_novelty_assessment`.
        """
        assessment = self.classify_novelty_detailed(
            vuln,
            rfc_context=rfc_context,
            anomaly=anomaly,
            oracle_violated=oracle_violated,
            divergence_matrix=divergence_matrix,
            baseline_resp=baseline_resp,
            ast_finding=ast_finding,
            top_k=top_k,
        )
        return bool(assessment["is_novel"]), assessment["technique"]
