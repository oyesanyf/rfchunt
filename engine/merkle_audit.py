"""
Cryptographic Merkle Audit Trail for Protocol Vulnerability Research (RFC 6962 / Merkle Tree).

Enforces mathematical and cryptographic auditability for all evaluated wire probes,
multi-trial reproducibility results, and 4-parser differential matrix classifications.
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class AuditLeaf:
    """Represents a single cryptographic audit entry in the Merkle Tree."""
    index: int
    entry_id: str
    target_engine: str
    probe_sha256: str
    response_sha256: str
    reproducibility_rate: float
    verification_attempts: int
    successful_reproductions: int
    four_parser_differential: Dict[str, Any]
    status: str  # 'CONFIRMED_VULNERABILITY', 'ANOMALY_VERIFIED', 'NON_REPRODUCIBLE_TRANSIENT'
    timestamp: float
    iso_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_leaf_hash(self) -> str:
        """Computes SHA-256 leaf hash with RFC 6962 0x00 leaf prefix."""
        payload = json.dumps(
            {
                "index": self.index,
                "entry_id": self.entry_id,
                "target_engine": self.target_engine,
                "probe_sha256": self.probe_sha256,
                "response_sha256": self.response_sha256,
                "reproducibility_rate": self.reproducibility_rate,
                "verification_attempts": self.verification_attempts,
                "successful_reproductions": self.successful_reproductions,
                "four_parser_differential": self.four_parser_differential,
                "status": self.status,
                "timestamp": self.timestamp,
            },
            sort_keys=True,
        ).encode("utf-8")
        # RFC 6962 Section 2.1: 0x00 prefix for leaf hashes
        return hashlib.sha256(b"\x00" + payload).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "entry_id": self.entry_id,
            "target_engine": self.target_engine,
            "probe_sha256": self.probe_sha256,
            "response_sha256": self.response_sha256,
            "reproducibility_rate": self.reproducibility_rate,
            "verification_attempts": self.verification_attempts,
            "successful_reproductions": self.successful_reproductions,
            "four_parser_differential": self.four_parser_differential,
            "status": self.status,
            "timestamp": self.timestamp,
            "iso_timestamp": self.iso_timestamp,
            "leaf_hash": self.compute_leaf_hash(),
        }


class MerkleAuditTrail:
    """
    Cryptographic Merkle Tree audit trail ensuring tamper-evident logging
    of all protocol findings and multi-trial reproducibility gates.
    """

    def __init__(self):
        self.leaves: List[AuditLeaf] = []
        self._leaf_hashes: List[str] = []

    @staticmethod
    def _is_differential_verified(four_parser_differential: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(four_parser_differential, dict):
            return False
        if any(
            bool(four_parser_differential.get(k))
            for k in ("divergence", "divergence_detected", "is_divergent", "verified")
        ):
            return True
        matrix = (
            four_parser_differential.get("matrix")
            if isinstance(four_parser_differential.get("matrix"), dict)
            else four_parser_differential
        )
        if isinstance(matrix, dict) and len(matrix) >= 2:
            statuses = {
                int(v.get("status", 0))
                for v in matrix.values()
                if isinstance(v, dict) and "status" in v
            }
            if len(statuses) > 1:
                return True
        return False

    def record_finding(
        self,
        entry_id: str,
        target_engine: str,
        raw_probe: bytes,
        raw_response: bytes,
        reproducibility_rate: float,
        verification_attempts: int,
        successful_reproductions: int,
        four_parser_differential: Dict[str, Any],
        status: str,
    ) -> AuditLeaf:
        """
        Appends a protocol finding to the cryptographic audit trail after enforcing
        the mandatory 3-trial reproducibility + 4-parser differential oracle gate.
        Unstable jitter or <3-trial findings are automatically downgraded to
        `'NON_REPRODUCIBLE_TRANSIENT'`.
        """
        index = len(self.leaves)
        probe_hash = hashlib.sha256(raw_probe).hexdigest()
        resp_hash = hashlib.sha256(raw_response).hexdigest()

        attempts = int(verification_attempts or 0)
        successes = int(successful_reproductions or 0)
        rate = float(reproducibility_rate or 0.0)
        diff_ok = self._is_differential_verified(four_parser_differential)

        passes_gate = attempts >= 3 and successes >= 2 and rate >= 0.66 and diff_ok
        resolved_status = (
            str(status or "CONFIRMED_VULNERABILITY")
            if passes_gate and str(status or "") in ("CONFIRMED_VULNERABILITY", "ANOMALY_VERIFIED")
            else "NON_REPRODUCIBLE_TRANSIENT"
        )

        leaf = AuditLeaf(
            index=index,
            entry_id=entry_id,
            target_engine=target_engine,
            probe_sha256=probe_hash,
            response_sha256=resp_hash,
            reproducibility_rate=rate,
            verification_attempts=attempts,
            successful_reproductions=successes,
            four_parser_differential=four_parser_differential if isinstance(four_parser_differential, dict) else {},
            status=resolved_status,
            timestamp=time.time(),
        )

        self.leaves.append(leaf)
        self._leaf_hashes.append(leaf.compute_leaf_hash())
        return leaf

    def get_confirmed_leaves(self) -> List[AuditLeaf]:
        return [l for l in self.leaves if l.status in ("CONFIRMED_VULNERABILITY", "ANOMALY_VERIFIED")]

    def get_transient_leaves(self) -> List[AuditLeaf]:
        return [l for l in self.leaves if l.status == "NON_REPRODUCIBLE_TRANSIENT"]

    def get_merkle_root(self) -> str:
        """
        Computes the cryptographic SHA-256 Merkle Root of all current audit trail leaves.
        Uses RFC 6962 interior node hashing (0x01 prefix).
        """
        if not self._leaf_hashes:
            return hashlib.sha256(b"").hexdigest()

        current_level = list(self._leaf_hashes)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate lone leaf to balance tree
                    right = left
                # RFC 6962 Section 2.1: 0x01 prefix for interior node hashes
                node_data = b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
                next_level.append(hashlib.sha256(node_data).hexdigest())
            current_level = next_level

        return current_level[0]

    def generate_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """
        Generates Merkle audit proof for a specific leaf index.
        Returns a list of tuples: (sibling_hash, 'left' | 'right').
        """
        if leaf_index < 0 or leaf_index >= len(self._leaf_hashes):
            raise IndexError("Leaf index out of bounds")

        proof: List[Tuple[str, str]] = []
        current_level = list(self._leaf_hashes)
        idx = leaf_index

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                if i == idx or i + 1 == idx:
                    if idx % 2 == 0:
                        proof.append((right, "right"))
                    else:
                        proof.append((left, "left"))

                node_data = b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
                next_level.append(hashlib.sha256(node_data).hexdigest())

            idx //= 2
            current_level = next_level

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Tuple[str, str]], expected_root: str) -> bool:
        """Verifies a Merkle audit proof against the expected Merkle Root."""
        current = leaf_hash
        for sibling_hash, direction in proof:
            if direction == "right":
                node_data = b"\x01" + bytes.fromhex(current) + bytes.fromhex(sibling_hash)
            else:
                node_data = b"\x01" + bytes.fromhex(sibling_hash) + bytes.fromhex(current)
            current = hashlib.sha256(node_data).hexdigest()
        return current == expected_root

    @staticmethod
    def _compute_root_for_hashes(leaf_hashes: Sequence[str]) -> str:
        if not leaf_hashes:
            return hashlib.sha256(b"").hexdigest()
        current_level = list(leaf_hashes)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                node_data = b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)
                next_level.append(hashlib.sha256(node_data).hexdigest())
            current_level = next_level
        return current_level[0]

    def compute_signed_tree_head(
        self,
        signing_key: bytes = b"rfchunt-rfc6962-sth-v1",
        *,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Computes an RFC 6962 Section 3.5 Signed Tree Head (STH) with constant-time
        verifiable HMAC-SHA256 signature over `(tree_size, timestamp_ms, sha256_root_hash)`.
        """
        root = self.get_merkle_root()
        tree_size = len(self._leaf_hashes)
        ts_ms = int(timestamp_ms if timestamp_ms is not None else int(time.time() * 1000))
        canonical = f"rfc6962_sth_v1|{tree_size}|{ts_ms}|{root}".encode("utf-8")
        sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        return {
            "version": "v1",
            "tree_size": tree_size,
            "timestamp_ms": ts_ms,
            "sha256_root_hash": root,
            "signature_alg": "HMAC-SHA256",
            "sth_signature": sig,
        }

    @staticmethod
    def verify_signed_tree_head(
        sth: Dict[str, Any],
        signing_key: bytes = b"rfchunt-rfc6962-sth-v1",
    ) -> bool:
        """Verifies a Signed Tree Head using constant-time `hmac.compare_digest`."""
        if not isinstance(sth, dict):
            return False
        try:
            tree_size = int(sth.get("tree_size", -1))
            ts_ms = int(sth.get("timestamp_ms", -1))
            root = str(sth.get("sha256_root_hash") or "")
            provided_sig = str(sth.get("sth_signature") or "")
        except (TypeError, ValueError):
            return False
        if tree_size < 0 or ts_ms < 0 or not root or not provided_sig:
            return False
        canonical = f"rfc6962_sth_v1|{tree_size}|{ts_ms}|{root}".encode("utf-8")
        expected_sig = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig.encode("ascii"), provided_sig.encode("ascii"))

    def generate_consistency_proof(self, first_size: int) -> Dict[str, Any]:
        """
        Generates an append-only consistency proof showing that the first `first_size`
        leaves of this tree hash to `first_root` and are an unmodified prefix of the
        current tree of size `second_size`.
        """
        second_size = len(self._leaf_hashes)
        if first_size < 0 or first_size > second_size:
            raise ValueError(f"Invalid first_size {first_size} for tree of size {second_size}")
        prefix_hashes = list(self._leaf_hashes[:first_size])
        suffix_hashes = list(self._leaf_hashes[first_size:])
        first_root = self._compute_root_for_hashes(prefix_hashes)
        second_root = self.get_merkle_root()
        return {
            "first_size": first_size,
            "second_size": second_size,
            "first_root": first_root,
            "second_root": second_root,
            "prefix_leaf_hashes": prefix_hashes,
            "append_leaf_hashes": suffix_hashes,
        }

    @classmethod
    def verify_consistency_proof(
        cls,
        first_size: int,
        first_root: str,
        second_size: int,
        second_root: str,
        proof: Dict[str, Any],
    ) -> bool:
        """Verifies that `first_root` (size `first_size`) is a strict prefix of `second_root` (size `second_size`)."""
        if not isinstance(proof, dict) or first_size < 0 or first_size > second_size:
            return False
        prefix_hashes = list(proof.get("prefix_leaf_hashes") or [])
        suffix_hashes = list(proof.get("append_leaf_hashes") or [])
        if len(prefix_hashes) != first_size or (len(prefix_hashes) + len(suffix_hashes)) != second_size:
            return False
        computed_first = cls._compute_root_for_hashes(prefix_hashes)
        computed_second = cls._compute_root_for_hashes(prefix_hashes + suffix_hashes)
        return hmac.compare_digest(computed_first, str(first_root)) and hmac.compare_digest(computed_second, str(second_root))

    def export_audit_log(self) -> Dict[str, Any]:
        """Exports the full tamper-evident audit trail with Merkle root, Signed Tree Head, and leaf metadata."""
        root = self.get_merkle_root()
        return {
            "merkle_root": root,
            "signed_tree_head": self.compute_signed_tree_head(),
            "total_leaves": len(self.leaves),
            "confirmed_leaves": len(self.get_confirmed_leaves()),
            "transient_leaves": len(self.get_transient_leaves()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "leaves": [leaf.to_dict() for leaf in self.leaves],
        }
