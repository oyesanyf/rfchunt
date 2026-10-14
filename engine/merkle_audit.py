"""
Cryptographic Merkle Audit Trail for Protocol Vulnerability Research (RFC 6962 / Merkle Tree).

Enforces mathematical and cryptographic auditability for all evaluated wire probes,
multi-trial reproducibility results, and 4-parser differential matrix classifications.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


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
        """Appends a new verified protocol finding to the cryptographic audit trail."""
        index = len(self.leaves)
        probe_hash = hashlib.sha256(raw_probe).hexdigest()
        resp_hash = hashlib.sha256(raw_response).hexdigest()

        leaf = AuditLeaf(
            index=index,
            entry_id=entry_id,
            target_engine=target_engine,
            probe_sha256=probe_hash,
            response_sha256=resp_hash,
            reproducibility_rate=reproducibility_rate,
            verification_attempts=verification_attempts,
            successful_reproductions=successful_reproductions,
            four_parser_differential=four_parser_differential,
            status=status,
            timestamp=time.time(),
        )

        self.leaves.append(leaf)
        self._leaf_hashes.append(leaf.compute_leaf_hash())
        return leaf

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

    def export_audit_log(self) -> Dict[str, Any]:
        """Exports the full tamper-evident audit trail with Merkle root and leaf metadata."""
        root = self.get_merkle_root()
        return {
            "merkle_root": root,
            "total_leaves": len(self.leaves),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "leaves": [leaf.to_dict() for leaf in self.leaves],
        }
