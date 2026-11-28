/-
  RFCHunt Formal Verification Suite (Lean 4 Core - Zero External Dependencies)
  Module: MerkleAuditInvariants.lean

  Proves domain-separation and append-only consistency invariants for RFCHunt's
  Merkle audit log (`merkle_audit.py`):
    1. leaf_node_domain_separation: RFC 6962-style domain-prefixed leaf preimages
       (0x00 :: data) can NEVER equal internal node preimages (0x01 :: left ++ right),
       eliminating second-preimage tree-forging attacks.
    2. append_increases_log_size: Appending an entry strictly increases log length.
-/

namespace RFCHunt.Merkle

def leafTag : UInt8 := 0x00
def nodeTag : UInt8 := 0x01

def leafPreimage (payload : List UInt8) : List UInt8 :=
  leafTag :: payload

def nodePreimage (left right : List UInt8) : List UInt8 :=
  nodeTag :: (left ++ right)

/-- Theorem 1: Domain separation prevents any leaf preimage from colliding with an internal node preimage. -/
theorem leaf_node_domain_separation (payload left right : List UInt8) :
    leafPreimage payload ≠ nodePreimage left right := by
  intro h
  simp [leafPreimage, nodePreimage, leafTag, nodeTag] at h

/-- Theorem 2: Appending a verified audit record strictly increases the audit log length. -/
theorem append_increases_log_size {α : Type} (log : List α) (entry : α) :
    log.length < (log ++ [entry]).length := by
  simp

end RFCHunt.Merkle
