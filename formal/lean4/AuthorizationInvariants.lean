/-
  RFCHunt Formal Verification Suite (Lean 4 Core - Zero External Dependencies)
  Module: AuthorizationInvariants.lean

  Proves AWS Cedar-inspired policy invariants and RFCHunt's TargetAuthorizationGate
  scope-containment guarantees:
    1. forbid_overrides_permit: Any matching `forbid` rule strictly overrides `permit`.
    2. default_deny_when_no_permit: Unmatched requests are denied by default.
    3. unauthorized_remote_denied: Non-loopback remote targets without explicit
       authorization are mathematically denied.
-/

namespace RFCHunt.Authz

inductive Effect where
  | permit
  | forbid
  deriving DecidableEq, Repr

structure Policy where
  effect  : Effect
  applies : Bool
  deriving DecidableEq, Repr

def hasMatch (eff : Effect) (policies : List Policy) : Bool :=
  policies.any (fun p => decide (p.effect = eff) && p.applies)

def isAllowed (policies : List Policy) : Bool :=
  hasMatch Effect.permit policies && !hasMatch Effect.forbid policies

theorem hasMatch_cons_true (eff : Effect) (p : Policy) (ps : List Policy)
    (heff : p.effect = eff) (hm : p.applies = true) :
    hasMatch eff (p :: ps) = true := by
  simp [hasMatch, heff, hm]

theorem hasMatch_mem (eff : Effect) (p : Policy) (ps : List Policy)
    (hmem : p ∈ ps) (heff : p.effect = eff) (hm : p.applies = true) :
    hasMatch eff ps = true := by
  induction ps with
  | nil => cases hmem
  | cons q qs ih =>
    cases hmem with
    | head => exact hasMatch_cons_true eff p qs heff hm
    | tail _ htail =>
      simp only [hasMatch, List.any_cons, Bool.or_eq_true]
      exact Or.inr (ih htail)

/-- Theorem 1: A matching `forbid` policy ALWAYS denies access, even when `permit` policies exist. -/
theorem forbid_overrides_permit (policies : List Policy) (p : Policy)
    (hmem : p ∈ policies) (heff : p.effect = Effect.forbid) (hm : p.applies = true) :
    isAllowed policies = false := by
  have hf : hasMatch Effect.forbid policies = true :=
    hasMatch_mem Effect.forbid p policies hmem heff hm
  simp [isAllowed, hf]

/-- Theorem 2: Default-deny when no `permit` policy matches. -/
theorem default_deny_when_no_permit (policies : List Policy)
    (hno : hasMatch Effect.permit policies = false) :
    isAllowed policies = false := by
  simp [isAllowed, hno]

structure TargetScope where
  isLoopback       : Bool
  isMetadataOrPriv : Bool
  hasExplicitAuth  : Bool
  deriving DecidableEq, Repr

def scopePermitted (t : TargetScope) : Bool :=
  !t.isMetadataOrPriv && (t.isLoopback || t.hasExplicitAuth)

/-- Theorem 3: Cloud metadata / forbidden private ranges are ALWAYS blocked, even with `--authorized`. -/
theorem metadata_always_blocked (t : TargetScope) (hmeta : t.isMetadataOrPriv = true) :
    scopePermitted t = false := by
  simp [scopePermitted, hmeta]

/-- Theorem 4: Any non-loopback target without explicit authorization is mathematically denied. -/
theorem unauthorized_remote_denied (t : TargetScope)
    (hnotloop : t.isLoopback = false) (hnoauth : t.hasExplicitAuth = false) :
    scopePermitted t = false := by
  simp [scopePermitted, hnotloop, hnoauth]

end RFCHunt.Authz
