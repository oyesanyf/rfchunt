/-
  RFCHunt Formal Verification Suite (Lean 4 Core - Zero External Dependencies)
  Module: TrustedClosure.lean

  Formally proves RFCHunt's Trusted Closure, Verification Inversion, and
  Epistemic State Machine invariants:
    1. trusted_closure_sanitizer_blocks_exploit:
       If a path to a sink passes through a dominating validator/sanitizer
       in the trusted closure, untrusted input cannot reach the sink unsanitized.
    2. bounds_clamping_prevents_overflow:
       Clamping `x` into `[lo, hi]` with `lo <= hi` mathematically guarantees
       `lo <= clamp x lo hi ∧ clamp x lo hi <= hi`.
    3. comparator_contract_fail_closed:
       Under strict fail-closed RBAC/JWT comparator contracts, an inverted or
       missing authorization predicate never permits access.
    4. llm_only_never_promotes_proven:
       In the epistemic state machine, if `independentOracles = 0` (even when
       `correlatedLlmVotes >= 3`), the derived epistemic status is strictly
       `unresolved` (when not refuted) and NEVER `provenRuntime` or
       `provenStaticInvariant`.
-/

namespace RFCHunt.TrustedClosure

/-- Node kinds along a call-graph path from an untrusted entry point to a sink. -/
inductive StepKind where
  | passthrough
  | sanitizer
  | failOpenHandler
  deriving DecidableEq, Repr

/-- Tracks whether untrusted input remains tainted after traversing a sequence of steps. -/
def remainsTainted (initialTainted : Bool) : List StepKind → Bool
  | [] => initialTainted
  | StepKind.sanitizer :: rest => remainsTainted false rest
  | StepKind.passthrough :: rest => remainsTainted initialTainted rest
  | StepKind.failOpenHandler :: rest => remainsTainted initialTainted rest

/-- A path is dominated by the trusted closure when it traverses a sanitizer/validator step. -/
def hasDominatingSanitizer (path : List StepKind) : Prop :=
  StepKind.sanitizer ∈ path

theorem remainsTainted_false (rest : List StepKind) :
    remainsTainted false rest = false := by
  induction rest with
  | nil => rfl
  | cons s rs ih =>
    cases s <;> exact ih

/-- Theorem 1: Any path through a dominating validator/sanitizer prevents unsanitized input from reaching the sink. -/
theorem trusted_closure_sanitizer_blocks_exploit
    (path : List StepKind)
    (hdom : hasDominatingSanitizer path) :
    remainsTainted true path = false := by
  induction path with
  | nil => cases hdom
  | cons s rest ih =>
    cases s with
    | sanitizer => exact remainsTainted_false rest
    | passthrough =>
      cases hdom with
      | tail _ htail => exact ih htail
    | failOpenHandler =>
      cases hdom with
      | tail _ htail => exact ih htail

/-- Corollary 1a: If every path to a sink traverses a dominating sanitizer, no path delivers unsanitized input. -/
theorem trusted_closure_all_paths_safe
    (paths : List (List StepKind))
    (hall : ∀ p, p ∈ paths → hasDominatingSanitizer p) :
    ∀ p, p ∈ paths → remainsTainted true p = false := by
  intro p hp
  exact trusted_closure_sanitizer_blocks_exploit p (hall p hp)

/-- Bounded integer clamp into `[lo, hi]`. -/
def clamp (x lo hi : Int) : Int :=
  if x < lo then lo
  else if hi < x then hi
  else x

/-- Theorem 2: Clamping `x` into `[lo, hi]` with `lo <= hi` guarantees `lo <= clamp x lo hi ∧ clamp x lo hi <= hi`. -/
theorem bounds_clamping_prevents_overflow (x lo hi : Int) (h : lo ≤ hi) :
    lo ≤ clamp x lo hi ∧ clamp x lo hi ≤ hi := by
  unfold clamp
  split
  · exact ⟨Int.le_refl lo, h⟩
  · split
    · exact ⟨h, Int.le_refl hi⟩
    · omega

/-- Fail-closed RBAC & JWT/OIDC comparator verification contract predicates. -/
structure ComparatorContract where
  sigVerified  : Bool
  expVerified  : Bool
  audVerified  : Bool
  issVerified  : Bool
  roleVerified : Bool
  notForbidden : Bool
  deriving DecidableEq, Repr

/-- Strict conjunctive fail-closed evaluation of a comparator contract. -/
def evalComparatorContract (c : ComparatorContract) : Bool :=
  c.sigVerified && c.expVerified && c.audVerified &&
  c.issVerified && c.roleVerified && c.notForbidden

/-- Predicate capturing a missing or inverted authorization / JWT check. -/
def hasMissingOrInvertedPredicate (c : ComparatorContract) : Prop :=
  c.sigVerified = false ∨ c.expVerified = false ∨ c.audVerified = false ∨
  c.issVerified = false ∨ c.roleVerified = false ∨ c.notForbidden = false

/-- Theorem 3: Under strict fail-closed RBAC/JWT comparator contracts, an inverted or missing predicate never permits access. -/
theorem comparator_contract_fail_closed (c : ComparatorContract)
    (hbad : hasMissingOrInvertedPredicate c) :
    evalComparatorContract c = false := by
  rcases hbad with h | h | h | h | h | h <;> simp [evalComparatorContract, h]

/-- First-class 4-state epistemic status of an RFCHunt security claim. -/
inductive EpistemicStatus where
  | provenRuntime
  | provenStaticInvariant
  | unresolved
  | refuted
  deriving DecidableEq, Repr

/-- Evidence tuple passed into the epistemic state machine. -/
structure EpistemicEvidence where
  independentOracles      : Nat
  correlatedLlmVotes      : Nat
  runtimePoeVerified      : Bool
  staticInvariantVerified : Bool
  isRefuted               : Bool
  deriving DecidableEq, Repr

/-- Fail-closed epistemic status derivation with hard cap on LLM-only consensus. -/
def deriveEpistemicStatus (e : EpistemicEvidence) : EpistemicStatus :=
  if e.isRefuted then
    EpistemicStatus.refuted
  else if e.independentOracles = 0 then
    EpistemicStatus.unresolved
  else if e.runtimePoeVerified then
    EpistemicStatus.provenRuntime
  else if e.staticInvariantVerified then
    EpistemicStatus.provenStaticInvariant
  else
    EpistemicStatus.unresolved

/-- Theorem 4: When `independentOracles = 0` (even with `correlatedLlmVotes >= 3`), status is strictly `unresolved` and never `provenRuntime` or `provenStaticInvariant`. -/
theorem llm_only_never_promotes_proven (e : EpistemicEvidence)
    (hno_indep : e.independentOracles = 0)
    (hnot_refuted : e.isRefuted = false)
    (_hllm : e.correlatedLlmVotes ≥ 3) :
    deriveEpistemicStatus e = EpistemicStatus.unresolved ∧
    deriveEpistemicStatus e ≠ EpistemicStatus.provenRuntime ∧
    deriveEpistemicStatus e ≠ EpistemicStatus.provenStaticInvariant := by
  simp [deriveEpistemicStatus, hno_indep, hnot_refuted]

/-- Corollary 4a: Unconditionally, `independentOracles = 0` can never yield `provenRuntime` or `provenStaticInvariant`. -/
theorem zero_independent_oracles_never_proven (e : EpistemicEvidence)
    (hno_indep : e.independentOracles = 0) :
    deriveEpistemicStatus e ≠ EpistemicStatus.provenRuntime ∧
    deriveEpistemicStatus e ≠ EpistemicStatus.provenStaticInvariant := by
  unfold deriveEpistemicStatus
  cases h : e.isRefuted <;> simp [hno_indep]

end RFCHunt.TrustedClosure
