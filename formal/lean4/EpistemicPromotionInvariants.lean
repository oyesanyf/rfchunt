/-
  RFCHunt Formal Verification Suite (Lean 4 Core - Zero External Dependencies)
  Module: EpistemicPromotionInvariants.lean

  Scope Clarification (Honest Boundary of Formal Verification):
    - This Lean 4 module formally verifies RFCHunt's *epistemic promotion
      gating specification* (`engine/epistemic_state.py`), paired with
      exhaustive Python conformance tests checking that the runtime gate
      matches this state machine.
    - Target-code claims themselves are verified by deterministic AST/CFG
      precondition checks (`engine/claim_verifier.py`), Z3 SMT constraint
      witnesses (`engine/verification_inversion_hunter.py`), independent
      behavioral/runtime PoE execution (`engine/poe_container_verifier.py`
      and 3-trial wire replay), and empirical patched-vs-unpatched &
      adversarial false-claim benchmarks (`benchmarks/eval_epistemic_rigor.py`).

  Theorems Proved (Zero `sorry` / Zero External Dependencies):
    1. llm_without_independent_oracle_never_proven_runtime
    2. llm_without_independent_oracle_never_proven_static
    3. unanimous_llm_only_stays_unresolved
    4. missing_obligations_stays_unresolved
    5. refuted_dominates_all_oracles
    6. dominating_sanitizer_forces_refuted
    7. proven_runtime_requires_execution_evidence
    8. proven_static_requires_independent_witness
-/

namespace RFCHunt.Epistemic

/-- Strict 4-state epistemic lattice for every RFCHunt security finding. -/
inductive EpistemicState where
  | provenRuntime
  | provenStaticInvariant
  | unresolved
  | refuted
  deriving DecidableEq, Repr

/-- Complete proof-obligation input record evaluated by the RFCHunt promotion gate. -/
structure PromotionInput where
  independentOracles       : Nat
  correlatedLlmOracles     : Nat
  poeLevel                 : Nat
  runtimePoeExecuted       : Bool
  runtimePoePassed         : Bool
  staticInvariantWitness   : Bool
  dominatingSanitizerFound : Bool
  refuted                  : Bool
  missingObligations       : Nat
  deriving DecidableEq, Repr

/--
  Canonical fail-closed epistemic state-machine transition function.
  Matches `engine.epistemic_state.evaluate_epistemic_transition` 1-to-1.
-/
def deriveState (x : PromotionInput) : EpistemicState :=
  if x.refuted || x.dominatingSanitizerFound then
    EpistemicState.refuted
  else if x.independentOracles = 0 then
    EpistemicState.unresolved
  else if x.missingObligations > 0 then
    EpistemicState.unresolved
  else if x.runtimePoeExecuted && x.runtimePoePassed && decide (x.poeLevel ≥ 3) then
    EpistemicState.provenRuntime
  else if x.staticInvariantWitness then
    EpistemicState.provenStaticInvariant
  else
    EpistemicState.unresolved

/-- Theorem 1: LLM agreement without an independent oracle NEVER transitions to PROVEN_RUNTIME. -/
theorem llm_without_independent_oracle_never_proven_runtime
    (x : PromotionInput)
    (hno_indep : x.independentOracles = 0) :
    deriveState x ≠ EpistemicState.provenRuntime := by
  unfold deriveState
  cases hr : (x.refuted || x.dominatingSanitizerFound) <;> simp [hno_indep]

/-- Theorem 2: LLM agreement without an independent oracle NEVER transitions to PROVEN_STATIC_INVARIANT. -/
theorem llm_without_independent_oracle_never_proven_static
    (x : PromotionInput)
    (hno_indep : x.independentOracles = 0) :
    deriveState x ≠ EpistemicState.provenStaticInvariant := by
  unfold deriveState
  cases hr : (x.refuted || x.dominatingSanitizerFound) <;> simp [hno_indep]

/-- Theorem 3: Even unanimous (>= 3) correlated LLM agreement with zero independent oracles stays strictly UNRESOLVED (when not refuted). -/
theorem unanimous_llm_only_stays_unresolved
    (x : PromotionInput)
    (hno_indep : x.independentOracles = 0)
    (hnot_ref : x.refuted = false)
    (hno_san : x.dominatingSanitizerFound = false)
    (_hunanimous : x.correlatedLlmOracles ≥ 3) :
    deriveState x = EpistemicState.unresolved := by
  simp [deriveState, hno_indep, hnot_ref, hno_san]

/-- Theorem 4: Any non-refuted claim with missing proof obligations stays strictly UNRESOLVED. -/
theorem missing_obligations_stays_unresolved
    (x : PromotionInput)
    (hnot_ref : x.refuted = false)
    (hno_san : x.dominatingSanitizerFound = false)
    (hmissing : x.missingObligations > 0) :
    deriveState x = EpistemicState.unresolved := by
  unfold deriveState
  by_cases h0 : x.independentOracles = 0
  · simp [hnot_ref, hno_san, h0]
  · simp [hnot_ref, hno_san, h0, hmissing]

/-- Theorem 5: Explicit refutation dominates all correlated and independent signals. -/
theorem refuted_dominates_all_oracles
    (x : PromotionInput)
    (href : x.refuted = true) :
    deriveState x = EpistemicState.refuted := by
  simp [deriveState, href]

/-- Theorem 6: A dominating AST sanitizer/guard forces REFUTED regardless of LLM consensus. -/
theorem dominating_sanitizer_forces_refuted
    (x : PromotionInput)
    (hsan : x.dominatingSanitizerFound = true) :
    deriveState x = EpistemicState.refuted := by
  simp [deriveState, hsan]

/-- Theorem 7: PROVEN_RUNTIME requires independent execution evidence (poeLevel >= 3, executed, passed, zero missing obligations, not refuted). -/
theorem proven_runtime_requires_execution_evidence
    (x : PromotionInput)
    (h : deriveState x = EpistemicState.provenRuntime) :
    x.refuted = false ∧
    x.dominatingSanitizerFound = false ∧
    x.independentOracles > 0 ∧
    x.missingObligations = 0 ∧
    x.runtimePoeExecuted = true ∧
    x.runtimePoePassed = true ∧
    x.poeLevel ≥ 3 := by
  unfold deriveState at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · rename_i hnotref hnotzero hnotmiss hrun
          have h1 : x.refuted = false ∧ x.dominatingSanitizerFound = false := by
            cases hr : x.refuted <;> cases hs : x.dominatingSanitizerFound <;> simp_all
          have h2 : x.independentOracles > 0 := Nat.pos_of_ne_zero hnotzero
          have h3 : x.missingObligations = 0 := Nat.eq_zero_of_not_pos hnotmiss
          have h4 : x.runtimePoeExecuted = true ∧ x.runtimePoePassed = true ∧ x.poeLevel ≥ 3 := by
            cases he : x.runtimePoeExecuted <;> cases hp : x.runtimePoePassed <;> simp_all
          exact ⟨h1.1, h1.2, h2, h3, h4.1, h4.2.1, h4.2.2⟩
        · split at h <;> cases h

/-- Theorem 8: PROVEN_STATIC_INVARIANT requires an independent static/formal witness with no dominating sanitizer and zero missing obligations. -/
theorem proven_static_requires_independent_witness
    (x : PromotionInput)
    (h : deriveState x = EpistemicState.provenStaticInvariant) :
    x.refuted = false ∧
    x.dominatingSanitizerFound = false ∧
    x.independentOracles > 0 ∧
    x.missingObligations = 0 ∧
    x.staticInvariantWitness = true := by
  unfold deriveState at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · split at h
        · cases h
        · split at h
          · rename_i hnotref hnotzero hnotmiss _ hstat
            have h1 : x.refuted = false ∧ x.dominatingSanitizerFound = false := by
              cases hr : x.refuted <;> cases hs : x.dominatingSanitizerFound <;> simp_all
            have h2 : x.independentOracles > 0 := Nat.pos_of_ne_zero hnotzero
            have h3 : x.missingObligations = 0 := Nat.eq_zero_of_not_pos hnotmiss
            exact ⟨h1.1, h1.2, h2, h3, hstat⟩
          · cases h

end RFCHunt.Epistemic
