/-
  RFCHunt Formal PE & .NET Framework 4 UMCI Loader Invariant (Lean 4)
  ===================================================================
  Formalizes the Windows PE / .NET Framework 4 code-integrity discrepancy
  (CVE-2026-108398 / CVE-2026-87268):
  - Clearing `IMAGE_FILE_EXECUTABLE_IMAGE` (0x0002) on a .NET assembly with a valid
    CLR header (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`) causes `SEC_IMAGE` mapping
    to fail and triggers an uninspected `SEC_COMMIT` flat memory fallback on unpatched
    .NET Framework 4.
  - Proves that the patched policy model blocks all unverified `SEC_COMMIT` fallbacks
    when UMCI is enforced.
-/

namespace RFCHunt.DotNetPeIntegrity

structure PeAssemblyHeader where
  isValidPe : Bool
  hasClrDescriptor : Bool
  hasExecutableImageBit : Bool  -- IMAGE_FILE_EXECUTABLE_IMAGE (0x0002)
  isUmciEnforced : Bool
  isSignedByTrustedPublisher : Bool
  deriving DecidableEq, Repr

inductive LoadOutcome where
  | loadedViaSecImageVerified
  | loadedViaUncheckedFlatMemoryFallback
  | rejectedInvalidOrUnsigned
  deriving DecidableEq, Repr

/-- Unpatched .NET Framework 4 loader model (CVE-2026-108398). -/
def unpatchedNet4Loader (h : PeAssemblyHeader) : LoadOutcome :=
  if !h.isValidPe || !h.hasClrDescriptor then
    .rejectedInvalidOrUnsigned
  else if h.hasExecutableImageBit then
    if h.isUmciEnforced && !h.isSignedByTrustedPublisher then
      .rejectedInvalidOrUnsigned
    else
      .loadedViaSecImageVerified
  else
    -- Clearing 0x0002 forces STATUS_INVALID_IMAGE_FORMAT -> flat SEC_COMMIT memory fallback
    .loadedViaUncheckedFlatMemoryFallback

/-- Patched .NET Framework 4 loader model (KB5127694+). -/
def patchedNet4Loader (h : PeAssemblyHeader) : LoadOutcome :=
  if !h.isValidPe || !h.hasClrDescriptor || !h.hasExecutableImageBit then
    .rejectedInvalidOrUnsigned
  else if h.isUmciEnforced && !h.isSignedByTrustedPublisher then
    .rejectedInvalidOrUnsigned
  else
    .loadedViaSecImageVerified

/-- Anomaly detector predicate matching `engine/pe_magika_classifier.py`. -/
def isCve2026108398Anomaly (h : PeAssemblyHeader) : Bool :=
  h.isValidPe && h.hasClrDescriptor && !h.hasExecutableImageBit

/-- Theorem 1: Any assembly flagged by `isCve2026108398Anomaly` triggers the unchecked flat
    memory fallback on unpatched .NET Framework 4, even when UMCI is enforced and unsigned. -/
theorem anomaly_triggers_unpatched_fallback (h : PeAssemblyHeader)
    (hAnom : isCve2026108398Anomaly h = true) :
    unpatchedNet4Loader h = .loadedViaUncheckedFlatMemoryFallback := by
  unfold isCve2026108398Anomaly at hAnom
  unfold unpatchedNet4Loader
  cases hv : h.isValidPe <;> cases hc : h.hasClrDescriptor <;> cases he : h.hasExecutableImageBit <;> simp_all

/-- Theorem 2: The patched loader NEVER permits unchecked flat memory fallback for any input. -/
theorem patched_loader_never_uses_unchecked_fallback (h : PeAssemblyHeader) :
    patchedNet4Loader h ≠ .loadedViaUncheckedFlatMemoryFallback := by
  unfold patchedNet4Loader
  cases hv : h.isValidPe <;> cases hc : h.hasClrDescriptor <;> cases he : h.hasExecutableImageBit <;>
    cases hu : h.isUmciEnforced <;> cases hs : h.isSignedByTrustedPublisher <;> simp

/-- Theorem 3: Under UMCI enforcement, the patched loader rejects all unsigned assemblies. -/
theorem patched_loader_enforces_umci (h : PeAssemblyHeader)
    (hUmci : h.isUmciEnforced = true) (hUnsigned : h.isSignedByTrustedPublisher = false) :
    patchedNet4Loader h = .rejectedInvalidOrUnsigned := by
  unfold patchedNet4Loader
  cases hv : h.isValidPe <;> cases hc : h.hasClrDescriptor <;> cases he : h.hasExecutableImageBit <;>
    simp [hUmci, hUnsigned]

end RFCHunt.DotNetPeIntegrity
