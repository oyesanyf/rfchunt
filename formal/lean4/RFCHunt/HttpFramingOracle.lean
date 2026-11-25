/-
  RFCHunt Formal RFC 9112 HTTP/1.1 Framing Differential Oracle (Lean 4)
  =====================================================================
  Formalizes core RFC 9112 Section 6.3 message framing invariants as an executable
  reference oracle for differential testing against permissive/legacy HTTP proxies:
  1. `strict_rejects_cl_te_conflict`: Strict RFC 9112 rejects simultaneous CL + TE.
  2. `strict_rejects_mismatched_dual_cl`: Strict RFC 9112 rejects conflicting duplicate CLs.
  3. `differential_witness_cl_te`: Constructive witness proving divergence between
     Strict RFC 9112 and a permissive CL-first proxy (desync condition).
-/

namespace RFCHunt.HttpFramingOracle

inductive FramingVerdict where
  | acceptContentLength (len : Nat)
  | acceptChunked
  | reject400
  deriving DecidableEq, Repr

structure HttpFramingHeaders where
  contentLengths : List Nat
  hasTransferEncodingChunked : Bool
  hasBareLF : Bool
  deriving DecidableEq, Repr

def allEqualNat : List Nat → Bool
  | [] => true
  | [_] => true
  | x :: y :: rest => (x == y) && allEqualNat (y :: rest)

/-- Strict RFC 9112 Section 2.2 & 6.3 reference oracle. -/
def strictRfc9112 (h : HttpFramingHeaders) : FramingVerdict :=
  if h.hasBareLF then
    .reject400
  else if h.hasTransferEncodingChunked && !h.contentLengths.isEmpty then
    .reject400
  else if h.hasTransferEncodingChunked then
    .acceptChunked
  else
    match h.contentLengths with
    | [] => .acceptContentLength 0
    | n :: rest =>
      if allEqualNat (n :: rest) then .acceptContentLength n else .reject400

/-- Permissive legacy proxy model (prioritizes first Content-Length even when TE is present). -/
def permissiveClFirstProxy (h : HttpFramingHeaders) : FramingVerdict :=
  match h.contentLengths with
  | n :: _ => .acceptContentLength n
  | [] => if h.hasTransferEncodingChunked then .acceptChunked else .acceptContentLength 0

/-- Theorem 1: Strict RFC 9112 unconditionally rejects any CL + TE conflict. -/
theorem strict_rejects_cl_te_conflict
    (h : HttpFramingHeaders)
    (hTE : h.hasTransferEncodingChunked = true)
    (hCL : h.contentLengths.isEmpty = false) :
    strictRfc9112 h = .reject400 := by
  unfold strictRfc9112
  cases hb : h.hasBareLF <;> simp [hb, hTE, hCL]

/-- Theorem 2: Strict RFC 9112 unconditionally rejects conflicting duplicate Content-Length values. -/
theorem strict_rejects_mismatched_dual_cl
    (n m : Nat) (hNeq : n ≠ m) (hBare : Bool) :
    strictRfc9112 { contentLengths := [n, m], hasTransferEncodingChunked := false, hasBareLF := hBare } = .reject400 := by
  unfold strictRfc9112 allEqualNat
  have hBeq : (n == m) = false := beq_false_of_ne hNeq
  cases hBare <;> simp [hBeq]

/-- Theorem 3: Constructive differential witness where Strict RFC 9112 and a permissive CL-first
    proxy diverge on the exact same HTTP headers. -/
theorem differential_witness_cl_te :
    ∃ h : HttpFramingHeaders, strictRfc9112 h ≠ permissiveClFirstProxy h := by
  refine ⟨{ contentLengths := [42], hasTransferEncodingChunked := true, hasBareLF := false }, ?_⟩
  decide

end RFCHunt.HttpFramingOracle
