/-
  RFCHunt Compiled Lean 4 Runtime Oracle (`rfchunt-lean-oracle`)
  ==============================================================
  Exposes the exact kernel-proven functions from `RFCHunt.PolicyGuard`,
  `RFCHunt.HttpFramingOracle`, and `RFCHunt.DotNetPeIntegrity` as a fast native
  executable callable directly from Python (eliminating Python-vs-Lean mirror drift).
-/

import RFCHunt.PolicyGuard
import RFCHunt.HttpFramingOracle
import RFCHunt.DotNetPeIntegrity

open RFCHunt.PolicyGuard
open RFCHunt.HttpFramingOracle
open RFCHunt.DotNetPeIntegrity

private def parseBool (s : String) : Bool :=
  s == "true" || s == "1"

private def parseAction (s : String) : Option ActionKind :=
  match s with
  | "readWorkspaceFile" => some .readWorkspaceFile
  | "networkProbe" => some .networkProbe
  | "shellExec" => some .shellExec
  | "destructiveHttp" => some .destructiveHttp
  | _ => none

private def parseScope (s : String) : Option TargetScope :=
  match s with
  | "inScopeAuthorized" => some .inScopeAuthorized
  | "outOfScope" => some .outOfScope
  | "privateOrLoopbackBlocked" => some .privateOrLoopbackBlocked
  | _ => none

private def parseRules (csv : String) : List PolicyRule :=
  if csv.isEmpty || csv == "none" then
    []
  else
    (csv.splitOn ",").filterMap fun item =>
      match item.splitOn ":" with
      | [effStr, matchStr] =>
        let eff? : Option Effect :=
          if effStr == "permit" then some .permit
          else if effStr == "forbid" then some .forbid
          else none
        eff?.map fun eff => { effect := eff, applies := fun _ => parseBool matchStr }
      | _ => none

private def parseNatList (csv : String) : List Nat :=
  if csv.isEmpty || csv == "none" then
    []
  else
    (csv.splitOn ",").filterMap String.toNat?

private def formatVerdict : FramingVerdict → String
  | .reject400 => "reject400"
  | .acceptChunked => "acceptChunked"
  | .acceptContentLength n => s!"acceptContentLength:{n}"

private def formatLoadOutcome : LoadOutcome → String
  | .loadedViaSecImageVerified => "loadedViaSecImageVerified"
  | .loadedViaUncheckedFlatMemoryFallback => "loadedViaUncheckedFlatMemoryFallback"
  | .rejectedInvalidOrUnsigned => "rejectedInvalidOrUnsigned"

def main (args : List String) : IO UInt32 := do
  match args with
  | ["policy", actStr, scopeStr, inRootStr, allowDestrStr, rulesCsv] =>
    match parseAction actStr, parseScope scopeStr with
    | some act, some sc =>
      let req : AgentRequest := {
        action := act,
        scope := sc,
        inWorkspaceRoot := parseBool inRootStr,
        allowDestructive := parseBool allowDestrStr
      }
      let rules := parseRules rulesCsv
      let allowed := evaluatePolicies rules req
      IO.println (if allowed then "true" else "false")
      return 0
    | _, _ =>
      IO.eprintln "invalid action or scope"
      return 2

  | ["reconcile", toolStr, llmStr] =>
    let res := reconcileVerdict (parseBool toolStr) (parseBool llmStr)
    IO.println (if res then "true" else "false")
    return 0

  | ["framing", clsCsv, teStr, bareLfStr] =>
    let hdrs : HttpFramingHeaders := {
      contentLengths := parseNatList clsCsv,
      hasTransferEncodingChunked := parseBool teStr,
      hasBareLF := parseBool bareLfStr
    }
    IO.println (formatVerdict (strictRfc9112 hdrs))
    return 0

  | ["pe", validPeStr, clrStr, execBitStr, umciStr, signedStr] =>
    let hdr : PeAssemblyHeader := {
      isValidPe := parseBool validPeStr,
      hasClrDescriptor := parseBool clrStr,
      hasExecutableImageBit := parseBool execBitStr,
      isUmciEnforced := parseBool umciStr,
      isSignedByTrustedPublisher := parseBool signedStr
    }
    let anom := if isCve2026108398Anomaly hdr then "true" else "false"
    let unpatched := formatLoadOutcome (unpatchedNet4Loader hdr)
    let patched := formatLoadOutcome (patchedNet4Loader hdr)
    IO.println s!"{anom}|{unpatched}|{patched}"
    return 0

  | _ =>
    IO.eprintln "usage: rfchunt-lean-oracle <policy|reconcile|framing|pe> ..."
    return 2
