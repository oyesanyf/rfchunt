import Lake
open Lake DSL

package «rfchunt_formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «RFCHunt» where
  roots := #[`RFCHunt]
