import Lake
open Lake DSL

package «rfchunt_formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «RFCHunt» where
  roots := #[`RFCHunt]

@[default_target]
lean_exe «rfchunt-lean-oracle» where
  root := `Main
