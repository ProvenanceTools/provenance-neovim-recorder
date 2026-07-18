--- Master public key used to verify a workspace `.provenance-manifest` during
--- activation (design.md §4.1). This is the maintainer-held signing key's public
--- half — public by definition, committed here on `main`; the private half is
--- kept offline and never enters the repo. It is named COURSE_PUBLIC_KEY_HEX for
--- parity with the VS Code / JetBrains recorders, but operationally it is a single
--- master key: there is one published plugin, not a fork per course.
---
--- Because Neovim plugins have no build step, this constant ships as-is in every
--- tagged release; the release's source tree-hash (its `extension_hash`) is what
--- the analyzer allowlists. Rotating the key is therefore a normal new tagged
--- release plus a new allowlist entry — see docs/design.md §6–§7.
---
--- Tests never assume this equals any fixture key: the conformance manifest
--- fixture carries its own dev keypair and is verified by passing that key
--- explicitly (see tests/recorder/activation_loader_spec.lua).
local M = {}

M.COURSE_PUBLIC_KEY_HEX = "b5bca59ffa918c879d01050dab428e60c630f9d2051508af3d29c60cce985e25"

return M
