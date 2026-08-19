--- The recorder's embedded verification anchors (design.md §4.1; program spec
--- §2/§9, 2026-08-18-multicourse-program-architecture).
---
--- There are TWO, and they are not interchangeable. Which one applies is decided
--- by the manifest's `format_version`, in `recorder/activation.lua`:
---
---   2.0        -> ROOT_PUBLIC_KEY_HEX, via manifest.verify_chain
---   1.x/absent -> LEGACY_COURSE_PUBLIC_KEY_HEX, via manifest.verify
---
--- Both are PUBLIC keys, public by definition and committed here on `main`; the
--- private halves are held offline and never enter the repo. Because Neovim
--- plugins have no build step, these constants ship as-is in every tagged
--- release, and the release's source tree-hash (its `extension_hash`) is what
--- the analyzer allowlists — so rotating either key is a normal new tagged
--- release plus a new allowlist entry (docs/design.md §6-§7). That is this
--- repo's equivalent of the VS Code recorder's `build:prod` key-embedding step.
---
--- This module replaces the former `provenance.course_public_key`, which
--- exported a single `COURSE_PUBLIC_KEY_HEX`. One embedded key per build is
--- exactly what the trust hierarchy exists to remove.
local M = {}

--- The Provenance ROOT public key — the trust anchor for Manifest 2.0.
---
--- At 1.x the recorder embedded one course's signing key, so every course would
--- have needed its own release. At 2.0 it embeds the ROOT key only: a course's
--- authority comes from its root-signed `course_cert`, which travels inline in
--- the `.provenance-manifest`. One published plugin serves every course.
---
--- This is the DEV root key, shared verbatim by all three recorder
--- implementations so one dev manifest activates in any of them.
M.ROOT_PUBLIC_KEY_HEX = "80051f5bdb9064e0768bf2fca5cc9a4ee888502ab45472e0c6d0f4f704de4499"

--- The LEGACY course public key — the grandfathered anchor for Manifest 1.x.
---
--- Every 1.x manifest already in the field was signed directly by a course's OLD
--- signing key, with no cert and no chain. Verifying those against the ROOT key
--- fails closed, and a failed activation is silent non-recording — total
--- evidence loss for anyone whose course has not re-issued yet. So the old key
--- is grandfathered back in for the 1.x path, and ONLY the 1.x path: a 2.0
--- manifest never verifies against it, which is what keeps the chain's step-0
--- downgrade gate meaningful.
---
--- **Scheduled for removal.** A second permanent trust anchor is precisely what
--- the root-key hierarchy exists to eliminate. Once program spec §9's migration
--- has completed for every course with manifests still active in the field —
--- i.e. no 1.x manifest anyone still needs to verify remains unreissued as 2.0 —
--- delete this constant, the 1.x branch in `recorder/activation.lua` that reads
--- it, and its entry in tests/recorder/trust_keys_spec.lua.
M.LEGACY_COURSE_PUBLIC_KEY_HEX = "46f91d5902c53816110b05ddedd2b8caa95b452d51e696f5327b52bf90bf4838"

return M
