# Provenance Recorder for Neovim

**Provenance Recorder for Neovim** records a tamper-evident log of how a student's code came
into existence, and seals it into a signed submission bundle.

It is the Neovim counterpart to the
[Provenance](https://github.com/ProvenanceTools/provenance) VS Code recorder and the
[JetBrains recorder](https://github.com/ProvenanceTools/provenance-jetbrains-recorder), and
ships under the same **Provenance Recorder** name. All three produce a bundle in the **same
format**, so the Provenance analyzer and server ingest and validate a submission regardless
of which editor produced it — they care only that it validates: hash chain intact, manifest
signature verifies, `extension_hash` on the allowlist.

This is a **port of the wiring, not a new product**. The event format, hash chain, JCS
canonicalization, ed25519 signing, bundle and manifest shapes, signed checkpoints, and
per-session keypair are all defined by the Provenance monorepo's `log-core` package. This
repo reimplements that format in Lua and re-derives the editor-specific signal detection
against the Neovim API.

## How it works

The plugin activates only on a workspace containing a valid, course-signed
`.provenance-manifest`. From then on it records a timestamped, hash-chained log of editing
activity, buffered and written atomically, and seals it into a signed bundle at the end of
the session.

The log format is a **fixed contract owned by the Provenance monorepo**, not by this repo.
Parity is not assumed — it is tested. `core/`'s output is verified byte-for-byte against
`log-core` using golden vectors exported from the monorepo, so all three editors' bundles
stay compatible down to the byte. If a conformance test fails, the implementation is wrong;
the vectors are never edited to make it pass.

```
lua/provenance/core/      pure-Lua port of the log format — no editor APIs
lua/provenance/recorder/  the plugin: Neovim wiring around core/
```

## Crypto: pure Lua, zero native dependencies

Unlike the VS Code and JetBrains recorders, Neovim ships no standard crypto library, so the
recorder carries its own — **in pure Lua, with no native dependency**:

- **SHA-256** via Neovim's builtin `vim.fn.sha256`.
- **ed25519** and **XChaCha20-Poly1305** are vendored pure-Lua implementations.
- **File I/O** (atomic write-temp-then-rename, fsync) via `vim.uv` (libuv).

This means the recorder runs anywhere Neovim runs — every OS, every student machine — with
no libsodium to install, no FFI, no compiled sidecar. It is also fully auditable, which the
recorder is required to be: the protocol is public and students are expected to read the
source. Signing is infrequent (session start, periodic checkpoints, final seal), so the
per-keystroke path only ever *hashes* — the rare, heavier signing work never touches the
edit hot loop. Correctness is not taken on faith: the vendored crypto is proven against the
same golden conformance vectors that pin the format.

## What it records

- **Document changes.** File open, save, close, and every edit, recorded from Neovim's
  `nvim_buf_attach` `on_lines` firehose with per-event handler work kept minimal and the
  writer buffered.
- **Pastes.** Detected by combining three signals — bracketed paste / `vim.paste()`, the
  resulting `on_lines` edit burst, and clipboard register content (`+`/`*`). Neovim has no
  single paste-command surface, so no one signal is sufficient; the three are reconciled
  into exactly one event per paste.
- **External changes.** Edits made to watched files *outside* Neovim, detected via
  `FileChangedShell` (driven by `autoread`/`:checktime`) against an in-memory
  expected-content model. Only files listed in the manifest get that model.
- **Selection and cursor movement.**
- **Terminal and git activity**, where available. Git may be absent or provided only by a
  third-party plugin; missing git integration is a degraded signal, not a crash.
- **Session metadata and signed checkpoints** throughout the session, so a truncated log
  still validates up to its last checkpoint.

## Privacy & security

- **Offline.** The plugin makes no network calls during a session.
- **Scoped to the assignment workspace.** It activates only against a `.provenance-manifest`
  that verifies with the course public key committed in the release. Events for files
  outside the workspace are dropped. It never records a student's Neovim config
  (`init.lua`, `~/.config/nvim`) or out-of-workspace scratch buffers.
- **Append-only.** There is no update or delete on a log, anywhere. Exactly one chaining
  function; every log-producing path goes through it.
- **Signed at seal.** Each session gets its own ed25519 keypair, and the private key is
  encrypted at rest under a key derived from the manifest signature. `manifest.json` and
  `manifest.sig` are never modified after seal.
- **Atomic writes.** Write-temp-then-rename via `vim.uv`. The live log file is never
  partially written.

## Requirements

- **Neovim 0.10+** (the version floor is pinned to stable `vim.uv`, `nvim_buf_attach`
  `on_lines`, and `FileChangedShell` semantics — see `docs/design.md` §12).
- **A course-signed `.provenance-manifest`** at the workspace root. Without one the plugin
  stays inactive by design.
- No native dependencies. No compiler. No libsodium.

## Install

Install with any Neovim plugin manager, from the release your course points you at. With
[lazy.nvim](https://github.com/folke/lazy.nvim):

```lua
{
  "ProvenanceTools/provenance-neovim-recorder",
  -- pin the tag your course specifies; the tag commits the course public key,
  -- and its source tree-hash is what the analyzer allowlist recognizes.
  version = "v0.1.0",
}
```

The plugin does nothing until you open a workspace containing a course-signed
`.provenance-manifest` — so it is safe to have installed all the time.

> **Why a tag matters.** Neovim plugins are git checkouts, not signed artifacts. The
> recorder's `extension_hash` is a deterministic hash of its own installed Lua source at
> runtime, and the analyzer allowlists the hash of each released tag. Installing an arbitrary
> commit or a fork with modified source will produce a hash the analyzer does not recognize,
> and every submission from it gets flagged.

## Developing

Lua, tested headless with Neovim.

```sh
git clone https://github.com/ProvenanceTools/provenance-neovim-recorder
cd provenance-neovim-recorder

# run the test suite headless (harness pinned at implementation time)
nvim --headless -c "..." tests/
```

Wiring tests run under headless Neovim, mocking the Neovim API at the seam. The
event→log-entry transform is tested as a pure function, separately from the editor wiring.
Clocks are injected, so no test asserts against wall-clock time. A few behaviors need a real,
focused TUI (`FileChangedShell` on focus, live terminal/status render) — those are a short
manual checklist, not headless coverage.

## Conformance

Cross-language format parity is the non-negotiable gate. `core/`'s output is checked
byte-for-byte against `log-core` using golden vectors, plus a golden sealed bundle. These are
generated, not hand-authored — and generated by the **same** export script the JetBrains
recorder uses. Regenerate them from the monorepo:

```sh
cd ../provenance
node --experimental-strip-types tools/export-conformance-vectors.ts \
  --out ../provenance-neovim-recorder/tests/conformance/fixtures
```

**Never hand-edit a vector file.** A failing conformance test after regenerating means the
implementation has drifted from the format — fix `core/`, never the vectors.

## Repo layout

```
provenance-neovim-recorder/
├── lua/provenance/
│   ├── core/            # pure-Lua port of the log format — no editor APIs
│   └── recorder/        # the plugin: Neovim wiring around core/
├── tests/
│   └── conformance/     # golden vectors exported from log-core
├── docs/
│   └── design.md        # the approved architecture and design
├── CLAUDE.md            # repo conventions
└── README.md
```

## Architecture rules (enforced)

- **`core/` has zero editor imports.** It knows about events, hashing, canonicalization,
  signing, bundles, and the source tree-hash — nothing about buffers, autocmds, or editing.
  This mirrors `log-core`'s zero-editor-dependency rule and keeps the conformance surface
  testable in isolation.
- **`recorder/` depends on `core/` and the Neovim API.** Activation, listeners, paste
  detection, the session host, the status indicator, the seal command.
- **The log format is a contract, not a design space.** It is pinned by test vectors in
  `log-core` and by the golden vectors here. A change to accommodate Neovim would be a
  cross-repo, signed-contract decision owned by the monorepo — never made unilaterally here.
- **Crypto stays pure Lua.** No FFI, no libsodium, no compiled sidecar. Vendored, auditable,
  verified against the conformance vectors.
- **No background task without an explicit teardown path.** Every autocmd group, `buf_attach`,
  timer, and job has a `dispose()` / plugin-teardown hook.

## The recorder family

| Recorder | Editor | Language | Repo |
| --- | --- | --- | --- |
| `provcode` | VS Code | TypeScript | in the [monorepo](https://github.com/ProvenanceTools/provenance) (`packages/recorder`) |
| `provjet` | JetBrains IDEs | Kotlin | [provenance-jetbrains-recorder](https://github.com/ProvenanceTools/provenance-jetbrains-recorder) |
| `provnvim` | Neovim | Lua | this repo |

All three produce the identical bundle format. The recorder product spec (`docs/prd.md`)
lives in the monorepo.

## Documentation

| Document                           | What's in it                          |
| ---------------------------------- | ------------------------------------- |
| [`docs/design.md`](docs/design.md) | The approved architecture and design. |
| [`CLAUDE.md`](CLAUDE.md)           | Repo conventions and architecture rules. |

## License

Licensed under the Apache License, Version 2.0 — see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).

Because a Neovim plugin is distributed as its own source tree, any third-party code
the recorder depends on at runtime (notably the vendored pure-Lua ed25519 and
XChaCha20-Poly1305) will be committed into this repo and therefore redistributed by
us. When that crypto is vendored, a `THIRD-PARTY-NOTICES.txt` reproducing each
component's license and attribution is added in the same commit — a hard release
gate, since the plugin's `extension_hash` is a hash of exactly this source tree.

## Trademarks

Neovim and Vim are separate works used as the host runtime; this project is
independent and not affiliated with or endorsed by the Neovim or Vim projects.

## Contributing

Contributor conventions and architecture rules live in [`CLAUDE.md`](CLAUDE.md); the design
is in [`docs/design.md`](docs/design.md). Read `CLAUDE.md` before making changes. The rule
that matters most: **this repo implements the Provenance log format, it does not author it.**
The format is pinned by conformance vectors, and loosening an assertion or editing a vector
to make a test pass is not a coding decision — if the format appears to need a change, stop
and ask.

## Development / Testing

Requires Neovim ≥ 0.10 (developed against 0.12.1) and `plenary.nvim` on the
runtimepath. Run the suite headless:

    make test

`make test` runs `plenary.nvim`'s busted-style runner over `tests/`. The
conformance suite (`tests/conformance/`) proves byte-for-byte format parity
with the Provenance monorepo's `log-core`; a red conformance test means the
implementation drifted — fix the code, never the vectors. Regenerate vectors
with `PROVENANCE_REPO=/path/to/provenance make vectors`.

### Conformance

`lua/provenance/core/` is verified byte-for-byte against Provenance's `log-core`
via golden vectors exported by the monorepo's `tools/export-conformance-vectors.ts`
into `tests/conformance/fixtures/`. A failing conformance test means the format
has drifted — fix the implementation, never the vectors. Crypto/bundle vectors
are asserted starting in Plan 2.

`tests/conformance/conformance_spec.lua` currently asserts the format vectors in
`fixtures/vectors.json`: the pinned SHA-256 test cases and the pinned hash-chain
entry, run through this repo's `core.sha256` and `core.hash_chain` +
`core.envelope`. The remaining fixtures (`ed25519.json`, `session-key.json`,
`checkpoint.json`, `manifest.json`, `bundle-manifest.json`, `golden-bundle.json`,
`golden-bundle.zip`) are committed now as the pinned contract snapshot but are
not yet asserted against — they gate the vendored ed25519/XChaCha20 crypto and
the seal/bundle path added in Plan 2.
