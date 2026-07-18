# Design: Provenance Neovim Recorder (`provnvim`)

**Status:** Approved design, pre-implementation
**Date:** 2026-07-17
**External brand:** Provenance Recorder (identical to the VS Code and JetBrains recorders)
**Internal codename:** `provnvim`

---

## 1. What this is

A Neovim plugin (Lua) that records a tamper-evident `.provenance` log while a
student works on an assignment, producing a sealed submission bundle that is
**byte-for-byte format-compatible** with the one the VS Code recorder produces.
The Provenance analyzer and server do not care which editor produced a bundle —
only that it validates (hash chain intact, manifest signature verifies,
`extension_hash` on the allowlist).

This is a **port of the wiring, not a new product.** The event format, hash
chain, JCS canonicalization, ed25519 signing, bundle/manifest shapes, signed
checkpoints, and per-session keypair all already exist in the Provenance
monorepo's `packages/log-core` (pure TypeScript). This repo reimplements that
format in Lua and re-derives the editor-specific signal detection against the
Neovim API.

It lives in **its own repo** (not the Provenance monorepo, not the JetBrains
recorder repo) for the same reason `provjet` does: the Lua/LuaJIT toolchain and
Neovim plugin layout cannot live inside the monorepo's npm workspace. This is a
forcing function, not a preference — see §9. It is the third member of the
recorder family, alongside the VS Code recorder (`provcode`, in the monorepo) and
the JetBrains recorder (`provjet`).

## 2. Scope

- **Target:** Neovim, LuaJIT runtime. Version floor is whatever guarantees the
  APIs this design leans on — `vim.uv` (libuv bindings), `nvim_buf_attach`
  `on_lines`, and `FileChangedShell` semantics — most likely **0.10+** (pinned at
  implementation time, see §12).
- **v1 = full behavioral parity** with the VS Code recorder (recorder PRD §4):
  activation + manifest verification, `doc.open/change/save/close`, three-signal
  paste detection (§4.3), external-change detection (§4.5), terminal + git
  wiring, plugin snapshot, hash chain, signed checkpoints, chain recovery,
  bundle seal, disk-full degraded mode.
- Even though v1 targets full parity, it is **built core-first** (§8) so
  canonicalization drift and Neovim event semantics are never debugged in the
  same week.

## 3. The crypto/runtime strategy — the keystone (new vs `provjet`)

`provjet` had a vetted JVM crypto library for every primitive (erdtman JCS,
BouncyCastle ed25519 + hand-composed XChaCha20). Neovim has no such standard
library. The keystone decision for this port is therefore the crypto/runtime
strategy, and it is: **pure-Lua, vendored — zero native dependencies.**

| Primitive | Source in this port |
|---|---|
| SHA-256 (hash chain, tree-hash) | `vim.fn.sha256` (Neovim builtin) |
| JCS canonicalization | ported to Lua; Lua numbers are IEEE-754 doubles like JS, so number formatting — the fiddly part — is a close match |
| ed25519 sign/verify | vendored pure-Lua implementation |
| XChaCha20-Poly1305 | vendored pure-Lua implementation |
| File I/O (atomic write, fsync, rename) | `vim.uv` (libuv) — no native dep |
| Monotonic clock (`t`) | `vim.uv.hrtime()` |
| Wall clock (`wall`) | `os.time` / `os.date`, formatted to the fixed-width millisecond ISO string the format requires |

Rationale for pure-Lua over FFI-to-libsodium or a sidecar binary:

- **Zero native deps.** The plugin runs anywhere Neovim runs — every student
  machine, every OS — with no per-platform native library to bundle, locate, or
  keep ABI-compatible. That native-dependency fragility is the single biggest
  operational risk a pure-Lua editor plugin gets to avoid.
- **Auditable.** Recorder PRD §6 assumes the protocol is public and students read
  the source. A vendored, readable Lua implementation is on-brand; a compiled
  blob (FFI target or sidecar) is not.
- **Performance is a non-issue.** Signing is infrequent — session-start keygen,
  an every-100-entries checkpoint, and the final seal. The per-keystroke firehose
  only *hashes*, and hashing is the builtin `vim.fn.sha256`. LuaJIT executes the
  rare scalar-multiplication paths fast enough that they never touch the hot loop.
- **Correctness risk is neutralized the same way `provjet`'s was** — golden
  conformance vectors (§4). "Sign a known input; assert the *real* analyzer
  verifies the resulting bundle" turns a subtle-crypto worry into a red test.

The cost is that we ship a hand-vendored ed25519/XChaCha20 rather than leaning on
a library with a large audit history. We buy that risk down with the conformance
suite and by vendoring a well-known existing implementation rather than writing
one (see §12, open question 1).

## 4. The format-parity strategy (the low-risk core)

Reimplement `log-core` in Lua, gated by **golden conformance vectors** exported
from the Provenance monorepo.

- **Reuse the existing export.** `provjet` already added
  `tools/export-conformance-vectors.ts` to the monorepo, which emits `log-core`'s
  `hash-chain.test.ts` vectors plus a full golden bundle as language-neutral
  JSON. `provnvim`'s conformance suite consumes the **same** output — no new
  export path, no second source of truth.
- **Conformance suite** (`tests/conformance/`): loads those fixtures and asserts
  (a) byte-identical hashes and canonical forms for known inputs, and (b) that a
  bundle this plugin seals is accepted by the *real* analyzer/server (hash chain,
  manifest signature, all §5.4 checks). Format drift becomes a red test, not a
  production surprise.

The format port is the **well-bounded, low-risk** part of this project. JCS
number formatting is the one subtlety, and it is directly pinned by vectors.

## 5. The Neovim wiring map (the ~70%, where the real work is)

VS Code's document/paste/watcher APIs and Neovim's equivalents have different
semantics. This table is the port's core risk register.

| Signal | VS Code (today) | Neovim equivalent | Risk |
|---|---|---|---|
| doc edits | `onDidChangeTextDocument` (diff-grained) | `nvim_buf_attach` `on_lines` callback (diff-grained: first line, last line, new last line, byte counts) | **Low** — a closer match than IntelliJ's `DocumentListener` was |
| open/save/close | doc lifecycle events | `BufReadPost`/`BufNewFile`, `BufWritePre`+`BufWritePost`, `BufDelete`/`BufUnload` autocmds | Low |
| external change (§4.5) | `FileSystemWatcher` + expected-content model | `FileChangedShell` autocmd + `:checktime`/`autoread`, compared against the expected-content model | **High** — Neovim only *notices* on focus / `checktime`; detection timing and direction |
| paste (§4.3, 3-signal) | paste-command intercept + doc change + clipboard | bracketed-paste / `vim.paste()` override + `on_lines` burst shape + `getreg('+')`/`getreg('*')` compare | **High** — no 1:1 command surface |
| terminal | terminal API | `TermOpen`/`TermRequest` autocmds, `jobstart` output | Med |
| git | git extension API | shell-out to `git`, or detect fugitive/gitsigns presence; must degrade gracefully when absent | Med |
| plugin snapshot | `vscode.extensions.all` | enumerate `runtimepath` / loaded packages → fills the existing `ext.snapshot` event shape | Low |
| status indicator | status bar item | statusline segment / small indicator API | Low |

**External-change detection is the highest-risk item.** Neovim's awareness of
on-disk changes is *lazy*: it fires `FileChangedShell` on focus-gain or an
explicit `:checktime`, not the instant the file changes. The recorder PRD §4.5
note ("easy to get the direction wrong") is doubly true here, because the
on-disk-vs-expected-content comparison interacts with *when* Neovim learns the
file changed. Budget for this specifically, and drive it with `autoread` +
`checktime` in tests.

**Paste is the second high-risk item.** Neovim routes bracketed paste through
`vim.paste()` (overridable) and surfaces the resulting edit through the same
`on_lines` firehose; the clipboard registers (`+`/`*`) give the third signal.
There is no single "paste command" to intercept as in VS Code — the three signals
must be reconciled into exactly one event per paste, mirroring the monorepo's
paste reconciler. Do not simplify to one signal without discussion.

## 6. Producer identity, the integrity anchor, and the one format wrinkle

- **Producer identity already exists:** `session.start.recorder.extension_id`
  lets this plugin identify itself (e.g. `com.provenance.recorder.nvim`, pinned at
  implementation time) with **no format change**. The analyzer can distinguish
  editors from this field if a heuristic ever needs to.

- **The integrity anchor is a runtime source tree-hash.** Neovim plugins are not
  signed build artifacts — a plugin manager (lazy.nvim, packer, etc.) clones a git
  repo. So there is no VSIX/`.zip` whose SHA is the natural `extension_hash`.
  Instead, the recorder **deterministically tree-hashes its own installed Lua
  source at session start** (the same DirectoryHash idea `provjet` centralized in
  its `core/`) and emits that as `extension_hash`. The analyzer's allowlist pins
  the known-good tree hash per tagged release. This is native to how Neovim
  plugins are actually installed, and needs no separate artifact to build or host.
  The tree-hash algorithm (sorted relative paths, per-file SHA-256, one rolling
  digest) is part of `core/` and itself covered by a vector so it is reproducible.

- **The master public key is a committed constant.** Verification uses a single
  maintainer-held *master* key, not a per-course key: there is one published
  plugin, mirroring the single published VS Code / JetBrains extension. Its public
  half is committed as a Lua constant (`lua/provenance/course_public_key.lua`) on
  `main`; the private half is held offline and never enters the repo. There is no
  build-time embed step (Neovim has no build step), so the key ships as-is in every
  tagged release. Because the key is part of the hashed source, a given release's
  tree hash already covers it: rotating the key is simply a new tagged release with
  a new allowlist entry. No secret is ever committed; the *public* key is. (The
  constant is named `COURSE_PUBLIC_KEY_HEX` for parity with the other recorders.)

- **The `vscode` field wrinkle.** `session.start` has a hard-coded
  `vscode: { version, commit, platform }` object that is part of the signed,
  test-vector-pinned format. This recorder must emit *something* there.
  **Decision (v1):** fill it with editor-generic values — `version` = the Neovim
  version, `commit` = `''` (analyzers already accept `''`), `platform` = the OS.
  **No format change.** Rationale: YAGNI, avoids signed-format churn and
  test-vector rework, and `extension_id` already disambiguates the host.
  Generalizing the field to `host`/`editor` would be an approval-gated format bump
  in the monorepo and is explicitly deferred. This is the identical decision
  `provjet` made.

## 7. Distribution & the "prod build" analog

There is no compile/sign step, so the `build:prod` flow the VS Code and JetBrains
recorders run collapses to almost nothing:

- **Distribution** is a plain tagged git release of this one canonical repo,
  installed by any Neovim plugin manager (`version = "v0.1.0"` in lazy.nvim, etc.).
  There are no per-course forks: every course installs the same release and pins
  the tag its course points to. The master public key (§6) is committed on `main`,
  so cutting a release is an ordinary `git tag` — nothing is swapped or embedded at
  release time.
- **`extension_hash`** is the runtime tree-hash of §6, not an artifact SHA. The
  monorepo allowlist pins the tree hash of each released tag. Rotating the master
  key is a new tagged release and a new allowlist entry; older tags keep their old
  key immutably.
- The plugin **never modifies** `manifest.json` / `manifest.sig` after seal — same
  rule as the monorepo and `provjet`. The stored bundle must stay signature/chain
  verifiable.

## 8. Changes required in the Provenance monorepo (small, additive)

This repo does **not** change Provenance source except:

1. **Allowlist:** add this release's source tree-hash to
   `packages/analysis-core/src/heuristics/config/known-good-extension-hashes.json`,
   and teach `npm run update-hashes` about the third producer. The allowlist is
   producer-agnostic — it just needs the hash. Otherwise the
   `extension_hash_mismatch` heuristic flags every Neovim submission.
2. **Golden-vector export:** *already done.* `provjet` added
   `tools/export-conformance-vectors.ts`; this port consumes its output unchanged.
   Expect zero new export work — confirm at implementation time that the emitted
   JSON is editor-neutral (it is, by construction).

No new event types. No heuristic logic changes (heuristics read the format, not
the editor).

## 9. Build sequence

Full-parity v1, but layered so each stage is independently green:

1. `core/` + `tests/conformance/` — Lua format port (JCS, SHA-256, ed25519,
   XChaCha20, hash chain, tree-hash) proven against golden vectors.
2. activation + manifest verification + status indicator.
3. `doc.open/change/save/close` + hash chain + bundle seal → **first valid bundle
   the real analyzer accepts.**
4. external-change detection (the high-risk `FileChangedShell` work, isolated).
5. three-signal paste detection.
6. terminal + git wiring (graceful degradation when git is absent).
7. checkpoints + chain recovery + disk-full degraded mode.
8. integration pass — wire every signal into the live session controller, add the
   `:ProvenanceSeal` user command, re-run the real analyzer with all signals live.

## 10. Why a separate repo (and why the VS Code recorder is *not* split)

`provnvim` is separate because the Lua/LuaJIT toolchain and Neovim plugin layout
cannot live in the monorepo's npm workspace — the same toolchain forcing function
that put `provjet` in its own repo.

The VS Code recorder (`provcode`) **stays in the monorepo** deliberately: it is
TypeScript, consumes `log-core` as live workspace source, and its format parity is
enforced by the same `npm run test` that runs `log-core`'s vectors. Splitting it
would trade that co-located contract enforcement for mere symmetry. **The rule for
"own repo" is a toolchain boundary, not symmetry.**

## 11. Testing

- **Conformance vectors** — cross-language format parity (§4). The non-negotiable
  gate.
- **Wiring unit tests** — Neovim headless (`nvim --headless`) with a Lua test
  harness (`plenary.nvim`'s `busted`-style runner is the leading option, §12 open
  q2), mocking the Neovim API at the seam. Mirror the monorepo convention: test
  the event→log-entry transform as a pure function, separately from the editor
  wiring.
- **Determinism** — inject clocks; no `os.time()` / `vim.uv.hrtime()` in
  assertions (mirrors the monorepo's no-`Date.now()` rule).
- **Irreducible manual floor** (like `provjet`): a few behaviors need a real,
  focused TUI — `FileChangedShell` on focus-gain, native-watcher latency, live
  terminal/status render. These get a short manual checklist, not headless
  coverage.

## 12. Open questions (non-blocking, decide at implementation time)

1. **Which pure-Lua ed25519 / XChaCha20-Poly1305 implementation to vendor** — pick
   a known, readable existing implementation and pin it; do not write crypto from
   scratch. Verified against the conformance suite regardless.
2. **Test harness:** `plenary.nvim` busted-style vs standalone `busted` +
   `nlua`/`luv`. Affects CI shape.
3. **Neovim version floor** — pin to the lowest version with stable `vim.uv`,
   `nvim_buf_attach` `on_lines`, and `FileChangedShell` guarantees (≈0.10).
4. **Plugin / producer id string** (`recorder.extension_id`), stable forever.
5. **Terminal & git parity depth** on the first pass vs deferred to a follow-up,
   given how much of it needs a live TUI to verify.
