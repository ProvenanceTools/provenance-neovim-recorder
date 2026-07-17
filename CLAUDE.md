# CLAUDE.md

Project conventions and standing instructions for Claude Code working in this repo. Read this fully before doing anything.

## What this is

**provenance-neovim-recorder** (`provnvim`): a Neovim plugin (Lua) that records a tamper-evident `.provenance` log while a student works on an assignment, producing a sealed submission bundle that is **byte-for-byte format-compatible** with the one the VS Code recorder produces. It ships under the same **Provenance Recorder** name as the VS Code and JetBrains recorders.

This is a **port of the wiring, not a new product.** The event format, hash chain, JCS canonicalization, ed25519 signing, bundle/manifest shapes, signed checkpoints, and per-session keypair all already exist in the [Provenance monorepo](https://github.com/ProvenanceTools/provenance)'s `packages/log-core` (pure TypeScript). This repo:

1. Reimplements that format in Lua (`lua/provenance/core/`), and
2. Re-derives the editor-specific signal detection against the Neovim API (`lua/provenance/recorder/`).

The Provenance analyzer and server do not care which editor produced a bundle — only that it validates: hash chain intact, manifest signature verifies, `extension_hash` on the allowlist.

The full approved design is in `docs/design.md`. **Read it before implementing anything.** The recorder product spec is the monorepo's `docs/prd.md` (recorder PRD); section references like "§4.3" mean the recorder PRD.

## The Provenance format contract (do not redesign it)

The log file format is owned by the Provenance monorepo's `log-core`. This repo is a **third implementation of the same contract** (after `provcode` and `provjet`), not an author of it. Treat the format as fixed:

- **The event envelope, hash chain, and JCS canonicalization are pinned by test vectors** in `log-core`'s `hash-chain.test.ts`. This repo's Lua implementation must reproduce them byte-for-byte.
- **Parity is enforced by golden conformance vectors** exported from `log-core` and checked in `tests/conformance/`. If the conformance suite fails, the implementation is wrong — never "fix" it by changing the vectors.
- **JCS canonicalization** is ported to Lua. Lua numbers are IEEE-754 doubles like JS, so number formatting is a close match — but whitespace, key ordering, and number representation all still matter, and are pinned by vectors. Do not eyeball it; run the vectors.
- **Never modify `manifest.json` / `manifest.sig` after seal.** They are signed; the stored bundle must stay signature/chain verifiable.
- **Producer identity:** set `session.start.recorder.extension_id` to this plugin's id. This is how the analyzer distinguishes hosts — no format change needed.
- **The `session.start.vscode` field:** the format hard-codes a `vscode: { version, commit, platform }` object. Fill it with editor-generic values (`version` = Neovim version, `commit` = `''`, `platform` = OS). Do **not** rename or generalize this field — that would be an approval-gated format change in the monorepo. See `docs/design.md` §6.

**If the format appears to require a change to accommodate Neovim, STOP and ask.** A format change is a cross-repo, signed-contract, test-vector-pinned decision owned by the Provenance monorepo — never made unilaterally here to make an implementation easier.

## The crypto/runtime keystone (do not swap it silently)

The keystone decision for this port is **pure-Lua, vendored, zero native dependencies** (`docs/design.md` §3):

- **SHA-256** via `vim.fn.sha256` (Neovim builtin). **ed25519** and **XChaCha20-Poly1305** are vendored pure-Lua implementations. **File I/O** is `vim.uv` (libuv). No FFI, no libsodium, no sidecar binary.
- **Do not introduce a native dependency** (FFI-to-libsodium, a compiled helper) to "make crypto easier." That reintroduces the per-platform distribution fragility this design deliberately avoids, and undercuts the auditability the recorder is required to keep (PRD §6). If you think the pure-Lua path is genuinely unworkable somewhere, stop and ask — it is a keystone decision, not an implementation detail.
- **Do not write crypto from scratch.** Vendor a known, readable existing pure-Lua implementation and pin it. Correctness is proven against the conformance suite regardless.
- **Vendoring is a licensing gate.** A Neovim plugin is distributed as its own source tree, so anything vendored is redistributed by us. In the *same commit* that vendors a component, create/update `THIRD-PARTY-NOTICES.txt` at the repo root with that component's upstream project, vendored path, version/commit, and full license + copyright text. Prefer permissive licenses (MIT/BSD/Apache-2.0/CC0/Unlicense); copyleft needs review first. No `THIRD-PARTY-NOTICES.txt` entry → do not vendor.
- Signing is infrequent (session start / every-100-entries checkpoint / seal); the per-keystroke path only hashes. Keep it that way — never move a signing operation into the edit firehose.

## Working agreement

- **Stop and ask on ambiguity.** If a decision isn't covered by `docs/design.md`, the recorder PRD, or this file, do not invent an answer. Inventing architecture is the single biggest failure mode.
- **Stay in scope.** Touch only the files the current task requires. Do not opportunistically refactor. If you notice something that should change, mention it; don't change it.
- **No new dependencies without asking.** Every vendored library or plugin dependency is a decision. Propose, justify, wait for approval. The approved set is: Neovim's own runtime (`vim.uv`, `vim.fn.sha256`, `nvim_buf_attach`, autocmds), a vendored pure-Lua ed25519 + XChaCha20-Poly1305, and a test harness (`plenary.nvim` or standalone `busted` — to be pinned at implementation time).
- **No silent constraint softening.** If a conformance test fails and the obvious fix is to weaken the assertion or edit a vector, stop and explain. The vectors encode the format contract; loosening them is not a coding decision.
- **Read before writing.** Before editing any file, read it. Before editing any module, read its tests.
- **Small diffs.** A change touching more than ~200 lines across more than ~5 files is probably two changes. Split it.

## Architecture rules

- **`lua/provenance/core/` is a pure-Lua port of the log format.** No Neovim editor APIs beyond the runtime primitives it is allowed (`vim.fn.sha256`, `vim.uv` for I/O). It knows about events, hashing, canonicalization, signing, bundles, and the source tree-hash — nothing about editing, buffers, or autocmds. This mirrors `log-core`'s zero-editor-dependency rule and keeps the conformance surface testable in isolation.
- **`lua/provenance/recorder/` is the plugin: the Neovim wiring around `core/`.** Activation, buffer/autocmd/paste/external-change/terminal/git listeners, the session host, the status indicator, the seal command. It depends on `core/` and the Neovim API.
- **`tests/conformance/` proves format parity** against golden vectors exported from the monorepo. It is the gate: a bundle this plugin seals must be accepted by the *real* Provenance analyzer/server.
- Events are **append-only**. There is no update or delete on a log, anywhere.
- The hash chain is the foundation of integrity. Exactly one chaining function; all log-producing paths go through it (mirrors `log-core`).
- **This repo never changes the Provenance monorepo** except one small, additive thing (see `docs/design.md` §8): adding this release's source tree-hash to the `known-good-extension-hashes.json` allowlist (and teaching `update-hashes` about the third producer). The golden-vector export script already exists — `provjet` added it — and is consumed unchanged.

## Neovim wiring — things that are easy to get wrong here

The format port is the low-risk part. The wiring is ~70% of the work and where the real ambiguity lives (`docs/design.md` §5). VS Code's APIs and Neovim's have **different semantics** — do not assume a 1:1 mapping.

- **External-change detection (§4.5) is the highest-risk item.** Neovim's awareness of on-disk changes is *lazy*: `FileChangedShell` fires on focus-gain or an explicit `:checktime`, not the moment the file changes. The expected-content model is the source of truth; the on-disk hash is what you compare against — and getting the direction wrong is easy, made worse by *when* Neovim learns a file changed. Drive it with `autoread` + `:checktime` in tests.
- **Paste detection (§4.3) is three signals combined** — bracketed paste / `vim.paste()`, the resulting `on_lines` edit burst, and clipboard register content (`+`/`*`). Neovim has no single paste-command surface. Reconcile to exactly one event per paste; do not simplify to one signal without discussion.
- **Git wiring degrades gracefully.** Git may be absent, or exposed only via a third-party plugin. Missing git integration is a degraded signal, not a crash.
- **Activation is scoped and privacy-preserving.** Record only inside an activated assignment workspace whose `.provenance-manifest` verifies against the embedded course public key (§4.1). Drop events for files outside the workspace. Never record a student's user-level config (`init.lua`, `~/.config/nvim`) or out-of-workspace scratch buffers.
- **Atomic writes.** Write-temp-then-rename via `vim.uv`. Never partial-write the live log file.
- **Clock handling.** Monotonic clock (`vim.uv.hrtime()`) for `t` (relative to session start); wall clock for `wall`, formatted to the fixed-width millisecond ISO string. Don't conflate. (Note: `provjet` shipped a real bug here — a wall-clock formatter that dropped millis when zero broke the analyzer's monotonic-wall check. Format wall times to fixed width.)
- **The edit firehose.** `on_lines` fires rapidly on every keystroke; the callback must be fast and the writer must buffer. Keep per-event handler work minimal and never sign or canonicalize on the hot path.

## Testing

- **Conformance suite** for cross-language format parity — the non-negotiable gate.
- **Wiring unit tests** run headless (`nvim --headless`) with a Lua harness, mocking the Neovim API at the seam. Test the event→log-entry transform as a pure function, separately from the editor wiring (mirrors the monorepo).
- **Determinism.** Inject clocks. No `os.time()` / `vim.uv.hrtime()` / `math.random()` in assertions.
- Every PR-sized change ships with tests. New behavior gets new tests; bug fixes get a regression test that fails before the fix.
- A few behaviors need a real, focused TUI (`FileChangedShell` on focus, native-watcher latency, live terminal/status render). These get a short manual checklist, not headless coverage.

## Code style

- Lua, idiomatic for Neovim plugins. Prefer small, single-purpose modules returning a table. Pure functions over stateful modules when there's no state to own — hashing/canonicalization are pure; the session writer owns a file handle, so it is a stateful module with an explicit `close()`.
- Use a tagged-table discriminated-union convention for event types (a `type` field + a shape per type), the Lua analogue of `log-core`'s discriminated unions.
- No background task without an explicit teardown path. Every autocmd group, `buf_attach`, timer, and job has a `dispose()` / plugin-teardown hook.
- Errors are values when expected (return `ok, value_or_err`), raised only when unexpected. Never swallow.
- `local`-scope everything; no accidental globals. One require-able entry module.

## Conventions for talking to me

- When you finish a task, summarize what you did, what you didn't do, and what you noticed but didn't change.
- If you make a non-obvious choice, explain it in the response — don't bury it in a comment.
- If you vendored a dependency you weren't told to, or skipped a test you couldn't get to pass, lead with it.
- "Done" means: tests pass (including conformance), it loads in headless Neovim, the diff is reviewable. Not "I wrote some code."

## Git commits

- Conventional-commit prefixes (`feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `style`).
- Commit with `git commit --no-gpg-sign`. Do **not** add a `Co-Authored-By: Claude` trailer or any Claude attribution.
- Always stage/commit with an explicit pathspec — the tree may contain unrelated in-progress work.
- Commit incrementally during multi-phase work.

## When in doubt

Re-read `docs/design.md`, re-read the recorder PRD section, re-read this file, and ask. The format is a contract owned elsewhere; the crypto path is a keystone decision; the wiring is full of non-obvious Neovim semantics. The cost of a clarifying question is five minutes.
