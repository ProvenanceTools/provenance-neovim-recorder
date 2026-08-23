# Path scope — Neovim recorder port

**Repo:** `provenance-neovim-recorder` (provnvim, Lua), branch `feat/manifest-2.0-trust-chain`
**Date:** 2026-08-22
**Status:** Approved design, in implementation.
**Binding authority:** the monorepo spec, `provenance/docs/superpowers/specs/2026-08-22-path-scope-design.md`. Where that spec and this document disagree about BEHAVIOUR, the monorepo spec wins. This document exists only to say how that behaviour is achieved in Lua and in Neovim, and to record the four places where the mechanics genuinely differ.
**Sibling ports:** VS Code (`provenance/packages/recorder`, shipped), JetBrains (`provenance-jetbrains-recorder`, in flight).

---

## 0. Why this port is urgent

`ignore` and `attachments` are now **required** fields in the Manifest 2.0 signed payload. A manifest signed with the current tooling canonicalizes to bytes this recorder does not reproduce, so its signature fails here and the recorder never activates. The monorepo is ahead of this repo on a signed format contract; until this lands, provnvim is broken against every newly-signed 2.0 manifest.

## 1. What is being ported

Three additions to the course-signed manifest:

- `files_under_review` may now name a **folder** (`src/`) or a **filename suffix** (`*.java`), not only exact paths.
- `ignore` — files the recorder never captures.
- `attachments` — files sealed into the bundle and hashed, but never captured.

Plus the recorder-side consequences: live scope membership, a memory cap with disclosure, a workspace walk at seal time, and two additive-optional bundle-manifest fields.

## 2. The invariants — inherited, not re-derived

These cost four fix rounds in the monorepo (`provenance/.superpowers/sdd/2026-08-22-path-scope/task-7-report.md`). They are not open for rediscovery here.

1. **`missing` is reachable from exactly ONE condition: `ENOENT`.** Never from a read failure, a containment rejection, `EISDIR`, or a non-regular file. A `submission_files` record with `status = "missing"` is shown to staff as *"File listed in files_under_review but absent on disk at seal time"* and is used in academic-integrity proceedings. Emitting one about a file the student actually submitted is the worst failure this system can produce.
2. **Only an EXACT track entry may mint a `missing` record.** A rule entry asserts nothing about any particular file existing. A course writing `*.java` must not generate a finding for every `.java` file the student never wrote.
3. Containment rejection, unreadable file, unreadable directory, non-regular file, and duplicate-drop each **DROP** the entry and raise their own warning flag — never a `missing`.
4. Hard-excluded directories are pruned by **segment name** (`.git`, `.provenance`), not root-anchored, and each seal's exact-entry loop applies the same check against the manifest string directly, because that loop never passes through the walk's pruning.
5. **`scope_capped` is emitted only when true.** An absent key and a `false` value canonicalize differently and therefore sign differently.

## 3. The matcher — `lua/provenance/core/path_scope.lua`

A direct port of `packages/log-core/src/path-scope.ts`. Byte-exact, case-sensitive, no separator normalization, no `.` resolution, no case folding.

```
matches_scope_entry(path, entry):
  entry ends with "/"    -> path starts with entry
  entry starts with "*"  -> path ends with entry:sub(2)
  otherwise              -> path == entry
```

Precedence (`resolve_path_role`), first match wins: hard-exclude > `ignore` > `attachments` > `files_under_review` > unscoped.

`validate_scope_entry` runs at manifest **parse** time and rejects the manifest. The check ORDER is load-bearing: entries violating more than one rule are pinned by the vector file to one specific problem kind.

**Lua hazard, called out because it is the one way this port silently diverges.** Lua patterns treat `.`, `[`, `]`, `%`, `*`, `-`, `?`, `+`, `(`, `)`, `^`, `$` as metacharacters. Every containment test here uses `string.find(s, needle, 1, true)` (plain mode) or explicit prefix/suffix slicing. The vector file contains `a[0-9].java` and `{a,b}.java` precisely because a pattern-based forbidden-character check gets them wrong.

### 3.1 The conformance gate

`tools/path-scope-vectors.json` in the monorepo is copied **verbatim** to `tests/conformance/fixtures/path-scope-vectors.json` and driven by `tests/conformance/path_scope_spec.lua`. Unlike the other fixtures in that directory, it is **not** produced by `tools/export-conformance-vectors.ts` — it is hand-maintained in the monorepo. It is re-copied, never edited locally. If this port disagrees with a vector, the port is wrong.

The suite asserts each array's COUNT before iterating, so a truncated or mis-decoded fixture cannot make a loop vacuously pass. `vim.json.decode` turns JSON `null` into `vim.NIL`, and a `nil`-valued key vanishes from a Lua table, so the `problem: null` cases are handled explicitly.

## 4. Where Neovim genuinely differs

### 4.1 The watcher — `fs_event` for discovery, `fs_poll` for change detection

This is the deviation that needed the most thought, and the one §4.2 of the monorepo spec exists to guard.

Today `watch/fs_watcher.lua` opens one `uv.new_fs_poll()` handle per exact `files_under_review` entry — one handle per **named file**. A folder or suffix rule has no file to poll.

Two options were rejected:

- **A timer that re-walks the workspace on the poll interval (1000ms).** Rejected on measurement, not taste: task 13 measured the workspace walk at ~140ms over a 48k-file tree. At 1s cadence that is a permanently pegged core — worse than the rolling-seal case the monorepo put a 60s floor on.
- **No external-change detection for rule entries in v1.** Rejected: it silently drops a capability the spec grants, and the gap would be invisible to staff.

**What we do instead.** One non-recursive `uv.new_fs_event()` handle per **directory** in the walked tree, as the coarse pre-filter. It answers exactly one question — "a name appeared or changed in this directory" — and on a directory-creation event a handle is opened for the new directory too.

Non-recursive, one-per-directory, deliberately: libuv's `UV_FS_EVENT_RECURSIVE` is supported on macOS and Windows but **not on Linux** (inotify is not recursive). Watching per-directory works identically on all three platforms with no branch, so there is no platform-specific code path that only one developer's machine ever exercises.

`fs_event` is used **only for discovery**. When it reports a path that `resolve_path_role` puts at `reviewed`, that path gets an ordinary `uv.new_fs_poll()` handle, exactly like an exact entry, and all modify/delete detection continues to run through the existing deterministic `handle_path_event(rel, abs_path)`. This is not incidental: `fs_watcher.lua`'s own docstring records why this repo chose `fs_poll` over `fs_event` in the first place — `fs_event` backends miss rename-into-place atomic writes, which is a common editor save pattern. Routing rule-matched files through `fs_event` alone would make them *less* reliably watched than exact entries. Discovery is the one thing `fs_event` is better at, and it is the only job it gets.

Exact entries keep their existing per-file `fs_poll` unchanged, so 1.x and exact-2.0 behaviour is byte-identical to today.

**The non-negotiable rule (spec §4.2).** `fs_event` is a coarse pre-filter and nothing more. Every path it delivers is re-checked through `resolve_path_role` before any event is emitted. Neovim's autocmd patterns, `vim.fs` matching, and libuv's own filtering are **not** the matcher; `path_scope.lua` is. A port that emits on its watcher's verdict alone is a silent conformance failure — the same manifest would watch different files on different editors, which is the entire divergence risk the vector file exists to prevent.

Handle count is bounded by consulting `registry.is_watched(rel)` before opening a poll handle, which is also what flips the cap (§4.2 below).

### 4.2 The memory cap

`EXPECTED_CONTENT_MAX_FILES = 512`, `FILE_SCOPE_MAX_ENTRIES = 4096`. Both are **writer-contract constants**: all three recorders must use the same numbers or two ports disagree about when a session is capped. Neither may be changed here.

`expected_content_registry.lua` stops taking a path list and starts taking a resolved scope. `is_watched` stops being a set lookup and becomes a `resolve_path_role` evaluation, with the deliberate side effect that a path which *would* have been admitted but for the cap flips `cap_hit`. That is the only moment the cap is observable. A path that was never in scope does not set it — the cap did not cost us that file.

### 4.3 The seal has to grow a workspace walk

`commands/seal.lua` and `io/rolling_seal_writer.lua` do not walk the filesystem at all today; both read straight off `files_under_review`. A `src/` entry would seal nothing. Both gain the shared walk, in one new module used by both — two copies of a walk that must agree about hard exclusions is exactly the divergence this feature exists to avoid.

### 4.4 `scope_capped` is ORed across every packed session

Not optional, and not the live session's bit alone. A bundle whose earlier session capped and whose last session did not would report the key **absent**, so an analyzer trusts tier 1 and concludes "in scope, no activity" about a student who did nothing wrong — the exact R2 hole the monorepo's final review found and closed.

`seal.lua` already scans sibling rolling seals (`manifest-<session_id>.json`) for its orphan guard, so the machinery exists. Two sub-rules, both kept exactly:

- Only seals for sessions the bundle actually **packs** are consulted. A seal naming a session that is not here describes a recording this bundle makes no claim about.
- A session with **no** rolling seal contributes an **absent** report, never a `false` one — that is the field's own "absence means this recorder does not report" contract, and it is the honest answer: we cannot recover a bit nobody wrote down. A malformed or unreadable seal never mints `true`.

## 5. Deliberately unchanged

- **`doc_wiring.lua` is not gated on `ignore`.** The monorepo does not gate `doc.*` emission on scope membership — `is_watched` there governs only expected-content bookkeeping — and provnvim already behaves the same way. There is a known open discrepancy between that behaviour and spec §3.4's *"invisible to the recorder entirely"*; it is being decided for all three recorders together. Until it is, this port mirrors the monorepo exactly. A uniform documented gap across three recorders is recoverable; three recorders disagreeing about whether ignored files are recorded is not.
- **The 1.x branch of `signed_payload`.** Untouched, byte-for-byte. Archived 1.x signatures must keep verifying. At 1.x the new entry forms do not exist and are **not** an error: an entry ending in `/` means a file literally named `src/`, which matches nothing — exactly today's behaviour. 1.x parsing never rejects.
- **`format_version` is not bumped.** `role` and `scope_capped` are additive-optional on the bundle manifest, following the existing `final?` precedent.

## 6. Known cross-repo consequences

- **`extension_hash` moves.** It is a tree-hash of the whole `lua/` directory, so every new source file changes it. The monorepo's `known-good-extension-hashes.json` needs `npm run update-hashes` against a fresh provnvim build. Out of this repo; tracked by the program.
- **JCS and non-ASCII array values.** `json.lua`'s `escape_string` is shared by object keys and every string value including array elements; `table.sort` is called only in `canon_object`, never in `canon_array`. So `ignore` / `attachments` / `files_under_review` are array **values**, never keys, and the bytewise-vs-UTF-16 key-sort constraint documented in `course_cert.ts` / `manifest.ts` / `policy.ts` does not bind them. A non-ASCII path canonicalizes identically in Lua, Kotlin and TypeScript. One pre-existing residual, not specific to this feature and not acted on here: a string containing an **unpaired surrogate** (invalid UTF-8) would diverge — ES2019 well-formed `JSON.stringify` emits `\udXXX` escapes, this canonicalizer emits the raw bytes. That applies to every string value in the format today.
