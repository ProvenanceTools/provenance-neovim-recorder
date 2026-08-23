# Path scope — provnvim implementation plan

**Spec:** [`../specs/2026-08-22-path-scope-provnvim.md`](../specs/2026-08-22-path-scope-provnvim.md)
**Binding behaviour spec:** `provenance/docs/superpowers/specs/2026-08-22-path-scope-design.md`
**Conformance gate:** `provenance/tools/path-scope-vectors.json`

## Global constraints

- Byte-compatible behaviour with the TypeScript implementation. Idiomatic Lua is how you get there, not an excuse to differ.
- The five invariants in spec §2 are inherited, not re-derived. Any change that could mint a false `missing` is a stop-and-escalate.
- `EXPECTED_CONTENT_MAX_FILES = 512` and `FILE_SCOPE_MAX_ENTRIES = 4096` are writer-contract constants shared with two other recorders. Do not change either.
- If a test fails and the obvious fix is weakening an assertion: **stop and escalate.** Tests encode requirements.
- Never `git stash`, never `git clean` — the tree may carry parallel work.
- Commits: `git commit --no-gpg-sign`, conventional prefix, explicit pathspec after `--`, no `Co-Authored-By` trailer.
- Verify with `make test` (headless Neovim + plenary). Report observed counts; never a status you did not run.

## Tasks

| # | Task | Files | Depends on |
| --- | --- | --- | --- |
| A | The matcher + cross-port conformance vectors | `core/path_scope.lua`, `tests/conformance/fixtures/path-scope-vectors.json`, `tests/conformance/path_scope_spec.lua`, `tests/core/path_scope_spec.lua` | — |
| B | Manifest 2.0 gains `ignore` and `attachments` | `core/manifest.lua`, its tests, `tests/conformance/fixtures/manifest-v2.json` | A, and the regenerated fixture from the monorepo |
| C | Bundle manifest gains `role` and `scope_capped` | `core/bundle.lua`, `core/rolling_manifest.lua`, their tests | — |
| D | The shared workspace walk and file read | `recorder/io/workspace_walk.lua`, `recorder/io/workspace_file_read.lua` + tests | A |
| E | Live scope membership, the cap, and the watcher | `recorder/state/expected_content_registry.lua`, `recorder/session/recorder_context.lua`, `recorder/watch/fs_watcher.lua` + tests | A, D |
| F | Both seals learn the scope | `recorder/commands/seal.lua`, `recorder/io/rolling_seal_writer.lua`, call sites + tests | A, C, D, E |

### Task B is BLOCKED on the monorepo

`tests/conformance/fixtures/manifest-v2.json` is stale: its 2.0 signed payload predates `ignore` / `attachments`. It is a **generated** fixture — the monorepo's `tools/export-conformance-vectors.ts` produces it and this repo never hand-edits it. The generator itself was found to be stale (nothing validated that its emitted 2.0 manifests still parse); a fix is in flight in the monorepo and the regenerated file will be handed over. Hand-authoring the two keys locally is the one option that must not be taken: provjet and provnvim would independently author *different* bytes, which is exactly the divergence the vector files exist to prevent.

### Task D — what the two new modules must reproduce

`workspace_walk.lua`:
- Every file under the root as workspace-relative forward-slash paths.
- Hard-excluded directories pruned at the **directory** level by **segment name** (`.git`, `.provenance`), so a nested submodule `.git/` or a sibling assignment's `.provenance/` is pruned wherever it appears — not only at the root. Export `has_hard_excluded_segment(rel)` alongside, because each seal's exact-entry loop reads a manifest string directly and never passes through this pruning.
- Symlinks are **not followed** (cycle safety, workspace-escape safety) but each declined in-scope link is **reported**, so the caller can disclose the drop rather than let a file vanish from the bundle without a trace.
- A directory that cannot be listed is not silently treated as empty; it bubbles up so the caller can warn.

`workspace_file_read.lua`: one path's on-disk state as `present` / `missing` / `unreadable` / `out_of_workspace`.
- `missing` **only** from `ENOENT`. Every other errno, a non-regular file, and a directory-where-a-file-was-expected are `unreadable`.
- Containment fails **closed** and resolves symlinks on **both** sides, then classifies an unresolvable path by the carried errno exactly as the read itself would have.
- `out_of_workspace` is its own outcome, never folded into `missing`. The common way to reach it is not an attack — a student's `ln -s ~/shared/data.csv data.csv`.

### Task F — the two-loop shape both seals share

1. Walk the workspace; role-resolve each path; keep `reviewed` and `attachment`. Record every path **sighted**, before attempting the read — a file the walk saw but could not re-open must not fall through to loop 2 and mint a false `missing`. Anything not `present` is **dropped** with a warning, never recorded.
2. For each `scope.track` entry that `is_exact_entry`, is not hard-excluded by segment, and was not sighted: read it directly. Only this loop may mint `missing`, and only on that entry's own `ENOENT`.

Plus: `scope_capped` spread in only when true, and ORed across every packed session's rolling seal (spec §4.4).

## Out of scope

- Gating `doc.*` emission on `ignore` (spec §5 — decided for all three recorders together).
- Any change to the 1.x signed payload.
- The monorepo's `known-good-extension-hashes.json` update (spec §6).
