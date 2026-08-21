--- Pure payload builder for git events.
--- No Neovim API — simple {kind, data} constructor.
---
--- ## The commit graph (program spec S5)
---
--- `git.event` used to be exactly `{operation, commit_sha?}`. It now also
--- carries the shape of the history around HEAD: `sha`, `parents[]`, `branch`.
---
--- WHY THE GRAPH IS RECORDED RATHER THAN SHIPPED: Gradescope delivers the
--- working tree only, never `.git` — and a `.git` that did travel would prove
--- less than it looks like it does, because `commit --amend`, `rebase` and
--- `filter-branch` all rewrite history after the fact. A repository handed in is
--- evidence of what a student ENDED UP WITH, not of what happened. The recorder
--- sits on the live repo while the work is being done, so capturing the graph
--- here puts it inside the signed hash chain at the instant it existed, where it
--- can no longer be rewritten.
---
--- ## NO GIT AUTHOR IDENTITY. EVER.
---
--- There is deliberately no author name, no author email, no author date and no
--- commit message here — nor anywhere else in the log. This is a PROTOCOL
--- constraint, not a style preference: the approved CPHS protocol (2026-06-19796)
--- treats a new category of identifier as requiring a filed modification BEFORE
--- implementation, and a real name plus a real email address attached to every
--- commit is exactly that. `sha`, `parents` and `branch` are structural — they
--- describe the SHAPE of the history, not who produced it. Attribution already
--- has a designed, opaque home: the `student_ref` UUID inside
--- `session.start.identity`.
---
--- It is enforced STRUCTURALLY, not by discipline. `M.commit_view` is the only
--- path from a git read into a payload, and it takes exactly two positional
--- scalars (`sha`, `parents`) — there is no parameter through which an author
--- field could be passed in at all. `M.build_git_event` then reads named fields
--- off the view rather than merging it, so extra keys on a table handed in where
--- a view is expected cannot survive either. Widening the capture would mean
--- widening `commit_view`'s signature: a visible, reviewable change rather than
--- one more line in a payload builder.
---
--- ## Three things this port has to get right (each pinned by a vector in
--- `tests/conformance/fixtures/git-event.json`)
---
--- 1. **`commit_sha` is still emitted alongside `sha`.** Same value, two keys:
---    1.x readers only know `commit_sha`, and 1.x support is permanent (program
---    spec §9). Every new field stays optional forever, so a pre-S5
---    `{operation, commit_sha}` payload keeps building and chaining unchanged.
--- 2. **`parents` order is never touched.** JCS sorts object KEYS but leaves
---    array ELEMENTS alone, and `parents[1]` is the branch that was merged INTO
---    — so sorting or normalizing the list changes both the meaning of a merge
---    and the chain hash. Nothing here sorts it.
--- 3. **An empty `parents` list is not an absent one.** `[]` is a positive claim
---    ("this commit genuinely has no parents" — a root commit); ABSENT means
---    "the recorder could not read them". A read failure is not entitled to make
---    the former claim, so an unknown parent list omits the key entirely. That is
---    also why `parents` is explicitly tagged with `json.array`: an untagged
---    empty Lua table canonicalizes as `{}`, not `[]`.
---
--- ## THE REPOSITORY DISCRIMINATOR — `root_commit_sha` (decision D12)
---
--- A scope can observe more than one repository: a submodule, or a repository
--- nested inside the one that owns the assignment root. Their sha spaces are
--- unrelated, so a reader that keys observed commits by sha alone merges two
--- graphs that have nothing to do with each other. `root_commit_sha` is what
--- lets the reader key on `(repository, sha)` for real.
---
--- The value is the root of HEAD's FIRST-PARENT lineage, derived ONCE per
--- repository at git-wiring setup — see `recorder/wiring/root_commit_sha.lua`
--- for the derivation and `wiring/git_wiring.lua` for the memoization. It was
--- chosen because BOTH PARTNERS DERIVE THE SAME VALUE OFFLINE, which is the
--- only thing that makes cross-contributor correlation possible; a discriminator
--- two partners disagree about correlates nothing.
---
--- Four rules bind this builder, all pinned by
--- `tests/conformance/fixtures/git-event.json`:
---
--- 1. **OMIT, never `null`.** Omission and `null` canonicalize differently and
---    therefore chain to different hashes, exactly as `parents: []` and an
---    absent `parents` do. ABSENT is a legal, permanent, blameless answer — a
---    shallow clone has no reachable root commit and every bundle recorded
---    before D12 has no such field — so the absent case must stay byte-identical
---    to the pre-D12 world.
--- 2. **The value is validated through log-core's own reader**
---    (`core/git_event.read_repository_discriminator`), never a regex restated
---    on this side. A path, a remote URL, an abbreviated sha, an uppercased sha
---    and the empty string are all rejected and the key omitted. Rejecting costs
---    only correlation; letting a path through would put an identifier in a
---    staff-facing UI (S14(b)).
--- 3. **One value per repository OBSERVED.** A session that sees a submodule as
---    well as its outer repository labels each event with its OWN repository's
---    root. Labelling a submodule event with the outer root re-creates the exact
---    merge this field exists to prevent — which is why the memoization in
---    `git_wiring.lua` is keyed by repository, not per session.
--- 4. **It rides on every payload that carries a `sha`,** not only on commits:
---    an unlabelled observation does not correlate even when its neighbours in
---    the same session do. A payload naming no commit gets no discriminator,
---    because there is nothing for a repository key to key.
---
--- Like every other field here, it is a repository identifier and NOTHING else:
--- never the repository path, never a remote URL, and it reaches no author.
---
--- ## Branch names are VALUES at a fixed ASCII key, never keys
---
--- This port's JCS sorts object keys BYTEWISE, which only matches JS/Kotlin's
--- UTF-16 code-unit order for ASCII (see core/json.lua). `branch` and the shas
--- are therefore string VALUES under the fixed ASCII keys `branch`/`sha`/
--- `parents` — so a branch named with non-ASCII characters can never reorder a
--- signed payload or make the three recorders disagree on bytes.
local json = require("provenance.core.json")
local git_event = require("provenance.core.git_event")

local M = {}

--- The ONLY view of a git commit this plugin is allowed to hold (program spec S5).
---
--- Takes exactly two positional scalars, so author name / author email / author
--- date / commit message are UNREACHABLE rather than merely unused. See the
--- module docstring: widening this signature is out of protocol.
---
--- @param sha string|nil        the commit's object id, or nil if unreadable
--- @param parents string[]|nil  parent object ids in GIT'S OWN ORDER (the first
---   parent is the branch merged into). nil means "could not read", which is NOT
---   the same as `{}` ("root commit"). A list containing anything that is not a
---   string is treated as unreadable in full rather than filtered down, because
---   the LENGTH of this list is the structure (0 = root, 1 = ordinary, 2+ =
---   merge) — a partial list is a WRONG claim about the graph, not a partial one.
--- @return table view { sha = string|nil, parents = string[]|nil }
function M.commit_view(sha, parents)
  local view = {}

  if type(sha) == "string" then
    view.sha = sha
  end

  if type(parents) == "table" then
    local copied = {}
    local all_strings = true
    for i = 1, #parents do
      if type(parents[i]) ~= "string" then
        all_strings = false
        break
      end
      copied[i] = parents[i]
    end
    if all_strings then
      view.parents = copied
    end
  end

  return view
end

--- Build a git.event payload.
---
--- @param operation string — e.g. "commit", "state_change", "checkout"
--- @param commit_sha string|nil — omit the key when nil (the 1.x-compatible field)
--- @param view table|nil — an `M.commit_view`; nil when there is no commit to
---   describe. Only `.sha` and `.parents` are ever read off it.
--- @param branch string|nil — current branch. ABSENT on detached HEAD; never
---   invented, because an omitted branch and a branch literally named "HEAD"
---   are different claims.
--- @param root_commit_sha string|nil — the REPOSITORY DISCRIMINATOR (D12). See
---   the D12 block in the module docstring. OMITTED, never `null`, and dropped
---   entirely unless it passes log-core's own reader AND there is a commit for
---   it to label.
--- @return table {kind="git.event", data={operation, commit_sha?, sha?, parents?, branch?, root_commit_sha?}}
function M.build_git_event(operation, commit_sha, view, branch, root_commit_sha)
  local data = {
    operation = operation,
  }
  if commit_sha ~= nil then
    data.commit_sha = commit_sha
  end

  if type(view) == "table" then
    -- Named field reads, NEVER a table merge: a table handed in here that also
    -- carries author fields contributes nothing beyond these two.
    if view.sha ~= nil then
      data.sha = view.sha
    end
    if view.parents ~= nil then
      -- Copied so a caller cannot mutate an already-emitted payload, and TAGGED
      -- so an empty list canonicalizes as `[]` and not `{}`. Order is preserved
      -- exactly — see rule 2 in the module docstring.
      local parents = {}
      for i = 1, #view.parents do
        parents[i] = view.parents[i]
      end
      data.parents = json.array(parents)
    end
  end

  if branch ~= nil then
    data.branch = branch
  end

  -- THE REPOSITORY DISCRIMINATOR (D12). Three gates, in this order:
  --
  --  1. There must be a commit for it to label. Rule 10 says the field rides on
  --     every `git.event` that carries a `sha` — not only on commits, because
  --     an unlabelled observation does not correlate even when its neighbours
  --     in the same session do — but an `operation_only` payload names no
  --     commit at all, so there is nothing for a repository key to key.
  --
  --  2. It must pass LOG-CORE'S OWN READER, not a regex copied to this side of
  --     the contract. A writer that shape-checks with its own copy of the rule
  --     can emit a value its reader rejects; a writer that runs the reader
  --     cannot. This is the one place a repository PATH or a remote URL is
  --     stopped (S14(b)) — and running it here means such a value is never
  --     written down at all, rather than written and later declined.
  --
  --  3. OMIT, never `null`. Omission and `null` canonicalize differently and
  --     therefore chain to different hashes, exactly as `parents: []` and an
  --     absent `parents` do. Readers accept `null` as absence so a nonconforming
  --     log still parses; a writer that emits it is nonconforming. Note this
  --     branch is also what makes `json.NULL` handed in here an OMISSION: the
  --     reader answers `absent` for it, which is not `recorded`.
  if
    (data.sha ~= nil or data.commit_sha ~= nil)
    and git_event.is_usable_discriminator(root_commit_sha)
  then
    data[git_event.REPOSITORY_DISCRIMINATOR_FIELD] = root_commit_sha
  end

  return {
    kind = "git.event",
    data = data,
  }
end

return M
