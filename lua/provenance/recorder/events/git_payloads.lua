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
--- ## Branch names are VALUES at a fixed ASCII key, never keys
---
--- This port's JCS sorts object keys BYTEWISE, which only matches JS/Kotlin's
--- UTF-16 code-unit order for ASCII (see core/json.lua). `branch` and the shas
--- are therefore string VALUES under the fixed ASCII keys `branch`/`sha`/
--- `parents` — so a branch named with non-ASCII characters can never reorder a
--- signed payload or make the three recorders disagree on bytes.
local json = require("provenance.core.json")

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
--- @return table {kind="git.event", data={operation, commit_sha?, sha?, parents?, branch?}}
function M.build_git_event(operation, commit_sha, view, branch)
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

  return {
    kind = "git.event",
    data = data,
  }
end

return M
