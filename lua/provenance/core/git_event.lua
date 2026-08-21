--- Reading the repository discriminator off a `git.event` payload — decision
--- D12 (collaboration spec S14(b)). Lua port of log-core's `git-event.ts`.
---
--- ## Why a WRITER needs the READER
---
--- This module exists in `core/` — the log-core port — rather than beside the
--- git wiring, for the same reason `peer_observed.lua` does: the narrowing is a
--- CROSS-LANGUAGE CONTRACT with four consumers (the monorepo's analyzer and
--- server through `analysis-core`, plus the two sibling recorder repos), not a
--- private detail of one reader.
---
--- The write side (`recorder/wiring/root_commit_sha.lua`) validates through
--- THIS function rather than a private regex, exactly as provcode's
--- `root-commit-sha.ts` calls log-core's `readRepositoryDiscriminator`. A
--- writer that shape-checks with its own copy of the rule can emit a value its
--- own reader rejects; a writer that runs the reader cannot. That is not
--- theoretical tidiness — the shape check is the ONE place a nonconforming
--- writer's repository PATH or remote URL is stopped before it reaches a
--- staff-facing UI (S14(b)), so running it on the write side means such a value
--- is never written down at all.
---
--- ## What the discriminator is
---
--- The repository's ROOT-COMMIT sha, used for exactly one thing: deciding
--- whether two observed commits live in the same sha space. Node identity in
--- the observed DAG is `(repository, sha)`, and without a discriminator a scope
--- that observed a submodule alongside its outer repository merges two
--- unrelated sha spaces into one graph.
---
--- The root commit was chosen because BOTH PARTNERS DERIVE THE SAME VALUE
--- OFFLINE, which is what makes cross-contributor correlation possible at all,
--- and because a submodule has a different root commit, so it discriminates
--- correctly. It is deliberately NOT the repository path (arguably an
--- identifier, certainly noisy) and NOT a remote URL (which embeds the org and
--- frequently the student's own username).
---
--- ## Three answers, and the third is what makes the second safe
---
---  - `absent`    — no field (or an explicit `null`). The ordinary case for
---                  every bundle in existence and for a shallow clone forever.
---                  Folded into the unlabelled repository: exactly the
---                  behaviour that predates the field.
---  - `recorded`  — a usable root-commit sha; its own repository key.
---  - `malformed` — present and not a commit sha. Folded in with the
---                  unlabelled ones, and COUNTED.
---
--- `absent` and `malformed` reach the same repository and are still different
--- variants on purpose: one is a recorder with nothing to say, the other a
--- recorder that said something wrong, and only the second is worth counting.
--- **Neither is ever a finding.** A malformed discriminator is a statement
--- about the recorder that wrote it, never about the student it recorded.
---
--- ## Why the SHAPE is checked here when a commit `sha` is treated as opaque
---
--- The jobs differ. A `sha` is only ever compared for equality against other
--- recorded shas, and normalizing there could merge two genuinely distinct
--- commits. This value is a NAMESPACE KEY and a privacy boundary. Rejecting
--- what cannot be a commit sha costs only correlation — the observation still
--- lands, unlabelled.
---
--- Both git object formats are accepted: 40 hex for sha-1, 64 for sha-256.
--- Lowercase only, which is what git prints; an uppercase value is malformed
--- rather than folded, because folding it would be exactly the normalization
--- the paragraph above refuses.
---
--- Pure: no Neovim editor APIs, no I/O, total (never throws).
local json = require("provenance.core.json")

local M = {}

--- The payload key that carries the discriminator.
---
--- Named through this constant rather than restated as a string literal, so a
--- rename is one edit here rather than a silent cross-repository disagreement.
M.REPOSITORY_DISCRIMINATOR_FIELD = "root_commit_sha"

--- sha-1 (40) and sha-256 (64) object names, lowercase hex, as git prints them.
local function is_root_commit_sha(s)
  if type(s) ~= "string" then
    return false
  end
  if #s ~= 40 and #s ~= 64 then
    return false
  end
  return s:match("^[0-9a-f]+$") ~= nil
end

--- Read the repository discriminator out of an untyped `git.event` `data`.
---
--- Pure and total: never throws, never mutates. A `.slog` is a student-editable
--- file, so every input here is untrusted and a malformed one is EXPECTED
--- rather than exceptional.
---
--- `null` (both `json.NULL` and `vim.NIL`, so a payload straight out of
--- `vim.json.decode` reads the same way as one out of `core.ndjson`) is
--- accepted as absence, so a writer that spelled the unknown case explicitly
--- still READS correctly — but a **writer must OMIT the field**, never emit
--- `null`. The two canonicalize differently and therefore chain to different
--- hashes, exactly as `parents: []` and an absent `parents` do.
---
--- A payload that is not an object at all reads as `absent`: there is no field
--- on a non-object, and manufacturing a problem out of a payload this function
--- does not own would report the same garbage twice.
---
--- @param data any
--- @return table read  { kind = "absent" }
---                   | { kind = "recorded", root_commit_sha = string }
---                   | { kind = "malformed", problem = "not_a_string"|"empty"|"not_a_commit_sha" }
function M.read_repository_discriminator(data)
  if type(data) ~= "table" or json.is_array(data) or data == json.NULL then
    return { kind = "absent" }
  end

  local raw = data[M.REPOSITORY_DISCRIMINATOR_FIELD]
  if raw == nil or raw == json.NULL or raw == vim.NIL then
    return { kind = "absent" }
  end
  if type(raw) ~= "string" then
    return { kind = "malformed", problem = "not_a_string" }
  end
  if #raw == 0 then
    return { kind = "malformed", problem = "empty" }
  end
  if not is_root_commit_sha(raw) then
    return { kind = "malformed", problem = "not_a_commit_sha" }
  end
  return { kind = "recorded", root_commit_sha = raw }
end

--- True iff `value` is what every reader accepts as a repository discriminator.
---
--- Deliberately expressed by running the READER above rather than by exposing
--- the regex: one narrowing, four consumers. This is the predicate the write
--- side gates on.
--- @param value any
--- @return boolean
function M.is_usable_discriminator(value)
  return M.read_repository_discriminator({ [M.REPOSITORY_DISCRIMINATOR_FIELD] = value }).kind
    == "recorded"
end

return M
