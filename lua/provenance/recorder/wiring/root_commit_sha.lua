--- root_commit_sha.lua — THE REPOSITORY DISCRIMINATOR, write side (decision
--- D12, collaboration spec S14(b)).
---
--- A scope can observe more than one repository: a submodule, or a repository
--- nested inside the one that owns the assignment root. Their sha spaces are
--- unrelated, so a reader that keys observed commits by sha alone merges two
--- graphs that have nothing to do with each other. `git.event.root_commit_sha`
--- is what lets the reader key on `(repository, sha)` for real.
---
--- The reader half is `core/git_event.lua`'s `read_repository_discriminator`
--- (ported from log-core) and the monorepo's `analysis-core/git/observed-dag.ts`.
--- The writer contract is pinned in the monorepo's
--- `docs/superpowers/specs/2026-08-19-program-decision-log.md`, "The writer
--- contract for `root_commit_sha`". The reader is correct whatever the writer
--- picks — the value is opaque and compared only for equality — so the contract
--- exists to make THREE RECORDERS DERIVE THE SAME VALUE, which is the only
--- thing that makes correlation work at all.
---
--- ## The value
---
--- `git rev-list --max-parents=0 --first-parent HEAD` — the root of HEAD's
--- FIRST-PARENT lineage. First-parent because that lineage stays on the
--- mainline when an imported history is merged in, which is what keeps two
--- partners agreeing. If it yields more than one root — an orphan branch, a
--- squashed import; ORDINARY, and never a finding — the lexicographically
--- smallest is taken, so two partners with the same history agree.
---
--- ## Absence is a legal, permanent, blameless answer
---
--- The field is OMITTED — never `nil`-as-`null`, and the payload builder is the
--- one that enforces that — when the repository is shallow, when git fails,
--- times out or is missing, and when the value that comes back is not a commit
--- sha.
---
--- A SHALLOW CLONE is the case worth naming: its boundary commit has no parents
--- and is NOT a root, so `rev-list --max-parents=0` would happily print it and
--- emitting it would publish a value a full clone of the same repository
--- disagrees with — a silent failure to correlate, dressed as a successful one.
--- `rev-parse --is-shallow-repository` is checked FIRST and anything other than
--- a definite `false` omits.
---
--- That flag needs git >= 2.15. An older git does not know it and exits
--- non-zero, which lands in "omit on any failure" — correct, and worth naming
--- as the mechanism rather than special-casing: the answer for "I cannot tell
--- whether this clone is shallow" is the same as the answer for "it is".
---
--- ## No identity, ever
---
--- This is a repository identifier and nothing else. It is deliberately NOT the
--- repository path (arguably an identifier, certainly noisy) and NOT a remote
--- URL (which embeds the org and frequently the student's own username) —
--- S14(b). No author name, no author email, no commit message is read here or
--- anywhere else in this recorder.
---
--- The shape check is enforced through THIS PORT'S OWN LOG-CORE READER
--- (`core/git_event.is_usable_discriminator`), not a private regex, so a writer
--- can never emit a value its reader rejects. It is applied twice on purpose —
--- here, to reject a line before it can even be a candidate root, and again in
--- `git_payloads.build_git_event`, which is the last gate before the value
--- enters a signed payload.
---
--- ## No network (PRD NG2)
---
--- `rev-parse` and `rev-list` are local object-database reads. Nothing here
--- fetches, and nothing consults a remote.
---
--- ## Cost
---
--- Two `run_git` invocations, ONCE per repository at wiring setup — never on
--- the event path, never on the keystroke path. The value cannot change for the
--- life of a repository.
local git_event = require("provenance.core.git_event")

local M = {}

--- Run one git subcommand through the caller's seam, tolerating a throwing or
--- badly-shaped seam. Mirrors `git_wiring.safe_run_git`, kept local so this
--- module has exactly one dependency and can be unit-tested on its own.
--- @param run_git function(args_list: string[]) -> {ok: boolean, out: string}
--- @param args string[]
--- @return table {ok: boolean, out: string}
local function safe_run(run_git, args)
  local ok, res = pcall(run_git, args)
  if ok and type(res) == "table" then
    return { ok = res.ok == true, out = type(res.out) == "string" and res.out or "" }
  end
  return { ok = false, out = "" }
end

--- Derive the repository discriminator, or nil to OMIT the field.
---
--- Called ONCE per repository at git-wiring setup — never per event. Never
--- raises: every failure is an omission, because guessing is worse than
--- silence and silence costs only correlation.
---
--- @param run_git function(args_list: string[]) -> {ok: boolean, out: string}
---   The SAME injectable seam `git_wiring` already shells out through, so this
---   module inherits its `-C <workspace>` scoping, its `vim.fn.system` wrapper,
---   and its degrade-to-`{ok=false}` behaviour when there is no git binary.
---   Passing a repository's OWN seam is how writer rule 9 (one value per
---   repository observed) is honoured.
--- @return string|nil
function M.derive(run_git)
  if type(run_git) ~= "function" then
    return nil
  end

  -- A shallow clone's boundary commit has no parents and is NOT a root.
  -- Anything but a definite `false` omits — including the non-zero exit an
  -- older git gives for an unknown flag.
  local shallow = safe_run(run_git, { "rev-parse", "--is-shallow-repository" })
  if not shallow.ok or vim.trim(shallow.out) ~= "false" then
    return nil
  end

  local listed = safe_run(run_git, { "rev-list", "--max-parents=0", "--first-parent", "HEAD" })
  if not listed.ok then
    return nil
  end

  local roots = {}
  for line in (listed.out .. "\n"):gmatch("(.-)\n") do
    local candidate = vim.trim(line)
    -- Validated through log-core's own reader, not a regex restated here. A
    -- line that is not an object name — git chatter on stdout, an injected
    -- seam answering something unrelated, a path — is simply not a candidate.
    if git_event.is_usable_discriminator(candidate) then
      roots[#roots + 1] = candidate
    end
  end

  if #roots == 0 then
    return nil
  end

  -- Several roots is ORDINARY (an orphan branch, a squashed import merged in)
  -- and never a finding. Lexicographically smallest is deterministic, which is
  -- what makes two partners with the same history agree.
  table.sort(roots)
  return roots[1]
end

return M
