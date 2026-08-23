-- Conformance: path-scope-vectors.json — the cross-port matcher gate.
--
-- `tests/conformance/fixtures/path-scope-vectors.json` is a MANUAL, VERBATIM
-- copy of `tools/path-scope-vectors.json` in the Provenance monorepo. It is
-- hand-maintained there (the `tools/export-conformance-vectors.ts` generator
-- does NOT produce it) and consumed unmodified by the TypeScript, Kotlin
-- (provjet) and Lua (this repo) ports. Do not edit the copy in this repo —
-- re-copy the monorepo file byte-for-byte when it changes.

local path_scope = require("provenance.core.path_scope")

-- NOTE: `<sfile>` does not resolve to this file under plenary's `loadfile()`
-- runner (see conformance_spec.lua's note); use `debug.getinfo` instead.
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture(name)
  local dir = this_file_dir() .. "/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

local v = load_fixture("path-scope-vectors.json")

describe("conformance: path-scope-vectors.json", function()
  -- Assert fixture counts up front so a truncated or mis-decoded fixture
  -- cannot make a loop below vacuously pass.
  it("has the expected vector counts", function()
    assert.equals(14, #v.match)
    assert.equals(4, #v.editorGlobHazards.cases)
    assert.equals(25, #v.validate)
    assert.equals(8, #v.role)
  end)

  it("matches_scope_entry agrees with every 'match' vector", function()
    for _, case in ipairs(v.match) do
      assert.equals(
        case.expect,
        path_scope.matches_scope_entry(case.path, case.entry),
        string.format("path=%q entry=%q", case.path, case.entry)
      )
    end
  end)

  it(
    "rejects paths a permissive editor watcher glob would deliver but the matcher must not admit (design spec §4.2)",
    function()
      for _, case in ipairs(v.editorGlobHazards.cases) do
        assert.equals(
          case.expect,
          path_scope.matches_scope_entry(case.path, case.entry),
          string.format("path=%q entry=%q", case.path, case.entry)
        )
      end
    end
  )

  it("validate_scope_entry agrees with every 'validate' vector", function()
    for _, case in ipairs(v.validate) do
      local problem = path_scope.validate_scope_entry(case.entry)
      -- vim.json.decode turns JSON `null` into `vim.NIL`, and a nil-valued
      -- table key simply vanishes — so `case.problem` must be checked
      -- against both `nil` and `vim.NIL` to actually exercise the null
      -- cases rather than silently skipping them.
      if case.problem == nil or case.problem == vim.NIL then
        assert.is_nil(problem, string.format("entry=%q expected no problem", case.entry))
      else
        assert.is_not_nil(problem, string.format("entry=%q expected problem %q", case.entry, case.problem))
        assert.equals(case.problem, problem.kind, string.format("entry=%q", case.entry))
      end
    end
  end)

  it("resolve_path_role agrees with every 'role' vector", function()
    for _, case in ipairs(v.role) do
      local scope = {
        track = case.scope.track,
        ignore = case.scope.ignore,
        attachments = case.scope.attachments,
      }
      assert.equals(
        case.expect,
        path_scope.resolve_path_role(case.path, scope),
        string.format("path=%q", case.path)
      )
    end
  end)
end)
