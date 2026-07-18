--- Pure activation decision: parse + verify a manifest against the course
--- pubkey. Mirrors the recorder's activation gate (design.md §4.1) but with
--- zero Neovim API use in the module under test — only this spec uses
--- vim.json.encode, to serialize the fixture's manifest object into text.
local activation = require("provenance.recorder.activation")

-- Locate the shared conformance fixtures dir (see conformance_spec for why
-- debug.getinfo is used rather than <sfile> under plenary's loadfile runner).
local function this_file_dir()
  local source = debug.getinfo(1, "S").source
  local path = source:match("^@(.*)$") or source
  return vim.fn.fnamemodify(path, ":h")
end

local function load_fixture()
  local dir = this_file_dir() .. "/../conformance/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. "manifest.json"), "\n"))
end

describe("activation.evaluate", function()
  local fx = load_fixture()

  it("is active for a valid signed manifest with the correct pubkey", function()
    local res = activation.evaluate(vim.json.encode(fx.manifest), fx.course_pubkey_hex)
    assert.equals("active", res.status)
    assert.is_table(res.manifest)
    assert.equals("hw3", res.manifest.assignment_id)
  end)

  it("is inactive with reason signature_invalid for the wrong pubkey", function()
    local wrong_pubkey = fx.course_pubkey_hex:sub(1, -2) .. (fx.course_pubkey_hex:sub(-1) == "0" and "1" or "0")
    local res = activation.evaluate(vim.json.encode(fx.manifest), wrong_pubkey)
    assert.equals("inactive", res.status)
    assert.equals("signature_invalid", res.reason)
  end)

  it("is inactive with reason signature_invalid for a tampered field", function()
    local decoded = vim.json.decode(vim.json.encode(fx.manifest))
    decoded.assignment_id = decoded.assignment_id .. "-tampered"
    local res = activation.evaluate(vim.json.encode(decoded), fx.course_pubkey_hex)
    assert.equals("inactive", res.status)
    assert.equals("signature_invalid", res.reason)
  end)

  it("is inactive with reason parse_error for malformed JSON, and does not throw", function()
    local ok, res = pcall(activation.evaluate, "{not json", fx.course_pubkey_hex)
    assert.is_true(ok)
    assert.equals("inactive", res.status)
    assert.equals("parse_error", res.reason)
  end)
end)
