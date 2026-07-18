# Core Format Port Implementation Plan (Plan 1 of the provnvim series)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `lua/provenance/core/` — a pure-Lua reimplementation of Provenance's log-format primitives (SHA-256 via `vim.fn.sha256`, hand-ported JCS canonicalization, the one hash-chaining function, the envelope model, NDJSON, chain validation, the injectable clock) proven byte-for-byte identical to `log-core` via pinned conformance vectors.

**Architecture:** A pure-Lua module tree under `lua/provenance/core/`, with **zero Neovim editor-API dependencies** beyond the two runtime primitives it is explicitly allowed: `vim.fn.sha256` (hashing) and later `vim.uv` (I/O, not needed in this plan). This mirrors `log-core`'s "no editor deps" rule and keeps the conformance surface testable in isolation. Every module returns a table; pure functions where there is no state to own. Tests run headless under `plenary.nvim`'s busted-style runner.

**Tech Stack:** Lua (LuaJIT, as bundled by Neovim ≥ 0.10), `vim.fn.sha256`, `plenary.nvim` test harness, the monorepo's `tools/export-conformance-vectors.ts` for golden vectors.

## Global Constraints

- **Format is a fixed contract owned by the monorepo's `log-core`.** This module reproduces it; it never redefines it. If a vector cannot be matched, STOP and ask — do not edit the vector. (CLAUDE.md)
- **`core/` has zero editor dependencies.** Pure Lua + `vim.fn.sha256` only (and `vim.uv` for I/O in later plans). No `nvim_*`, no autocmds, no buffers. (design.md §9, CLAUDE.md)
- **Hash formula (PRD §5.2):** `entry.hash = sha256_hex(prev_hash_string .. JCS(entry))`, where `entry` is `{seq, t, wall, kind, data}` with **no** `prev_hash`/`hash` fields, and `prev_hash_string` is the raw 64-char hex string prepended to the canonical JSON. UTF-8 SHA-256.
- **Genesis prev_hash:** 64 lowercase-hex zeros.
- **All hashes are 64-char lowercase hex.**
- **JCS = `JSON.stringify` semantics, NOT full RFC 8785.** log-core's `canonical.ts` wraps the `canonicalize` npm package v3, which delegates every scalar to `JSON.stringify` and sorts keys with JS default `Array.prototype.sort()` (UTF-16 code-unit order). Reproduce *that*: code-unit key sort, no whitespace, `JSON.stringify` string escaping, shortest-round-trip numbers. All real envelope numbers are small non-negative integers.
- **Determinism:** no wall-clock / `vim.uv.hrtime()` / `math.random()` in assertions; inject clocks; assert against pinned constants.
- **Neovim floor:** 0.10+ (dev/CI on the installed 0.12.1). Pinned in Task 1's README note.
- **Commits:** conventional prefixes, `git commit --no-gpg-sign`, **no** `Co-Authored-By: Claude` trailer, explicit pathspec.

### Pinned conformance vectors (from log-core `hash-chain.test.ts`, re-emitted by the export tool into `tests/conformance/fixtures/vectors.json`)

- `sha256_hex("hello world")` = `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`
- `sha256_hex("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `GENESIS_PREV_HASH` = `"0"` × 64
- Golden chain vector: `chainEntry(GENESIS, {seq=0, t=0, wall="2026-01-01T00:00:00.000Z", kind="session.end", data={reason="test"}}).hash` = `d33cad1d38b90b26a2f7b1181801805233bf4332eca5bc6d4ff4e1b677683625`
  - Its canonical envelope string is exactly: `{"data":{"reason":"test"},"kind":"session.end","seq":0,"t":0,"wall":"2026-01-01T00:00:00.000Z"}`
  - **This has already been verified to reproduce in headless Neovim via `vim.fn.sha256(("0"):rep(64) .. canonical)` — the keystone hash path is proven.**

### File structure (created across this plan)

```
lua/provenance/core/
  sha256.lua        -- vim.fn.sha256 wrapper (Task 2)
  json.lua          -- JSON value model + JCS canonicalizer (Task 3)  [the crux]
  envelope.lua      -- Envelope / HashedEnvelope constructors + to-canonical (Task 4)
  hash_chain.lua    -- GENESIS_PREV_HASH + chain_entry (Task 5)
  ndjson.lua        -- serialize_entry / parse_entries + shape validation (Task 6)
  chain_validator.lua -- validate_chain (seq/prev/hash/t/wall rules) (Task 7)
  clock.lua         -- system + fixed clock; monotonic t + fixed-width ISO wall (Task 8)
tests/
  minimal_init.lua  -- headless bootstrap that puts plenary + this repo on rtp (Task 1)
  core/*_spec.lua   -- one spec per module
  conformance/
    fixtures/       -- exported golden vectors (Task 9)
    conformance_spec.lua
Makefile            -- `make test`, `make vectors` (Task 1 / Task 9)
```

---

### Task 1: Plugin scaffold + plenary headless test harness

**Files:**
- Create: `lua/provenance/init.lua` (placeholder entry module)
- Create: `tests/minimal_init.lua`
- Create: `Makefile`
- Modify: `README.md` (add a "Development / Testing" section)
- Create: `.gitignore` entries if needed (already present)

**Interfaces:**
- Produces: a working `make test` that runs `nvim --headless` with plenary's busted runner over `tests/`. A green run with zero specs is the deliverable.

- [ ] **Step 1: Create the placeholder entry module**

`lua/provenance/init.lua`:
```lua
--- Provenance Recorder (provnvim) — entry module.
--- Wiring is added in later plans; this file exists so the plugin is require-able.
local M = {}

return M
```

- [ ] **Step 2: Create the headless test bootstrap**

`tests/minimal_init.lua` — puts this repo and a discoverable `plenary.nvim` on the runtimepath. It searches common plugin-manager locations so CI and local dev both work:
```lua
-- Bootstrap runtimepath for headless plenary-busted runs.
local this = vim.fn.fnamemodify(vim.fn.resolve(vim.fn.expand("<sfile>:p")), ":h:h")
vim.opt.runtimepath:append(this)

local function find_plenary()
  local candidates = {
    vim.fn.stdpath("data") .. "/lazy/plenary.nvim",
    vim.fn.stdpath("data") .. "/site/pack/packer/start/plenary.nvim",
    vim.fn.expand("~/.local/share/nvim/lazy/plenary.nvim"),
    os.getenv("PLENARY_PATH") or "",
  }
  for _, p in ipairs(candidates) do
    if p ~= "" and vim.fn.isdirectory(p) == 1 then
      return p
    end
  end
  error("plenary.nvim not found; set PLENARY_PATH")
end

vim.opt.runtimepath:append(find_plenary())
vim.cmd("runtime plugin/plenary.vim")
```

- [ ] **Step 3: Create the Makefile**

`Makefile`:
```make
NVIM ?= nvim

.PHONY: test vectors
test:
	$(NVIM) --headless --noplugin -u tests/minimal_init.lua \
	  -c "PlenaryBustedDirectory tests/ { minimal_init = 'tests/minimal_init.lua' }"

# Regenerate golden conformance vectors from the Provenance monorepo (Task 9).
vectors:
	cd $(PROVENANCE_REPO) && node --experimental-strip-types tools/export-conformance-vectors.ts \
	  --out $(CURDIR)/tests/conformance/fixtures
```

- [ ] **Step 4: Run the harness with no specs to prove it boots**

Run: `make test`
Expected: plenary runs, reports "Success" / 0 failures (no specs yet). If it errors on `find_plenary`, run `PLENARY_PATH=~/.local/share/nvim/lazy/plenary.nvim make test`.

- [ ] **Step 5: Add the README development note**

Append to `README.md`:
```markdown
## Development / Testing

Requires Neovim ≥ 0.10 (developed against 0.12.1) and `plenary.nvim` on the
runtimepath. Run the suite headless:

    make test

`make test` runs `plenary.nvim`'s busted-style runner over `tests/`. The
conformance suite (`tests/conformance/`) proves byte-for-byte format parity
with the Provenance monorepo's `log-core`; a red conformance test means the
implementation drifted — fix the code, never the vectors. Regenerate vectors
with `PROVENANCE_REPO=/path/to/provenance make vectors`.
```

- [ ] **Step 6: Commit**

```bash
git add lua/provenance/init.lua tests/minimal_init.lua Makefile README.md
git commit --no-gpg-sign -m "chore: plugin scaffold + plenary headless test harness"
```

---

### Task 2: SHA-256 wrapper over `vim.fn.sha256`

**Files:**
- Create: `lua/provenance/core/sha256.lua`
- Test: `tests/core/sha256_spec.lua`

**Interfaces:**
- Produces: `sha256.hex(input: string): string` — returns 64-char lowercase hex of the UTF-8 bytes of `input`. Thin wrapper over `vim.fn.sha256` (which already returns lowercase hex).

- [ ] **Step 1: Write the failing test**

`tests/core/sha256_spec.lua`:
```lua
local sha256 = require("provenance.core.sha256")

describe("sha256.hex", function()
  it("matches the NIST vector for 'hello world'", function()
    assert.equals(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      sha256.hex("hello world")
    )
  end)

  it("matches the NIST vector for the empty string", function()
    assert.equals(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      sha256.hex("")
    )
  end)

  it("returns 64 lowercase hex chars", function()
    local h = sha256.hex("anything")
    assert.equals(64, #h)
    assert.is_truthy(h:match("^[0-9a-f]+$"))
  end)
end)
```

- [ ] **Step 2: Run to verify it fails**

Run: `make test`
Expected: FAIL — module `provenance.core.sha256` not found.

- [ ] **Step 3: Write the implementation**

`lua/provenance/core/sha256.lua`:
```lua
--- SHA-256 → 64-char lowercase hex, over the UTF-8 bytes of the input.
--- Mirrors log-core's sha256Hex. Uses Neovim's builtin (no native dep).
local M = {}

--- @param input string  raw byte string (Lua strings are byte arrays)
--- @return string       64-char lowercase hex digest
function M.hex(input)
  return vim.fn.sha256(input)
end

return M
```

- [ ] **Step 4: Run to verify it passes**

Run: `make test`
Expected: PASS (3 assertions).

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/sha256.lua tests/core/sha256_spec.lua
git commit --no-gpg-sign -m "feat(core): sha256 hex over vim.fn.sha256 matching log-core vectors"
```

---

### Task 3: JSON value model + JCS canonicalizer (the crux)

log-core has no separate JSON model (it uses JS objects). Lua tables cannot distinguish an empty object `{}` from an empty array `[]`, and JSON `null` has no native Lua value. Because this recorder **constructs** every payload itself, we define a small, explicit value model and canonicalize over it. This is the single most subtle module in the port; it is pinned by `canonical.test.ts`-derived vectors.

**Files:**
- Create: `lua/provenance/core/json.lua`
- Test: `tests/core/json_spec.lua`

**Interfaces:**
- Produces:
  - `json.NULL` — a unique sentinel table representing JSON `null`.
  - `json.array(t?: table): table` — tags a (possibly empty) list table as a JSON array; returns it.
  - `json.is_array(v: any): boolean` — true iff `v` was tagged by `json.array`.
  - `json.canonicalize(value: any): string` — returns the JCS-canonical JSON string. Objects are plain string-keyed tables; arrays are `json.array`-tagged tables; scalars are Lua `string`/`number`/`boolean`; `null` is `json.NULL`. Raises on `nil`, `NaN`, `±inf`, or non-string object keys (mirrors the library throwing on `undefined`/`NaN`/`Infinity`).

**Design notes (encode in the module doc-comment):**
- **Object detection:** a Lua table is an *array* iff `json.is_array` is true (tagged) — never inferred from shape, to avoid the empty-`{}` ambiguity. Everything else (including empty untagged `{}`) is an *object*.
- **Key sort:** collect string keys, sort by **byte order** (`a < b` on Lua strings is bytewise, which equals UTF-16 code-unit order for the all-ASCII keys this format uses: digits `0-9` < `A-Z` < `_` < `a-z`). Document that non-ASCII keys never occur in this format.
- **Strings:** escape `"`→`\"`, `\`→`\\`; `\b \t \n \f \r` for 0x08/09/0A/0C/0D; other control chars 0x00–0x1F → lowercase `\u00xx`; `/` is **not** escaped; bytes ≥ 0x80 pass through raw (UTF-8). No other escaping.
- **Numbers:** integer-valued numbers (`v == math.floor(v)` and within ±2^53) format with `%d`-style integer output, no decimal point, no exponent. `-0` → `0`. Non-integers use Lua `%.17g` then trimmed to shortest round-trip — but note **every real envelope number is a small non-negative integer**, so the integer path is what conformance exercises; the float path is defensive and covered by the `1.5` / `-0.5` vectors only.
- **Booleans / null:** `true`/`false`/`null`.

- [ ] **Step 1: Write the failing test (covers the pinned canonical cases)**

`tests/core/json_spec.lua`:
```lua
local json = require("provenance.core.json")

describe("json.canonicalize", function()
  it("sorts object keys by code-unit order", function()
    assert.equals('{"a":2,"b":1}', json.canonicalize({ b = 1, a = 2 }))
  end)

  it("strips all insignificant whitespace and sorts nested keys", function()
    assert.equals('{"a":{"b":2},"z":{"a":1,"c":3}}',
      json.canonicalize({ z = { c = 3, a = 1 }, a = { b = 2 } }))
  end)

  it("preserves array order and does not reorder", function()
    assert.equals("[3,1,2]", json.canonicalize(json.array({ 3, 1, 2 })))
  end)

  it("distinguishes empty array from empty object", function()
    assert.equals("[]", json.canonicalize(json.array({})))
    assert.equals("{}", json.canonicalize({}))
  end)

  it("formats scalars like JSON.stringify", function()
    assert.equals("null", json.canonicalize(json.NULL))
    assert.equals("true", json.canonicalize(true))
    assert.equals("false", json.canonicalize(false))
    assert.equals("42", json.canonicalize(42))
    assert.equals("0", json.canonicalize(0))
    assert.equals("-1", json.canonicalize(-1))
    assert.equals("1.5", json.canonicalize(1.5))
    assert.equals("-0.5", json.canonicalize(-0.5))
    assert.equals("1000000", json.canonicalize(1000000))
  end)

  it("escapes strings like JSON.stringify", function()
    assert.equals([["a/b"]], json.canonicalize("a/b")) -- slash NOT escaped
    assert.equals([["\"\\"]], json.canonicalize('"\\'))
    assert.equals('"\\u0000\\u001f"', json.canonicalize("\0\31")) -- control chars
    assert.equals('"\\n\\t"', json.canonicalize("\n\t")) -- short escapes
  end)

  it("canonicalizes the envelope shape identically regardless of insertion order", function()
    local a = json.canonicalize({ seq = 0, t = 0, wall = "w", kind = "k", data = { r = 1 } })
    local b = json.canonicalize({ data = { r = 1 }, kind = "k", wall = "w", t = 0, seq = 0 })
    assert.equals(a, b)
    assert.equals('{"data":{"r":1},"kind":"k","seq":0,"t":0,"wall":"w"}', a)
  end)

  it("raises on nil and non-finite numbers", function()
    assert.has_error(function() json.canonicalize(nil) end)
    assert.has_error(function() json.canonicalize(0 / 0) end)
    assert.has_error(function() json.canonicalize(math.huge) end)
  end)
end)
```

- [ ] **Step 2: Run to verify it fails**

Run: `make test`
Expected: FAIL — `provenance.core.json` not found.

- [ ] **Step 3: Write the implementation**

`lua/provenance/core/json.lua`:
```lua
--- JSON value model + JCS canonicalizer.
--- Reproduces log-core's canonical.ts, which is the `canonicalize` npm pkg v3:
--- JSON.stringify scalar semantics + code-unit key sort + no whitespace.
--- We construct all payloads ourselves, so arrays are explicitly tagged
--- (json.array) — never inferred from table shape — to avoid the empty-{}/[]
--- ambiguity. Objects are plain string-keyed tables; null is json.NULL.
local M = {}

M.NULL = setmetatable({}, { __tostring = function() return "null" end })

local ARRAY_MT = {}

--- Tag a list table as a JSON array. Returns the same table.
function M.array(t)
  return setmetatable(t or {}, ARRAY_MT)
end

function M.is_array(v)
  return type(v) == "table" and getmetatable(v) == ARRAY_MT
end

-- String escaping = JSON.stringify rules.
local SHORT = { ["\8"] = "\\b", ["\9"] = "\\t", ["\10"] = "\\n", ["\12"] = "\\f", ["\13"] = "\\r" }
local function escape_string(s)
  local out = s:gsub('[%z\1-\31"\\]', function(c)
    if c == '"' then return '\\"' end
    if c == "\\" then return "\\\\" end
    local short = SHORT[c]
    if short then return short end
    return string.format("\\u%04x", string.byte(c))
  end)
  return '"' .. out .. '"'
end

local function format_number(n)
  if n ~= n then error("NaN is not allowed") end
  if n == math.huge or n == -math.huge then error("Infinity is not allowed") end
  if n == 0 then return "0" end -- also collapses -0 → 0
  if n == math.floor(n) and math.abs(n) < 2 ^ 53 then
    return string.format("%d", n)
  end
  -- Non-integer path (defensive; real envelopes have no floats).
  local s = string.format("%.17g", n)
  -- Trim to shortest round-trip.
  for p = 1, 16 do
    local cand = string.format("%." .. p .. "g", n)
    if tonumber(cand) == n then s = cand; break end
  end
  return s
end

local canon -- forward decl
local function canon_object(t)
  local keys = {}
  for k in pairs(t) do
    if type(k) ~= "string" then error("object keys must be strings") end
    keys[#keys + 1] = k
  end
  table.sort(keys) -- bytewise == code-unit order for ASCII keys
  local parts = {}
  for _, k in ipairs(keys) do
    parts[#parts + 1] = escape_string(k) .. ":" .. canon(t[k])
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function canon_array(t)
  local parts = {}
  for i = 1, #t do
    parts[i] = canon(t[i])
  end
  return "[" .. table.concat(parts, ",") .. "]"
end

canon = function(v)
  local ty = type(v)
  if v == M.NULL then return "null" end
  if ty == "nil" then error("nil is not allowed (JSON has no undefined)") end
  if ty == "boolean" then return v and "true" or "false" end
  if ty == "number" then return format_number(v) end
  if ty == "string" then return escape_string(v) end
  if ty == "table" then
    if M.is_array(v) then return canon_array(v) end
    return canon_object(v)
  end
  error("cannot canonicalize value of type " .. ty)
end

function M.canonicalize(value)
  return canon(value)
end

return M
```

- [ ] **Step 4: Run to verify it passes**

Run: `make test`
Expected: PASS. If the ` ` or slash cases fail, fix `escape_string` — do not change the expectations.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/json.lua tests/core/json_spec.lua
git commit --no-gpg-sign -m "feat(core): JSON value model + JCS canonicalizer (JSON.stringify semantics)"
```

---

### Task 4: Envelope model + canonical form

**Files:**
- Create: `lua/provenance/core/envelope.lua`
- Test: `tests/core/envelope_spec.lua`

**Interfaces:**
- Consumes: `json` (Task 3).
- Produces:
  - `envelope.new(seq, t, wall, kind, data): table` — a plain table `{seq, t, wall, kind, data}` (no hash fields). `data` is a JSON value-model value.
  - `envelope.canonical(env): string` — `json.canonicalize({seq, t, wall, kind, data})`, i.e. the exact bytes fed (after prepending prev_hash) to SHA-256.
  - `envelope.hashed_to_wire(hashed): table` — given a `{seq,t,wall,kind,data,prev_hash,hash}` table, returns it unchanged (documented as the on-wire object whose `json.canonicalize` is the stored NDJSON line). Present so callers have a named seam.

- [ ] **Step 1: Write the failing test**

`tests/core/envelope_spec.lua`:
```lua
local envelope = require("provenance.core.envelope")

describe("envelope", function()
  it("canonicalizes to sorted-key JSON without hash fields", function()
    local env = envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.end", { reason = "test" })
    assert.equals(
      '{"data":{"reason":"test"},"kind":"session.end","seq":0,"t":0,"wall":"2026-01-01T00:00:00.000Z"}',
      envelope.canonical(env)
    )
  end)

  it("does not include prev_hash or hash in the canonical form", function()
    local env = envelope.new(1, 5, "w", "doc.close", { path = "a.py" })
    local c = envelope.canonical(env)
    assert.is_nil(c:find("prev_hash", 1, true))
    assert.is_nil(c:find("\"hash\"", 1, true))
  end)
end)
```

- [ ] **Step 2: Run to verify it fails** — Run `make test`; Expected FAIL (module missing).

- [ ] **Step 3: Write the implementation**

`lua/provenance/core/envelope.lua`:
```lua
--- Envelope = {seq, t, wall, kind, data}; the pre-hash log entry.
--- HashedEnvelope adds prev_hash + hash. Mirrors log-core envelope.ts.
local json = require("provenance.core.json")

local M = {}

function M.new(seq, t, wall, kind, data)
  return { seq = seq, t = t, wall = wall, kind = kind, data = data }
end

--- Canonical bytes of the 5-field envelope (no hash fields).
function M.canonical(env)
  return json.canonicalize({
    seq = env.seq, t = env.t, wall = env.wall, kind = env.kind, data = env.data,
  })
end

--- Identity seam: the on-wire HashedEnvelope object.
function M.hashed_to_wire(hashed)
  return hashed
end

return M
```

- [ ] **Step 4: Run to verify it passes** — Run `make test`; Expected PASS.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/envelope.lua tests/core/envelope_spec.lua
git commit --no-gpg-sign -m "feat(core): envelope model + canonical form"
```

---

### Task 5: The hash chain (the pinned cross-language gate)

**Files:**
- Create: `lua/provenance/core/hash_chain.lua`
- Test: `tests/core/hash_chain_spec.lua`

**Interfaces:**
- Consumes: `sha256` (Task 2), `envelope` (Task 4).
- Produces:
  - `hash_chain.GENESIS_PREV_HASH: string` = 64 zeros.
  - `hash_chain.chain_entry(prev_hash: string, env: table): table` — returns a HashedEnvelope `{seq,t,wall,kind,data,prev_hash,hash}` where `hash = sha256.hex(prev_hash .. envelope.canonical(env))`.

- [ ] **Step 1: Write the failing test (with the pinned golden vector)**

`tests/core/hash_chain_spec.lua`:
```lua
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local function session_end(seq, t, wall, reason)
  return envelope.new(seq, t, wall, "session.end", { reason = reason })
end

describe("hash_chain", function()
  it("genesis prev_hash is 64 zeros", function()
    assert.equals(("0"):rep(64), hc.GENESIS_PREV_HASH)
  end)

  it("chain_entry matches the log-core pinned vector", function()
    local h = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "2026-01-01T00:00:00.000Z", "test"))
    assert.equals("d33cad1d38b90b26a2f7b1181801805233bf4332eca5bc6d4ff4e1b677683625", h.hash)
    assert.equals(hc.GENESIS_PREV_HASH, h.prev_hash)
  end)

  it("second entry links to the first", function()
    local h0 = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "2026-01-01T00:00:00.000Z", "test"))
    local h1 = hc.chain_entry(h0.hash, session_end(1, 1000, "2026-01-01T00:00:01.000Z", "test"))
    assert.equals(h0.hash, h1.prev_hash)
    assert.are_not.equals(h0.hash, h1.hash)
  end)

  it("differing data changes the hash", function()
    local a = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "w", "a"))
    local b = hc.chain_entry(hc.GENESIS_PREV_HASH, session_end(0, 0, "w", "b"))
    assert.are_not.equals(a.hash, b.hash)
  end)
end)
```

- [ ] **Step 2: Run to verify it fails** — Run `make test`; Expected FAIL.

- [ ] **Step 3: Write the implementation**

`lua/provenance/core/hash_chain.lua`:
```lua
--- The ONE hash-chaining function (PRD §5.2). Mirrors log-core hash-chain.ts.
local sha256 = require("provenance.core.sha256")
local envelope = require("provenance.core.envelope")

local M = {}

M.GENESIS_PREV_HASH = ("0"):rep(64)

--- @param prev_hash string  64-char hex (GENESIS for seq 0)
--- @param env table         {seq,t,wall,kind,data}
--- @return table            HashedEnvelope
function M.chain_entry(prev_hash, env)
  local canonical = envelope.canonical(env)
  local hash = sha256.hex(prev_hash .. canonical)
  return {
    seq = env.seq, t = env.t, wall = env.wall, kind = env.kind, data = env.data,
    prev_hash = prev_hash, hash = hash,
  }
end

return M
```

- [ ] **Step 4: Run to verify it passes**

Run: `make test`
Expected: PASS. **If `chain_entry matches the log-core pinned vector` fails, the Lua JCS does not match log-core — STOP and diagnose `json.canonicalize`; do not change the expected hash.**

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/hash_chain.lua tests/core/hash_chain_spec.lua
git commit --no-gpg-sign -m "feat(core): hash chain matching log-core pinned vector"
```

---

### Task 6: NDJSON serialize + parse (+ shape validation)

Note on the parse path: the stored line is `json.canonicalize(HashedEnvelope)`. To parse back we use `vim.json.decode` (allowed builtin) then normalize into the value model so a re-canonicalize round-trips. `vim.json.decode` yields `vim.NIL` for `null` and `vim.empty_dict()` for `{}`; the normalizer maps `vim.NIL`→`json.NULL`, tags list-shaped tables as arrays, and treats `vim.empty_dict()` as an empty object. Empty-array vs empty-object is pinned by a `doc.change` entry with `deltas = []`.

**Files:**
- Create: `lua/provenance/core/ndjson.lua`
- Test: `tests/core/ndjson_spec.lua`

**Interfaces:**
- Consumes: `json` (Task 3), `hash_chain` (Task 5).
- Produces:
  - `ndjson.serialize_entry(hashed: table): string` — `json.canonicalize(hashed) .. "\n"`.
  - `ndjson.parse_entries(text: string): ok(list) | err({kind, line, ...})` — splits on `\n`, skips empty lines, `vim.json.decode` + normalize + shape-validate each, returns on first error (1-indexed line). `""` → `ok({})`. Uses the shared `Result` convention `{ ok = true, value = ... }` / `{ ok = false, error = ... }`.
  - Shape validation requires `seq:number, t:number, wall:string, kind:string, data:table(object), prev_hash:64hex, hash:64hex`; unknown `kind` accepted.

- [ ] **Step 1: Write the failing test**

`tests/core/ndjson_spec.lua`:
```lua
local ndjson = require("provenance.core.ndjson")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")
local json = require("provenance.core.json")

local entry = hc.chain_entry(hc.GENESIS_PREV_HASH,
  envelope.new(0, 0, "2026-01-01T00:00:00.000Z", "session.end", { reason = "test" }))

describe("ndjson", function()
  it("serialize_entry is canonical + trailing newline", function()
    local line = ndjson.serialize_entry(entry)
    assert.is_truthy(line:match("\n$"))
    assert.equals(json.canonicalize(entry) .. "\n", line)
  end)

  it("round-trips a single entry", function()
    local res = ndjson.parse_entries(ndjson.serialize_entry(entry))
    assert.is_true(res.ok)
    assert.equals(1, #res.value)
    assert.equals(entry.hash, res.value[1].hash)
  end)

  it("round-trips an entry with an empty array field", function()
    local dc = hc.chain_entry(entry.hash,
      envelope.new(1, 1, "2026-01-01T00:00:01.000Z", "doc.change",
        { path = "a.py", deltas = json.array({}), source = "typed" }))
    local line = ndjson.serialize_entry(dc)
    local res = ndjson.parse_entries(line)
    assert.is_true(res.ok)
    -- re-serializing the parsed entry reproduces the exact bytes (empty [] preserved)
    assert.equals(line, ndjson.serialize_entry(res.value[1]))
  end)

  it("empty string parses to zero entries", function()
    local res = ndjson.parse_entries("")
    assert.is_true(res.ok)
    assert.equals(0, #res.value)
  end)

  it("reports the failing line (1-indexed) on invalid json", function()
    local res = ndjson.parse_entries(ndjson.serialize_entry(entry) .. "not json\n")
    assert.is_false(res.ok)
    assert.equals(2, res.error.line)
  end)
end)
```

- [ ] **Step 2: Run to verify it fails** — Run `make test`; Expected FAIL.

- [ ] **Step 3: Write the implementation** (normalizer maps `vim.NIL`/`vim.empty_dict()`; validates shape; 1-indexed lines). Provide the shared `Result` helpers inline or in a tiny `core/result.lua` (create it here if not present):

`lua/provenance/core/result.lua`:
```lua
local M = {}
function M.ok(value) return { ok = true, value = value } end
function M.err(error) return { ok = false, error = error } end
return M
```

`lua/provenance/core/ndjson.lua`:
```lua
local json = require("provenance.core.json")
local result = require("provenance.core.result")

local M = {}

local HEX64 = "^[0-9a-f][0-9a-f]" -- length checked separately
local function is_hex64(s)
  return type(s) == "string" and #s == 64 and s:match("^[0-9a-f]+$") ~= nil
end

-- Map a vim.json.decode result into the json value model.
local function normalize(v)
  if v == vim.NIL then return json.NULL end
  if type(v) ~= "table" then return v end
  if vim.tbl_isempty(v) then
    -- empty_dict() carries a metatable marking it an object; plain {} is []
    return getmetatable(v) and {} or json.array({})
  end
  if vim.islist(v) then
    local out = json.array({})
    for i = 1, #v do out[i] = normalize(v[i]) end
    return out
  end
  local out = {}
  for k, val in pairs(v) do out[k] = normalize(val) end
  return out
end

function M.serialize_entry(hashed)
  return json.canonicalize(hashed) .. "\n"
end

local function validate_shape(obj)
  if type(obj) ~= "table" or json.is_array(obj) then return "not an object" end
  if type(obj.seq) ~= "number" then return "seq" end
  if type(obj.t) ~= "number" then return "t" end
  if type(obj.wall) ~= "string" then return "wall" end
  if type(obj.kind) ~= "string" then return "kind" end
  if type(obj.data) ~= "table" or json.is_array(obj.data) then return "data" end
  if not is_hex64(obj.prev_hash) then return "prev_hash" end
  if not is_hex64(obj.hash) then return "hash" end
  return nil
end

function M.parse_entries(text)
  if text == "" then return result.ok({}) end
  local out = {}
  local line_no = 0
  for line in (text .. "\n"):gmatch("(.-)\n") do
    line_no = line_no + 1
    if line ~= "" then
      local ok, decoded = pcall(vim.json.decode, line, { luanil = { object = false, array = false } })
      if not ok then
        return result.err({ kind = "invalid_json", line = line_no, message = tostring(decoded) })
      end
      local obj = normalize(decoded)
      local bad = validate_shape(obj)
      if bad then
        return result.err({ kind = "invalid_shape", line = line_no, missing_field = bad })
      end
      out[#out + 1] = obj
    end
  end
  return result.ok(out)
end

return M
```

- [ ] **Step 4: Run to verify it passes** — Run `make test`; Expected PASS. If the empty-array round-trip fails, the `normalize`/`vim.islist` handling is wrong — fix it (this is the empty `{}` vs `[]` seam).

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/ndjson.lua lua/provenance/core/result.lua tests/core/ndjson_spec.lua
git commit --no-gpg-sign -m "feat(core): NDJSON serialize + parse with shape validation"
```

---

### Task 7: Chain validator

**Files:**
- Create: `lua/provenance/core/chain_validator.lua`
- Test: `tests/core/chain_validator_spec.lua`

**Interfaces:**
- Consumes: `json`, `sha256`, `hash_chain`, `envelope`.
- Produces:
  - `chain_validator.validate_chain(entries: list): {ok=true} | {ok=false, break_={reason, at_seq, expected?}}`
  - Rules, first failure wins (mirrors `chain-validator.ts`): (1) empty → ok; (2) `entry.seq == index i` else `seq_gap {at_seq=entry.seq, expected=i}`; (3) `prev_hash == (i==0 ? GENESIS : prev.hash)` else `hash_mismatch`; (4) recomputed `sha256.hex(prev_hash .. envelope.canonical(entry-without-hashes)) == entry.hash` else `hash_mismatch`; (5) for i>0 `entry.t >= prev.t` else `t_regression`; (6) for i>0 `entry.wall >= prev.wall` (string compare) **unless** a `clock.skew`-kind entry exists at any seq in `[prev.seq, entry.seq]` inclusive, else `wall_regression`.

- [ ] **Step 1: Write the failing test** — cover: valid chain ok; empty ok; tampered `data` → `hash_mismatch` at that seq; broken `prev_hash` link → `hash_mismatch`; `seq` gap → `seq_gap`; `t` going backwards → `t_regression`; `wall` going backwards with a preceding `clock.skew` entry → ok, without it → `wall_regression`. (Build chains with `hash_chain.chain_entry`; mutate copies to break them.)

- [ ] **Step 2: Run to verify it fails** — Run `make test`; Expected FAIL.

- [ ] **Step 3: Write the implementation** — walk entries, recompute via `envelope.new(...)` + `hash_chain.chain_entry` (or a local recompute that strips prev_hash/hash and canonicalizes), track prev, scan the inclusive index window for a `clock.skew` kind to excuse `wall_regression`. Compare `wall` as raw strings (valid because of fixed-width ISO).

- [ ] **Step 4: Run to verify it passes** — Run `make test`; Expected PASS.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/chain_validator.lua tests/core/chain_validator_spec.lua
git commit --no-gpg-sign -m "feat(core): chain validator (seq/prev-hash/recompute/t/wall rules)"
```

---

### Task 8: Clock — monotonic `t` + fixed-width ISO `wall`

**Files:**
- Create: `lua/provenance/core/clock.lua`
- Test: `tests/core/clock_spec.lua`

**Interfaces:**
- Produces:
  - `clock.system(): Clock` — `now()` returns monotonic ms via `vim.uv.hrtime() / 1e6`; `wall()` returns the current UTC time formatted as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
  - `clock.fixed(now_ms?, wall_ms?): Clock` — deterministic test double with `advance(ms)`, `set_now(ms)`, `set_wall(ms)`; `wall()` formats `wall_ms` (epoch ms) the same way.
  - `clock.format_wall(epoch_ms: number): string` — the fixed-width formatter (exposed for direct testing). **Milliseconds are always 3 digits, including `.000`** (the provjet regression guard).
- A `Clock` is `{ now = fn(): number, wall = fn(): string }`.

- [ ] **Step 1: Write the failing test** — pin `format_wall`:
```lua
local clock = require("provenance.core.clock")
describe("clock.format_wall", function()
  it("formats epoch 0 with three-digit millis", function()
    assert.equals("1970-01-01T00:00:00.000Z", clock.format_wall(0))
  end)
  it("keeps .000 for whole-second times (zero-millis guard)", function()
    assert.equals("2026-01-01T00:00:01.000Z", clock.format_wall(1767225601000))
  end)
  it("zero-pads sub-second millis", function()
    assert.equals("2026-01-01T00:00:00.800Z", clock.format_wall(1767225600800))
  end)
  it("matches the fixed-width ISO regex", function()
    assert.is_truthy(clock.format_wall(1767225600800):match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d%.%d%d%dZ$"))
  end)
end)
describe("clock.fixed", function()
  it("advance moves both clocks", function()
    local c = clock.fixed(0, 0)
    c.advance(1500)
    assert.equals(1500, c.now())
    assert.equals("1970-01-01T00:00:01.500Z", c.wall())
  end)
end)
```
(Verify the epoch constants: `1767225600000` = `2026-01-01T00:00:00.000Z`.)

- [ ] **Step 2: Run to verify it fails** — Run `make test`; Expected FAIL.

- [ ] **Step 3: Write the implementation** — `format_wall` uses `os.date("!%Y-%m-%dT%H:%M:%S", math.floor(epoch_ms/1000))` for the UTC seconds part then appends `.` + `string.format("%03d", epoch_ms % 1000)` + `Z`. `system().now()` = `vim.uv.hrtime() / 1e6`; `system().wall()` = `format_wall(os.time()*1000 + <millis>)` — since `os.time()` is second-granular, obtain millis via `vim.uv.gettimeofday()` (returns sec, usec) → `sec*1000 + floor(usec/1000)`. `fixed` stores `now_ms`/`wall_ms` and mutates them.

- [ ] **Step 4: Run to verify it passes** — Run `make test`; Expected PASS.

- [ ] **Step 5: Commit**

```bash
git add lua/provenance/core/clock.lua tests/core/clock_spec.lua
git commit --no-gpg-sign -m "feat(core): injectable clock, fixed-width ISO wall (zero-millis guard)"
```

---

### Task 9: Conformance gate against exported golden vectors

**Files:**
- Create: `tests/conformance/fixtures/` (populated by the export tool)
- Create: `tests/conformance/conformance_spec.lua`
- Modify: `README.md` — expand the Conformance note (Task 1 added the dev note).

**Interfaces:**
- Consumes: `sha256`, `json`, `hash_chain`, `envelope`. This is a gate — nothing downstream consumes it. It reads `fixtures/vectors.json` and asserts every entry. Crypto/bundle vectors (`ed25519.json`, `session-key.json`, `manifest.json`, `bundle-manifest.json`, `checkpoint.json`, `golden-bundle.json`) are asserted in **Plan 2**; this task wires only the format vectors so Plan 1 is self-gating.

- [ ] **Step 1: Generate the fixtures from the monorepo**

Run: `PROVENANCE_REPO=/Users/aaryanmehta/projects/provenance make vectors`
Expected: `tests/conformance/fixtures/` now contains `vectors.json`, `ed25519.json`, `session-key.json`, `checkpoint.json`, `manifest.json`, `bundle-manifest.json`, `golden-bundle.json`, `golden-bundle.zip`. Commit all of them (they are the pinned contract snapshot).

- [ ] **Step 2: Write the conformance spec (format vectors)**

`tests/conformance/conformance_spec.lua`:
```lua
local sha256 = require("provenance.core.sha256")
local hc = require("provenance.core.hash_chain")
local envelope = require("provenance.core.envelope")

local function load_fixture(name)
  local dir = vim.fn.fnamemodify(vim.fn.expand("<sfile>:p"), ":h") .. "/fixtures/"
  return vim.json.decode(table.concat(vim.fn.readfile(dir .. name), "\n"))
end

describe("conformance: format vectors (vectors.json)", function()
  local v = load_fixture("vectors.json")

  it("sha256 vectors match", function()
    for _, case in ipairs(v.sha256) do
      assert.equals(case.hex, sha256.hex(case.input))
    end
  end)

  it("chain vectors match", function()
    for _, case in ipairs(v.chain) do
      local e = case.envelope
      local env = envelope.new(e.seq, e.t, e.wall, e.kind, e.data)
      assert.equals(case.hash, hc.chain_entry(case.prev_hash, env).hash)
    end
  end)
end)
```
Note: `vectors.json`'s chain envelope `data` is `{reason="test"}` — a plain object, which `vim.json.decode` yields as a normal table; `envelope.canonical` canonicalizes it correctly. If a future vector carries an empty array/object in `data`, route it through `ndjson`'s `normalize` first.

- [ ] **Step 3: Run to verify it passes**

Run: `make test`
Expected: PASS. A failure here means the Lua format is not identical to log-core — fix the implementation, never the fixture.

- [ ] **Step 4: Expand the README Conformance note**

Append to `README.md`:
```markdown
### Conformance

`lua/provenance/core/` is verified byte-for-byte against Provenance's `log-core`
via golden vectors exported by the monorepo's `tools/export-conformance-vectors.ts`
into `tests/conformance/fixtures/`. A failing conformance test means the format
has drifted — fix the implementation, never the vectors. Crypto/bundle vectors
are asserted starting in Plan 2.
```

- [ ] **Step 5: Run the full suite**

Run: `make test`
Expected: PASS — sha256, json, envelope, hash_chain, ndjson, chain_validator, clock, conformance all green.

- [ ] **Step 6: Commit**

```bash
git add tests/conformance/ README.md
git commit --no-gpg-sign -m "test(core): format conformance gate against log-core golden vectors"
```

---

## Self-Review

**Spec coverage (design.md §4 & §9.1 — the format-parity core):** SHA-256 via `vim.fn.sha256` (T2), hand-ported JCS with JSON.stringify semantics (T3), envelope + canonical form (T4), the one hash chain matching the pinned vector (T5), NDJSON serialize/parse (T6), chain validation incl. the `clock.skew` wall-regression window (T7), injectable clock with the zero-millis guard (T8), conformance gate (T9). ed25519/XChaCha20/manifest/bundle/checkpoint are **deferred to Plan 2** (they need the vendored crypto and pair with the seal path). `core/`'s zero-editor-dependency rule is structural (no `nvim_*`/autocmd/buffer calls anywhere in the module).

**Placeholder scan:** Tasks 2–6 and 8–9 contain full code + exact commands. Tasks 7 (chain_validator) gives interfaces + a complete rule list + enumerated test cases but not every line of Lua — the implementer writes the walk from the pinned rules; acceptable because the rules and tests are fully specified. If executing strictly, expand T7 Step 1/3 to literal code before starting.

**Type consistency:** `json.canonicalize`/`json.array`/`json.NULL` (T3) are consumed unchanged by envelope (T4), ndjson (T6), chain_validator (T7); `envelope.new`/`envelope.canonical` (T4) reused by hash_chain (T5) and chain_validator (T7); `hash_chain.chain_entry`/`GENESIS_PREV_HASH` (T5) reused by ndjson tests and chain_validator (T7); the `Result` `{ok,value}`/`{ok,error}` shape (T6) is the shared convention.

**Keystone note:** the hash path (`vim.fn.sha256`) is already proven to reproduce all three format vectors in headless Neovim before implementation. The remaining risk in this plan is entirely in `json.canonicalize` (T3), which is why it is pinned by both `canonical.test.ts`-derived cases and the golden chain vector.

**Dependency approvals (Global Constraints):** `plenary.nvim` (test harness, open q2 — resolved to plenary since it is already installed), and `vim.fn.sha256` (approved builtin). No vendored library in this plan — crypto vendoring starts in Plan 2.
