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

  it("passes non-ASCII string VALUES through raw as UTF-8 (not \\u-escaped)", function()
    assert.equals('"café"', json.canonicalize("café"))
    assert.equals('"😀"', json.canonicalize("😀")) -- non-BMP, raw 4-byte UTF-8
    assert.equals([["a/b"]], json.canonicalize("a/b")) -- '/' passes through raw
    assert.equals("\"\127\"", json.canonicalize("\127")) -- DEL (0x7f) passes through raw
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
