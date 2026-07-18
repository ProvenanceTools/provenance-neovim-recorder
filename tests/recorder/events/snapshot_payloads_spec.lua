local json = require("provenance.core.json")
local snapshot_payloads = require("provenance.recorder.events.snapshot_payloads")

describe("snapshot_payloads.build_ext_snapshot", function()
  it("builds ext.snapshot with extensions array preserving order", function()
    local plugins = {
      { id = "plugin.a", version = "1.0.0", enabled = true },
      { id = "plugin.b", version = "2.1.0", enabled = false },
      { id = "plugin.c", version = "0.1.0", enabled = true },
    }
    local ev = snapshot_payloads.build_ext_snapshot(plugins)
    assert.equals("ext.snapshot", ev.kind)
    assert.equals(3, #ev.data.extensions)
    assert.equals("plugin.a", ev.data.extensions[1].id)
    assert.equals("1.0.0", ev.data.extensions[1].version)
    assert.equals(true, ev.data.extensions[1].enabled)
    assert.equals("plugin.b", ev.data.extensions[2].id)
    assert.equals("2.1.0", ev.data.extensions[2].version)
    assert.equals(false, ev.data.extensions[2].enabled)
    assert.equals("plugin.c", ev.data.extensions[3].id)
  end)

  it("uses json.array so extensions canonicalizes as [] not {}", function()
    local ev = snapshot_payloads.build_ext_snapshot({})
    assert.is_true(json.is_array(ev.data.extensions))
    assert.equals("[]", json.canonicalize(ev.data.extensions))
  end)

  it("canonicalizes a non-empty extensions array correctly", function()
    local plugins = {
      { id = "x", version = "1.0", enabled = true },
    }
    local ev = snapshot_payloads.build_ext_snapshot(plugins)
    local canon = json.canonicalize(ev.data.extensions)
    -- Should be an array, not object
    assert.equals("[", canon:sub(1, 1))
  end)

  it("preserves the extensions field name", function()
    local plugins = { { id = "p", version = "v", enabled = true } }
    local ev = snapshot_payloads.build_ext_snapshot(plugins)
    -- The field name in data is "extensions"
    assert.is_not_nil(ev.data.extensions)
  end)
end)

describe("snapshot_payloads.build_ext_activate", function()
  it("builds ext.activate with id and version", function()
    local ev = snapshot_payloads.build_ext_activate("my.plugin", "1.2.3")
    assert.equals("ext.activate", ev.kind)
    assert.equals("my.plugin", ev.data.id)
    assert.equals("1.2.3", ev.data.version)
  end)

  it("has exactly the shape {id, version}", function()
    local ev = snapshot_payloads.build_ext_activate("p", "v")
    local field_count = 0
    for k in pairs(ev.data) do
      field_count = field_count + 1
    end
    assert.equals(2, field_count)
    assert.is_not_nil(ev.data.id)
    assert.is_not_nil(ev.data.version)
  end)
end)
