--- focus_payloads: pure builder for the focus.change event shape.
local focus_payloads = require("provenance.recorder.events.focus_payloads")

describe("focus_payloads.build_focus_change", function()
  it("builds focus.change with gained=true", function()
    local ev = focus_payloads.build_focus_change(true)
    assert.equals("focus.change", ev.kind)
    assert.equals(true, ev.data.gained)
  end)

  it("builds focus.change with gained=false", function()
    local ev = focus_payloads.build_focus_change(false)
    assert.equals("focus.change", ev.kind)
    assert.equals(false, ev.data.gained)
  end)
end)
