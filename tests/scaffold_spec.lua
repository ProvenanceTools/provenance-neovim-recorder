-- Placeholder spec so `make test` reports a legible Success/Failed summary.
-- Real specs land with each later task; this only proves the harness boots
-- and the entry module is require-able.
describe("provnvim scaffold", function()
  it("loads the entry module", function()
    local provenance = require("provenance")
    assert.is_table(provenance)
  end)
end)
