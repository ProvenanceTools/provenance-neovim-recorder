-- Provenance Recorder plugin entry point. Guarded by a vim.g sentinel so
-- sourcing this file twice (e.g. multiple rtp entries) is a no-op. All
-- activation logic lives in lua/provenance/recorder/init.lua — keep this
-- file minimal.
if vim.g.loaded_provenance then
  return
end
vim.g.loaded_provenance = true

require("provenance.recorder").setup()
