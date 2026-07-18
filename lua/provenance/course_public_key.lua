--- Course public key constant used for manifest verification during activation.
--- The dev value here matches the conformance fixture; in production, Plan 9's
--- dist flow swaps this per course release (see CLAUDE.md).
local M = {}

M.COURSE_PUBLIC_KEY_HEX = "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"

return M
