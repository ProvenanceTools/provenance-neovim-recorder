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
