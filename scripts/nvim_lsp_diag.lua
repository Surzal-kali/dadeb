-- nvim_lsp_diag.lua — read-only ground-truth dump for the framework-stub lane.
--
-- Run it INSIDE the buffer that should resolve tool aliases (e.g. the F2 cell,
-- root or kali, whatever session is actually failing):
--
--     :lua dofile("/home/kali/github/daharness/scripts/nvim_lsp_diag.lua")
--
-- Prints DIAG: lines. Nothing is mutated (no buffer writes, no config changes).
-- Paste the DIAG lines back verbatim — every branch below names a distinct fix.

local R = ""

local function line(s)
  R = R .. "DIAG: " .. s .. "\n"
end

-- 1. Identity: whose HOME is nvim running under, and what buffer are we in?
line("HOME=" .. (os.getenv("HOME") or "?") .. " expand~=" .. vim.fn.expand("~"))
line("bufname=" .. vim.fn.expand("%:p") .. " | filetype='" .. vim.bo.filetype .. "'")

-- 2. Cell header: modeline + star-import present in first lines?
local l1 = (vim.api.nvim_buf_get_lines(0, 0, 1, false)[1] or ""):gsub("%s+$", "")
local l2 = (vim.api.nvim_buf_get_lines(0, 1, 2, false)[1] or ""):gsub("%s+$", "")
line("line1='" .. l1:sub(1, 40) .. "' line2='" .. l2:sub(1, 40) .. "'")

-- 3. Stub files: which candidate paths actually exist for THIS process?
for _, p in ipairs({
  vim.fn.expand("~/.local/share/framework-stubs"),
  "/home/kali/.local/share/framework-stubs",
  "/root/.local/share/framework-stubs",
}) do
  local st = vim.uv.fs_stat(p .. "/framework_tools.pyi")
  line("stubs@" .. p .. " -> " .. (st and ("OK " .. st.size .. "B") or "MISSING"))
end

-- 4. Config resolution: is /root/.config/nvim a symlink (root sessions), and do
--    our spec files exist at the path nvim would have loaded them from?
for _, p in ipairs({
  vim.fn.expand("~/.config/nvim/lua/plugins/python.lua"),
  "/root/.config/nvim/lua/plugins/python.lua",
  vim.fn.expand("~/.config/nvim/lua/plugins/blink.lua"),
}) do
  line("spec@" .. p .. " -> " .. (vim.uv.fs_stat(p) and "exists" or "MISSING"))
end
local tgt = vim.uv.fs_readlink("/root/.config/nvim")
if tgt ~= nil then line("/root/.config/nvim -> symlink(" .. tgt .. ")") end

-- 5. LSP clients actually attached to this buffer.
local clients = vim.lsp.get_clients({ bufnr = 0 })
if #clients == 0 then
  line("LSP: NONE attached (check filetype above — no pyright without ft=python)")
else
  for _, c in ipairs(clients) do
    line("LSP client: " .. c.name)
    local a = c.settings and c.settings.python and c.settings.python.analysis
    if a ~= nil then
      line("  extraPaths=" .. vim.inspect(a.extraPaths or "missing"))
      line("  diagnosticMode=" .. tostring(a.diagnosticMode or "unset"))
    elseif c.name == "pyright" then
      line("  pyright attached but no analysis settings visible (spec may not have loaded)")
    end
  end
end

-- 6. Live probe: which "nma"-prefixed completions does the server return here?
local pyr = vim.lsp.get_clients({ bufnr = 0, name = "pyright" })[1]
if pyr then
  local params = vim.lsp.util.make_position_params(0, pyr.offset_encoding)
  pyr:request("textDocument/completion", params, function(err, res)
    if err then
      line("completion err: " .. tostring(err.message))
    else
      local items = type(res) == "table" and (res.items or res) or {}
      local hits = {}
      for _, it in ipairs(items) do
        if (it.label or ""):sub(1, 3) == "nma" then hits[#hits + 1] = it.label end
      end
      line("completion 'nma*' matches: " .. table.concat(hits, ", "))
    end
    print(R)
  end, 0)
else
  print(R)
end