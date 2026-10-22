-- Port discovery is a snapshot, not proof that a process still owns a port at submit time.
-- Load this module with dofile. It creates no processes until scan is called.
local M = {}
-- Labels filter UI choices only. They never authorize adopting or closing a pane.
local function infrastructure(label)
  label = type(label) == 'string' and label or ''
  if label == 'lazyrex-hub' or label == 'lazyrex-dev-process' then return true end
  for _, prefix in ipairs({'lazyrex-plugin:', 'lazyrex-view:', 'lazyrex-form:',
    'lazyrex-placeholder:', 'lazyrex-tunnel:'}) do
    if label:sub(1, #prefix) == prefix then return true end
  end
  return false
end
-- join is table.concat in blocks of 1000 items: Rex Lua fails table.concat of more than about 2559
-- items with "registry overflow" (observed on Rex 0.0.1792158932-g88fd41, lab, 2026-10-22; LazyRex
-- docs/rex-protocol.md).
local function join(list, sep)
  if #list <= 1000 then return table.concat(list, sep) end
  local blocks = {}
  for i = 1, #list, 1000 do blocks[#blocks + 1] = table.concat(list, sep, i, math.min(i + 999, #list)) end
  return join(blocks, sep)
end
local function pid(value)
  local n = tonumber(value)
  if n and n > 0 and n == math.floor(n) then return n end
end
local function detail(err)
  if type(err) == 'table' then return tostring(err.message or err.code or 'request failed') end
  return tostring(err or 'request failed')
end

-- Only the process name is read. Arguments can contain credentials.
function M.parse_ps(output)
  local rows = {}
  for line in output:gmatch('[^\n]+') do
    local p, parent, command = line:match('^%s*(%d+)%s+(%d+)%s+(.+)$')
    if pid(p) then rows[tonumber(p)] = {parent = tonumber(parent), command = command} end
  end
  return rows
end

-- -Fpcn gives one field per line. The numeric port is the final colon component,
-- including for an IPv6 address. lsof already restricts these files to TCP LISTEN.
function M.parse_lsof(output)
  local rows, seen = {}, {}
  local process, command
  for line in output:gmatch('[^\n]+') do
    local field, value = line:sub(1, 1), line:sub(2)
    if field == 'p' then process = pid(value); command = ''
    elseif field == 'c' then command = value
    elseif field == 'n' and process then
      local address, port_text = value:match('^(.*):(%d+)$')
      local port = tonumber(port_text)
      if address and address ~= '' and port and port >= 1 and port <= 65535 then
        local key = tostring(process) .. ':' .. value
        if not seen[key] then
          rows[#rows + 1] = {pid = process, command = command, port = port, address = address}
          seen[key] = true
        end
      end
    end
  end
  return rows
end

-- Walk toward the nearest pane root. A nested pane must not be assigned to its ancestor.
local function owner(process, roots, processes)
  local seen = {}
  while process and not seen[process] do
    if roots[process] then return roots[process] end
    seen[process] = true
    process = processes[process] and processes[process].parent
  end
end

function M.scan(current_session, api)
  api = api or rex
  local result = {ports = {}, warnings = {}}
  local function warn(message) result.warnings[#result.warnings + 1] = message end
  local function call(method, args)
    local value, err = api.call(method, args)
    if not value then warn(method .. ': ' .. detail(err)) end
    return value
  end
  local sessions = call('session.list', {})
  if not sessions then return result end
  local roots = {}
  for _, session in ipairs(sessions.sessions or {}) do
    local sid = session.session_id
    if call('session.attach', {session_id = sid, event_scope = 'session'}) then
      local blocks = call('session.list_blocks', {session_id = sid})
      local view = call('session.view', {session_id = sid})
      local tabs = {}
      for _, window in ipairs(view and view.windows or {}) do tabs[window.window_id] = window.label end
      for _, block in ipairs(blocks and blocks.blocks or {}) do
        if block.creator_name == 'com.superlogical.terminal' or block.flavor == 'com.superlogical.terminal.shell' then
          local process = call('com.superlogical.terminal.process', {session_id = sid, block_id = block.block_id, args = {}})
          local child = process and process.child and pid(process.child.pid)
          if child then
            roots[child] = {session_id = sid, window_id = block.window_id or '', block_id = block.block_id,
              tab = tabs[block.window_id] or '', excluded = infrastructure(block.label)}
          end
        end
      end
    end
  end
  if not next(roots) then return result end
  local ps, err = api.exec({'/bin/ps', '-axo', 'pid=,ppid=,comm='}, {timeout = 3})
  if not ps or not ps.ok then warn('ps: ' .. detail(err or (ps and ps.stderr))); return result end
  local processes = M.parse_ps(ps.stdout or '')
  local owners, selected = {}, {}
  for process in pairs(processes) do
    local pane = owner(process, roots, processes)
    if pane and not pane.excluded then owners[process] = pane; selected[#selected + 1] = process end
  end
  table.sort(selected)
  for i, process in ipairs(selected) do selected[i] = tostring(process) end
  -- An empty -p selection must never become a machine-wide listener scan.
  if #selected == 0 then return result end
  local sockets
  sockets, err = api.exec({'/usr/sbin/lsof', '-nP', '-a', '-p', join(selected, ','), '-iTCP', '-sTCP:LISTEN', '-Fpcn'}, {timeout = 3})
  if not sockets then warn('lsof: ' .. detail(err)); return result end
  -- lsof exits 1 when no selected process has a listening socket.
  if sockets.timed_out or (not sockets.ok and sockets.code ~= 1) then
    warn('lsof: ' .. (sockets.timed_out and 'scan timed out' or detail(sockets.stderr)))
    return result
  end
  if sockets.stderr and sockets.stderr ~= '' then warn('lsof: ' .. sockets.stderr) end
  for _, socket in ipairs(M.parse_lsof(sockets.stdout or '')) do
    local pane = owners[socket.pid]
    if pane then
      result.ports[#result.ports + 1] = {session_id = pane.session_id, window_id = pane.window_id,
        block_id = pane.block_id, tab = pane.tab, pid = socket.pid,
        command = processes[socket.pid].command, port = socket.port, address = socket.address}
    end
  end
  table.sort(result.ports, function(a, b)
    if (a.session_id == current_session) ~= (b.session_id == current_session) then return a.session_id == current_session end
    for _, key in ipairs({'session_id', 'tab', 'window_id', 'block_id', 'port', 'address', 'pid'}) do
      if a[key] ~= b[key] then return a[key] < b[key] end
    end
    return false
  end)
  return result
end
return M
