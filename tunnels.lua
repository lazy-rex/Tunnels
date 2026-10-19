-- Tunnels: forward a local TCP port with opentunnel (the maintainer, 2026-10-17; docs/decisions.md, "Side panels
-- and the Tunnels plugin"). One forward is one detached Rex block in the session of the forwarded
-- process. The block runs tunnels-run.sh, which runs `opentunnel serve` in the foreground, so the
-- block owns the tunnel: Stop closes the block, and closing the session ends the tunnel.
--
-- State (README, "Tunnels"): one hub.store record "forwards" = {intents = {[op key] = intent},
-- forwards = {[block ID] = forward}, cleanups = {[profile] = true}}. The intent is saved as "sending" before session.new_block, and
-- the create is sent once. The forward, the intent removal and the operation result commit in one
-- batch. A label is only a discovery hint (architecture.md). An intent with an unknown create
-- result is adopted only with process proof: exactly one block in its session has the label
-- lazyrex-tunnel:<op key>, its process argv carries the op key, and the process started after the
-- intent was saved. Otherwise the panel shows it as unknown, and it keeps its port until it is proven
-- or its session closes. A block or session that is absent from a successful Rex listing means a
-- stopped tunnel.
-- Cleanup: `opentunnel up` registers a launchd service before tunnels-run.sh runs `down`. A run that
-- is killed between them leaves that service. So when a forward or intent ends, the same write
-- records its profile in cleanups. The plugin runs tunnels-down.sh for it in a detached block of the
-- plugin session, so the attempt outlives a plugin restart and Rex shows whether it still runs.
-- The cleanup record owns the profile until Rex shows an exit code of 0: Forward refuses the port
-- while the record exists, because a running `down` would also stop a new `serve` of the profile.
local hub_id = assert(rex.args.hub_client_id, 'hub_client_id is required')
local instance_id = assert(rex.args.instance_id, 'instance_id is required')
local plugin_session = assert(rex.args.plugin_session or rex.session_id, 'plugin_session is required')
local function fail(code, message) error({code = code, message = message}) end
local plugin_dir = assert(debug.getinfo(1, 'S').source:match('^@?(/.*)/[^/]*$'), 'The plugin path is unknown')
-- Lab only: another profile prefix keeps lab tunnels apart from real ones. XDG directories cannot
-- isolate a lab: the launchd service that `opentunnel up` registers gets no XDG variables (0.5.2).
-- The hub config passes no plugin arguments. A lab sets these in the lab server's environment,
-- which its panes inherit (spikes/lab/server.sh).
local profile_prefix = os.getenv('LAZYREX_TUNNELS_PROFILE_PREFIX') or 'lazyrex-'
local label_prefix = 'lazyrex-tunnel:'
-- A Rex pane does not get a login PATH, so look for the binary in the usual install places.
local function find_opentunnel()
  local configured = os.getenv('LAZYREX_TUNNELS_OPENTUNNEL')
  if configured and configured ~= '' then return configured end
  local home = os.getenv('HOME') or ''
  for _, path in ipairs({'/opt/homebrew/bin/opentunnel', '/usr/local/bin/opentunnel', home .. '/.cargo/bin/opentunnel', home .. '/.local/bin/opentunnel'}) do
    local r = rex.exec({'/bin/test', '-x', path}, {timeout = 5})
    if r and r.ok then return path end
  end
end

local function hub(action, args)
  local response, err = rex.call('client.perform', {client_id = hub_id, action = action, args = args or {}, timeout_ms = 10000})
  if type(response) ~= 'table' or type(response.result) ~= 'table' then
    if type(err) == 'table' then fail(err.code or 'unavailable', err.message or 'Hub request failed') end
    fail('unavailable', tostring(err or 'Invalid hub result'))
  end
  return response.result
end
local function rex_ok(method, args)
  local result, err = rex.call(method, args)
  if not result then fail('unavailable', type(err) == 'table' and err.message or tostring(err)) end
  return result
end
local function invalidate() pcall(hub, 'hub.ui.invalidate', {}) end
local function message(err) return type(err) == 'table' and (err.message or err.code) or tostring(err) end

-- Port discovery is Codex's module. The form scans once per session and keeps the result until
-- the user asks for a rescan, so an unrelated render does not run ps and lsof again.
local scans = {}
local function scan(session_id)
  local key = session_id or ''
  if scans[key] then return scans[key] end
  local ok, ports = pcall(dofile, plugin_dir .. '/tunnels_ports.lua')
  local result
  if not ok then result = {ports = {}, warnings = {'Port discovery is unavailable: ' .. message(ports)}}
  else
    local done, r = pcall(ports.scan, session_id)
    result = done and r or {ports = {}, warnings = {'Port discovery failed: ' .. message(r)}}
  end
  scans[key] = result
  return result
end

local function catalog()
  local r = hub('hub.store.get', {keys = {'forwards'}}).records.forwards
  if not r or type(r.rev) ~= 'string' then fail('internal', 'Missing forward catalog') end
  local value = r.value or {}
  value.intents, value.forwards, value.cleanups = value.intents or {}, value.forwards or {}, value.cleanups or {}
  return value, r.rev
end
-- update applies f to the current catalog and saves it, with the operation result op if given.
-- It tries again after a revision conflict.
local function update(f, op)
  for _ = 1, 5 do
    local state, rev = catalog()
    f(state)
    local args = {ops = {{key = 'forwards', if_rev = rev, value = state}}}
    if op then args.op = op end
    local result = hub('hub.store.batch', args)
    if not result.conflict then return result end
  end
  fail('conflict', 'The forward list keeps changing; retry with the same key')
end

local function valid_port(value)
  local n = tonumber(value)
  if not n or n % 1 ~= 0 or n < 1 or n > 65535 then fail('invalid_input', 'A port is a whole number from 1 to 65535') end
  return math.floor(n)
end
-- target is the address that opentunnel connects to, from the listening address that lsof gave.
-- A wildcard listener is reached on loopback of its family; a concrete address is kept.
local function target(address, port)
  if address == '*' or address == '0.0.0.0' then return '127.0.0.1:' .. port end
  if address == '[::]' then return '[::1]:' .. port end
  if address:match('^%d+%.%d+%.%d+%.%d+$') then return address .. ':' .. port end
  if address:match('^%[[%x:%.]+%]$') then return address .. ':' .. port end
  fail('invalid_input', 'Unsupported listening address ' .. address)
end

-- Rex reads fail when Rex does not answer. blocks_of answers false when the session is gone.
local function sessions()
  local set = {}
  for _, s in ipairs(rex_ok('session.list', {}).sessions or {}) do set[s.session_id] = s end
  return set
end
local function blocks_of(session_id, known)
  if not known[session_id] then return false end
  if session_id ~= plugin_session then pcall(rex.call, 'session.attach', {session_id = session_id, event_scope = 'session'}) end
  local by_id = {}
  for _, b in ipairs(rex_ok('session.list_blocks', {session_id = session_id}).blocks or {}) do by_id[b.block_id] = b end
  return by_id
end
-- proven answers the block labeled label when Rex shows that its process is a run of script with
-- key in argv that started at or after saved_at, else nil.
local function proven(by_id, label, key, saved_at, session_id, script)
  local found
  for _, b in pairs(by_id) do
    if b.label == label then
      if found then return nil end -- several candidates: no proof
      found = b
    end
  end
  if not found then return nil end
  local process = rex.call('com.superlogical.terminal.process', {session_id = session_id, block_id = found.block_id, args = {}})
  local pid = process and process.child and tonumber(process.child.pid)
  if not pid then return nil end
  -- argv of the run script (a platform binary shows argv to ps) and the elapsed time since start.
  local r = rex.exec({'/bin/ps', '-o', 'etime=', '-o', 'command=', '-p', tostring(pid)}, {timeout = 3})
  if not r or not r.ok then return nil end
  local etime, command = (r.stdout or ''):match('^%s*(%S+)%s+(.-)%s*$')
  if not command or not command:find(' ' .. key .. ' ', 1, true) or not command:find(script, 1, true) then return nil end
  local days, rest = etime:match('^(%d+)-(.*)$')
  local parts = {}
  for n in (rest or etime):gmatch('%d+') do parts[#parts + 1] = tonumber(n) end
  local seconds = 0
  for _, n in ipairs(parts) do seconds = seconds * 60 + n end
  seconds = seconds + (tonumber(days) or 0) * 86400
  -- One second of slack for clock rounding. A process older than the intent is not this create.
  if type(saved_at) ~= 'number' or os.time() - seconds < saved_at - 1 then return nil end
  return found
end

local done_result = {panel = {command = 'tunnels'}}
-- commit turns intent id into the forward of block_id, with the operation result, in one batch.
local function commit(id, intent, block_id)
  update(function(s)
    s.intents[id] = nil
    s.forwards[block_id] = {session_id = intent.session_id, source_block = intent.source_block, port = intent.port,
      target = intent.target, profile = intent.profile, op = id, created = intent.created}
  end, {key = id, fingerprint = intent.fingerprint, result = done_result})
end
-- drop removes intent id and records the operation result, so a retry never creates again.
local function drop(id, intent, result)
  update(function(s) s.intents[id] = nil; s.cleanups[intent.profile] = s.cleanups[intent.profile] or {phase = 'new'} end, {key = id, fingerprint = intent.fingerprint, result = result})
end

local cleanup_errors = {} -- profile -> the last failure, shown in the panel
local cleanup_seq = 0
local down_prefix = 'lazyrex-tunnel-down:'
local maintain
-- advance_cleanups moves each cleanup one step: new -> sending (saved before session.new_block) ->
-- running (block known) -> done (exit 0: the record is removed) or retry (after 5 s). A running block
-- that disappears is retried: its process ended with the block. A sending record with an unknown
-- create result is adopted only with process proof, as for intents. It answers whether work remains.
local function set_cleanup(profile, f)
  update(function(s) if s.cleanups[profile] then f(s.cleanups[profile]) end end)
end
local function advance_cleanups()
  local state = catalog()
  if not next(state.cleanups) then return false end
  local by_id = blocks_of(plugin_session, sessions())
  local now = os.time()
  for profile, c in pairs(state.cleanups) do
    if type(c) ~= 'table' then c = {phase = 'new'} end
    if c.phase == 'running' then
      local block = by_id and by_id[c.block_id]
      if by_id and not block then
        set_cleanup(profile, function(x) x.phase, x.block_id, x.retry_at = 'retry', nil, now end)
      elseif block then
        local process = rex.call('com.superlogical.terminal.process', {session_id = plugin_session, block_id = c.block_id, args = {}})
        if process and not process.child and process.last_exit then
          pcall(rex.call, 'block.close', {session_id = plugin_session, block_id = c.block_id})
          if process.last_exit.exit_code == 0 then
            cleanup_errors[profile] = nil
            update(function(s) s.cleanups[profile] = nil end)
            invalidate()
          else
            cleanup_errors[profile] = process.last_exit.error or ('exit code ' .. tostring(process.last_exit.exit_code))
            set_cleanup(profile, function(x) x.phase, x.block_id, x.retry_at = 'retry', nil, now + 5 end)
          end
        end
      end
    elseif c.phase == 'sending' then
      local block = by_id and proven(by_id, down_prefix .. c.key, c.key, c.saved_at, plugin_session, 'tunnels-down.sh')
      if block then set_cleanup(profile, function(x) x.phase, x.block_id = 'running', block.block_id end)
      elseif not by_id then set_cleanup(profile, function(x) x.phase, x.retry_at = 'retry', now end) end
      -- Otherwise the create result stays unknown: the profile stays owned.
    elseif c.phase == 'new' or (c.phase == 'retry' and now >= (c.retry_at or 0)) then
      local opentunnel = find_opentunnel()
      if not opentunnel then cleanup_errors[profile] = 'opentunnel is not installed'
      else
        cleanup_seq = cleanup_seq + 1
        local key = instance_id .. '-' .. now .. '-' .. cleanup_seq
        set_cleanup(profile, function(x) x.phase, x.key, x.saved_at, x.block_id = 'sending', key, now, nil end)
        local created = rex.call('session.new_block', {session_id = plugin_session, flavor = 'com.superlogical.terminal.shell',
          label = down_prefix .. key, options = {command = {'/bin/sh', plugin_dir .. '/tunnels-down.sh', key, opentunnel, profile},
          login = false, exit = {on_completion = false}}})
        if created and created.block_id then
          set_cleanup(profile, function(x) if x.key == key then x.phase, x.block_id = 'running', created.block_id end end)
        end
      end
    end
  end
  return true
end

-- reconcile reads Rex and returns the panel rows. It resolves intents by their labels, records
-- URLs, and removes forwards that have stopped. A failed Rex read raises and changes nothing.
local function reconcile()
  local state = catalog()
  local known = sessions()
  local cache = {}
  local function blocks(session_id)
    if cache[session_id] == nil then cache[session_id] = blocks_of(session_id, known) end
    return cache[session_id]
  end
  local rows, gone, urls = {}, {}, {}
  for id, intent in pairs(state.intents) do
    local by_id = blocks(intent.session_id)
    local block = by_id and proven(by_id, label_prefix .. id, id, intent.saved_at, intent.session_id, 'tunnels-run.sh')
    if not by_id then drop(id, intent, {error = {code = 'not_found', message = 'The session closed before the tunnel started'}})
    elseif block then
      commit(id, intent, block.block_id)
      state.forwards[block.block_id] = {session_id = intent.session_id, source_block = intent.source_block, port = intent.port, profile = intent.profile, op = id, created = intent.created}
    else
      rows[#rows + 1] = {intent_id = id, fw = intent, state = 'Unknown start result'}
    end
  end
  for block_id, fw in pairs(state.forwards) do
    local by_id = blocks(fw.session_id)
    local block = by_id and by_id[block_id]
    if not block then gone[block_id] = true
    else
      local row = {block_id = block_id, fw = fw, block = block, url = fw.url}
      local process = rex.call('com.superlogical.terminal.process', {session_id = fw.session_id, block_id = block_id, args = {}})
      local screen = rex.call('com.superlogical.terminal.format', {session_id = fw.session_id, block_id = block_id, args = {format = 'text', trim = true, unwrap = true}})
      local text = screen and type(screen.content) == 'string' and screen.content or ''
      if not fw.url then
        local url = text:match('lazyrex%-tunnel%-url: (https://[%w%.%-]+)')
        if url then urls[block_id] = url; row.url = url end
      end
      if process and process.child then
        -- A live process is not a live connection. The serve log names its last connection event
        -- (opentunnel 0.5.2: event={"type":"connecting"|"connected",...}). A new profile first waits
        -- for certificate verification, which took about a minute in the lab (2026-10-17).
        local event
        for t in text:gmatch('"type":"(%a+)"') do event = t end
        if event then row.state = event:sub(1, 1):upper() .. event:sub(2)
        elseif not row.url then row.state = text:find('Waiting for certificate', 1, true) and 'Creating tunnel (can take minutes)' or 'Starting'
        else row.state = 'Starting' end
      elseif process and process.last_exit then
        row.state = 'Failed (' .. (process.last_exit.error or ('exit code ' .. tostring(process.last_exit.exit_code))) .. ')'
      elseif process then row.state = 'Starting'
      else row.state = 'Unknown' end
      rows[#rows + 1] = row
    end
  end
  if next(gone) or next(urls) then
    update(function(s)
      for block_id, url in pairs(urls) do if s.forwards[block_id] then s.forwards[block_id].url = url end end
      for block_id in pairs(gone) do
        local fw = s.forwards[block_id]
        if fw then s.cleanups[fw.profile] = s.cleanups[fw.profile] or {phase = 'new'}; s.forwards[block_id] = nil end
      end
    end)
    invalidate()
  end
  table.sort(rows, function(a, b) return (a.fw.created or '') < (b.fw.created or '') end)
  return rows
end

-- Maintenance is owned by the plugin, not by open views: it runs at start, after Rex events and
-- after Forward and Stop, and again on a timer while work remains: every second while a cleanup
-- runs or waits, every 10 s while forwards or intents exist (a missed event is found then).
local maintain_timer, kick_pending, maintaining
local function schedule(delay)
  if maintain_timer then return end
  maintain_timer = rex.after(delay, function() maintain_timer = nil; maintain() end)
end
maintain = function()
  if maintaining then return end
  maintaining = true
  local ok, work = pcall(function()
    local state = catalog()
    if next(state.forwards) or next(state.intents) then reconcile() end
    local cleanup = advance_cleanups()
    state = catalog()
    return {cleanup = cleanup, live = next(state.forwards) ~= nil or next(state.intents) ~= nil}
  end)
  maintaining = false
  if not ok then schedule(5)
  elseif work.cleanup then schedule(1)
  elseif work.live then schedule(10) end
end
local function kick()
  if kick_pending then return end
  kick_pending = true
  rex.after(0.1, function() kick_pending = false; maintain() end)
end

local function result_of(saved, fingerprint)
  if saved.fingerprint ~= fingerprint then fail('operation_conflict', 'This key has different content') end
  if type(saved.result) == 'table' and saved.result.error then fail(saved.result.error.code, saved.result.error.message) end
  return saved.result
end

local function forward(args)
  local id = args.operation_key
  if type(id) ~= 'string' or not id:match('^[%w%-_%.:]+$') or #id > 100 then fail('invalid_input', 'Invalid operation key') end
  local values = type(args.input) == 'table' and type(args.input.values) == 'table' and args.input.values or {}
  local ctx = type(args.context) == 'table' and args.context or {}
  local choice = type(values.port) == 'string' and values.port or ''
  local other = type(values.other) == 'string' and values.other or ''
  local fingerprint = 'forward/' .. #choice .. ':' .. choice .. '/' .. #other .. ':' .. other .. '/' .. tostring(ctx.session_id)
  local saved = hub('hub.store.op', {key = id})
  if saved.found then return result_of(saved, fingerprint) end
  local state = catalog()
  local intent = state.intents[id]
  if intent then
    if intent.fingerprint ~= fingerprint then fail('operation_conflict', 'This key has different content') end
    -- Sent before with an unknown result: never send it again. Look for its block.
    local by_id = blocks_of(intent.session_id, sessions())
    if not by_id then drop(id, intent, {error = {code = 'not_found', message = 'The session closed before the tunnel started'}}); fail('not_found', 'The session closed before the tunnel started') end
    local block = proven(by_id, label_prefix .. id, id, intent.saved_at, intent.session_id, 'tunnels-run.sh')
    if not block then fail('unresolved', 'The tunnel block has an unknown start result; a late Rex reply can still create it') end
    commit(id, intent, block.block_id)
    invalidate()
    return done_result
  end
  if choice ~= '' and choice ~= 'other' then
    local session_id, block_id, port, address = choice:match('^([^|]+)|([^|]*)|(%d+)|(.*)$')
    if not session_id then fail('invalid_input', 'Select a port') end
    port = valid_port(port)
    intent = {session_id = session_id, source_block = block_id ~= '' and block_id or nil, port = port, target = target(address, port)}
  else
    if type(ctx.session_id) ~= 'string' or ctx.session_id == '' then fail('invalid_input', 'The form has no session') end
    local port = valid_port(other)
    -- "Other port…" has no process: the source is the pane that ran the palette command.
    intent = {session_id = ctx.session_id, source_block = ctx.source_block_id ~= '' and ctx.source_block_id or nil, port = port, target = '127.0.0.1:' .. port}
  end
  if not sessions()[intent.session_id] then fail('not_found', 'The session of this port is closed') end
  -- Check the binary before the intent is saved: a request that is never sent must not hold a port.
  local opentunnel = find_opentunnel()
  if not opentunnel then fail('not_found', 'opentunnel is not installed. Install it with: brew install anomalyco/tap/opentunnel') end
  intent.profile = profile_prefix .. intent.port
  intent.fingerprint = fingerprint
  intent.created = os.date('!%Y-%m-%dT%H:%M:%SZ')
  intent.saved_at = os.time()
  intent.phase = 'sending'
  -- Drop stopped forwards first, so a closed session does not hold its port. A failed read keeps them.
  pcall(reconcile)
  -- One profile runs once (opentunnel holds a profile lock): refuse a second forward of the port.
  update(function(s)
    for _, list in ipairs({s.forwards, s.intents}) do
      for _, other_fw in pairs(list) do
        if other_fw.port == intent.port then fail('conflict', 'Port ' .. intent.port .. ' is already forwarded. Stop that forward first.') end
      end
    end
    -- A cleanup can still run `down` for this profile, which would stop the new `serve`.
    if s.cleanups[intent.profile] then fail('conflict', 'Port ' .. intent.port .. ' is still stopping its previous tunnel. Try again in a moment.') end
    s.intents[id] = intent
  end)
  local command = {'/bin/sh', plugin_dir .. '/tunnels-run.sh', id, opentunnel, intent.profile, intent.target}
  local created, err = rex.call('session.new_block', {session_id = intent.session_id, flavor = 'com.superlogical.terminal.shell',
    label = label_prefix .. id, options = {command = command, login = false, exit = {on_completion = false}}})
  if not (created and created.block_id) then
    -- The outcome can be unknown. The intent stays; the panel shows it and looks for its label.
    invalidate()
    fail('unavailable', 'Rex did not confirm the tunnel block: ' .. message(err))
  end
  commit(id, intent, created.block_id)
  invalidate()
  kick()
  return done_result
end

local function panel_action(args)
  local input = type(args.input) == 'table' and args.input or {}
  local item = input.item_id
  local block_id = type(args.node_id) == 'string' and args.node_id:match('^fw/(.+)$')
  if not block_id then fail('invalid_input', 'Unknown Tunnels action') end
  local fw = catalog().forwards[block_id]
  -- A repeated Stop after a lost reply finds the forward gone: the stop succeeded.
  if not fw then if item == 'stop' then return {} end fail('not_found', 'This forward has stopped') end
  local by_id = blocks_of(fw.session_id, sessions())
  local block = by_id and by_id[block_id]
  if item == 'stop' then
    if block then rex_ok('block.close', {session_id = fw.session_id, block_id = block_id}) end
    update(function(s) if s.forwards[block_id] then s.cleanups[fw.profile] = s.cleanups[fw.profile] or {phase = 'new'}; s.forwards[block_id] = nil end end)
    kick()
  elseif not block then
    fail('not_found', 'This forward has stopped')
  elseif item == 'show' then
    -- Show and Hide check the placement first, so a repeat after a lost reply changes nothing.
    if block.placement == 'detached' then
      local anchor = fw.source_block and by_id[fw.source_block]
      if not anchor or anchor.placement ~= 'placed' then fail('refused', 'The source pane is closed or hidden. Show Logs needs it.') end
      rex_ok('session.move_block', {session_id = fw.session_id, block_id = block_id, anchor_block_id = fw.source_block, direction = 'vertical', side = 'after', ratio = 0.7})
    end
  elseif item == 'hide' then
    if block.placement ~= 'detached' then rex_ok('session.detach_block', {session_id = fw.session_id, block_id = block_id}) end
  else
    fail('invalid_input', 'Unknown Tunnels action')
  end
  invalidate()
  return {}
end

local function render_form(args)
  local ctx = type(args.context) == 'table' and args.context or {}
  local result = scan(ctx.session_id)
  local options = {}
  for _, p in pairs(result.ports or {}) do
    local where = (type(p.tab) == 'string' and p.tab ~= '') and p.tab or 'detached pane'
    options[#options + 1] = {value = p.session_id .. '|' .. (p.block_id or '') .. '|' .. tostring(p.port) .. '|' .. (p.address or ''),
      label = tostring(p.port) .. ' · ' .. (tostring(p.command or '?'):match('([^/]+)$') or '?') .. ' · ' .. where .. ' · ' .. (p.address or '')
        .. (p.session_id ~= ctx.session_id and ' · other session' or '')}
  end
  options[#options + 1] = {value = 'other', label = 'Other port…'}
  local nodes = {}
  local warnings = {}
  for _, w in pairs(result.warnings or {}) do warnings[#warnings + 1] = tostring(w) end
  for i, w in ipairs(warnings) do nodes[#nodes + 1] = {id = 'warning/' .. i, type = 'widget', text = w} end
  if #options == 1 then nodes[#nodes + 1] = {id = 'none', type = 'widget', text = 'No listening TCP ports were found in the panes.'} end
  nodes[#nodes + 1] = {id = 'forward', type = 'form', label = 'Forward a port', fields = {
    {id = 'port', label = 'Port', kind = 'select', required = true, value = options[1].value, options = options},
    {id = 'other', label = 'Other port (for "Other port…")', kind = 'text', required = false, value = ''},
  }, submit_action = {name = 'forward', label = 'Forward', enabled = true}}
  nodes[#nodes + 1] = {id = 'rescan', type = 'widget', text = 'The list is from the last scan.', action = {name = 'rescan', label = 'Rescan', enabled = true}}
  nodes[#nodes + 1] = {id = 'notice', type = 'widget', text = 'Anyone with the URL can reach the port. The tunnel does not ask visitors to sign in.'}
  return {title = 'Forward Port', nodes = nodes}
end

-- Rex sends no event while opentunnel starts or reconnects, so the panel renders again on a timer
-- while forwards exist: every 2 s until each one is connected, then every 15 s.
local refresh_timer
local function arm_refresh(delay)
  if refresh_timer then return end
  refresh_timer = rex.after(delay, function() refresh_timer = nil; invalidate() end)
end
local function render_panel()
  local ok, rows = pcall(reconcile)
  local nodes = {}
  if not ok then
    nodes[#nodes + 1] = {id = 'error', type = 'widget', text = 'Could not read the tunnels: ' .. message(rows)}
    rows = {}
  end
  local names = {}
  if ok then for id, s in pairs(sessions()) do names[id] = s.label or id end end
  local running = 0
  for _, row in ipairs(rows) do
    local fw = row.fw
    local items, node_id = {}, nil
    if row.block then
      node_id = 'fw/' .. row.block_id
      local shown = row.block.placement ~= 'detached'
      local name = shown and 'hide' or 'show'
      items[#items + 1] = {id = name, label = shown and 'Hide Logs' or 'Show Logs', detail = '', action = {name = name, label = shown and 'Hide Logs' or 'Show Logs', enabled = true}}
      items[#items + 1] = {id = 'stop', label = 'Stop', detail = '', action = {name = 'stop', label = 'Stop', enabled = true}}
    else
      -- No action: the port stays reserved until Rex proves the block or the session closes.
      node_id = 'intent/' .. row.intent_id
      items[#items + 1] = {id = 'unknown', label = 'Waiting for Rex', detail = 'The tunnel block may still start. The port stays reserved until it does or its session closes.'}
    end
    if row.state == 'Connected' then running = running + 1 end
    nodes[#nodes + 1] = {id = node_id, type = 'list',
      label = 'Port ' .. fw.port .. ' · ' .. row.state .. ' · ' .. (row.url or 'no URL yet') .. ' · ' .. (names[fw.session_id] or fw.session_id),
      items = items}
  end
  local pending = {}
  local cok, state = pcall(catalog)
  if cok then for profile in pairs(state.cleanups) do pending[#pending + 1] = profile end end
  table.sort(pending)
  for _, profile in ipairs(pending) do
    nodes[#nodes + 1] = {id = 'cleanup/' .. profile, type = 'widget', text = 'Stopping the opentunnel service of ' .. profile
      .. (cleanup_errors[profile] and (' (failed, retrying: ' .. cleanup_errors[profile] .. ')') or '')}
  end
  if #rows == 0 and #pending == 0 and ok then nodes[#nodes + 1] = {id = 'empty', type = 'widget', text = 'No ports are forwarded.'} end
  if #rows > 0 or #pending > 0 then arm_refresh((running < #rows or #pending > 0) and 2 or 15) end
  kick()
  nodes[#nodes + 1] = {id = 'new', type = 'widget', text = 'Forward a port from a pane', action = {name = 'new', label = 'Forward Port…', enabled = true}}
  return {title = running > 0 and ('Tunnels (' .. running .. ' connected)') or 'Tunnels', nodes = nodes}
end

local function render(args)
  if args.route == '/panels/tunnels' then return render_panel() end
  if args.route == '/forms/forward' then return render_form(args) end
  fail('not_found', 'Unknown route')
end
local function perform(args)
  if args.route == '/forms/forward' and args.node_id == 'forward' and args.action == 'forward' then return forward(args) end
  if args.route == '/forms/forward' and args.node_id == 'rescan' then
    local ctx = type(args.context) == 'table' and args.context or {}
    scans[ctx.session_id or ''] = nil
    invalidate()
    return {}
  end
  if args.route == '/panels/tunnels' and args.node_id == 'new' then return {form = '/forms/forward'} end
  if args.route == '/panels/tunnels' then return panel_action(args) end
  fail('invalid_input', 'Unknown Tunnels action')
end

local handlers = {
  ['view.render'] = function(args) return {tree = render(args)} end,
  ['view.action'] = perform,
  ['view.seen'] = function() return {} end,
  ['hub.changed'] = function() return {} end,
}
local actions = {}
for name in pairs(handlers) do actions[#actions + 1] = {name = name, kind = 'client', title = name,
  args = {type = 'object', additionalProperties = true}} end
rex.call('client.keymap', {actions = actions})
hub('hub.register', {plugin = 'tunnels', instance_id = instance_id, exports = {}, commands = {
  {id = 'tunnels', title = 'Tunnels', description = 'Show forwarded ports', keywords = {'tunnel', 'port', 'opentunnel'}, route = '/panels/tunnels', surface = 'panel', landing = true},
  {id = 'forward_port', title = 'Forward Port…', description = 'Share a local port with a public URL', keywords = {'tunnel', 'port', 'share', 'opentunnel'}, route = '/forms/forward'},
}})
-- A tunnel block that exits or closes, or a closed session, changes the panel.
rex.on('terminal.child_exited', function() invalidate(); kick() end)
rex.on('block_closed', function() invalidate(); kick() end)
rex.on('session_closed', function() invalidate(); kick() end)
rex.on('client_perform_requested', function(ctx, ev)
  local ok, result = pcall(function()
    if not ev.requester or ev.requester.client_id ~= hub_id then fail('refused', 'Only the hub calls Tunnels actions') end
    local handler = handlers[ev.action]
    if not handler then fail('not_supported', 'Unknown Tunnels action') end
    local args = ev.args or {}
    if ev.action ~= 'hub.changed' and args.user ~= 'user' then fail('refused', 'Unknown user') end
    return handler(args)
  end)
  if ok then rex.call('client.reply', {call_id = ev.call_id, result = result})
  else rex.call('client.reply', {call_id = ev.call_id, error = type(result) == 'table' and result or {code = 'internal', message = tostring(result)}}) end
end)
rex.call('client.set_label', {label = 'lazyrex-plugin:tunnels'})
-- Work left by an earlier instance (a pending cleanup, a forward whose session closed) goes on now.
kick()
