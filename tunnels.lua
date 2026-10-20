-- Tunnels: forward a local TCP port with opentunnel (the maintainer, 2026-10-17; decision "Side panels and
-- the Tunnels plugin"). One forward is one detached Rex block in the session of the forwarded
-- process. The block runs tunnels-run.sh, which runs `opentunnel serve` in the foreground, so the
-- block owns the tunnel: Stop closes the block, and closing the session ends the tunnel.
--
-- State (README, "Tunnels"): one hub.store record "forwards" = {intents = {[op key] = intent},
-- forwards = {[block ID] = forward}, cleanups = {[profile] = cleanup}, stops = {[op key] = stop}}. The intent is saved as "sending" before session.new_block, and
-- the create is sent once. The forward, the intent removal and the operation result commit in one
-- batch. A label is only a discovery hint (architecture.md). An intent with an unknown create
-- result is adopted only with process proof: exactly one block in its session has the label
-- lazyrex-tunnel:<op key> (label_of: a digest for an agent key), its process argv carries the op key, and the process started after the
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
-- The hub config passes no plugin arguments. A lab sets these in the environment of the hub, which
-- its plugins inherit (lazyrex.json "env"). A prefix ends with '-', so a profile name ends with the port.
local default_prefix = 'lazyrex-'
local profile_prefix = os.getenv('LAZYREX_TUNNELS_PROFILE_PREFIX') or default_prefix
assert(profile_prefix:match('^[%w_][%w_%-]*%-$'), 'LAZYREX_TUNNELS_PROFILE_PREFIX must be letters, digits, _ or - and end with -')
local label_prefix = 'lazyrex-tunnel:'
-- label_of answers the block label of Forward operation id. Rex refuses a label over 128
-- characters (bad_request, Rex 0.0.1792158932-g88fd41). A user ID (at most 100 characters) is in
-- the label as before. An agent ID (fwd/...) can be longer, so its label has a 64-bit digest of the
-- ID. A label is only a discovery hint: the proof is the full ID in the process argv (proven()).
local function label_of(id)
  if id:sub(1, 4) ~= 'fwd/' then return label_prefix .. id end
  local a, b = 0, 0
  for i = 1, #id do
    local c = id:byte(i)
    a = (a * 31 + c) % 4294967296
    b = (b * 131 + c) % 4294967291
  end
  return label_prefix .. string.format('fwd-%08x%08x', a, b)
end
local function executable(path) local r = rex.exec({'/bin/test', '-x', path}, {timeout = 5}); return r and r.ok end
-- find_opentunnel answers the binary, or nil and the reason. A configured binary must be an absolute
-- executable path. A lab prefix uses only the stand-in of this checkout, plugin_dir/tests/fake-opentunnel.sh,
-- by its exact path: a lab never reaches the real opentunnel. A Rex pane does not get a login PATH, so without a configured
-- binary the plugin looks in the usual install places.
local function find_opentunnel()
  local configured = os.getenv('LAZYREX_TUNNELS_OPENTUNNEL')
  if configured and configured ~= '' then
    if configured:sub(1, 1) ~= '/' or not executable(configured) then return nil, 'LAZYREX_TUNNELS_OPENTUNNEL must be an absolute path to an executable' end
    if profile_prefix ~= default_prefix and configured ~= plugin_dir .. '/tests/fake-opentunnel.sh' then return nil, 'A lab profile prefix needs the fake opentunnel' end
    return configured
  end
  if profile_prefix ~= default_prefix then return nil, 'A lab profile prefix needs the fake opentunnel' end
  local home = os.getenv('HOME') or ''
  for _, path in ipairs({'/opt/homebrew/bin/opentunnel', '/usr/local/bin/opentunnel', home .. '/.cargo/bin/opentunnel', home .. '/.local/bin/opentunnel'}) do
    if executable(path) then return path end
  end
  return nil, 'opentunnel is not installed. Install it with: brew install anomalyco/tap/opentunnel'
end

-- text_error raises a Rex or hub error that Rex Lua gave as text. Observed on Rex
-- 0.0.1792158932-g88fd41 (lab): the text ends with "(status=<n> code=<code>)". Keep the code: a
-- refusal is final. Only an error with no code, or with unavailable, disconnected or timeout (a lost
-- or timed-out call), is unavailable, so the caller retries it.
local function text_error(err, default)
  local text = tostring(err or default)
  local code = text:match('code=([%w_]+)%)$')
  if not code or code == 'unavailable' or code == 'disconnected' or code == 'timeout' then fail('unavailable', text) end
  fail(code, text:match('failed: (.-) %(status=%d+ code=[%w_]+%)$') or text)
end

local function hub(action, args)
  local response, err = rex.call('client.perform', {client_id = hub_id, action = action, args = args or {}, timeout_ms = 10000})
  if type(response) ~= 'table' then
    if type(err) == 'table' then fail(err.code or 'unavailable', err.message or 'Hub request failed') end
    text_error(err, 'Hub request failed')
  end
  if type(response.result) ~= 'table' then fail('internal', 'Invalid hub result') end
  return response.result
end
local function rex_ok(method, args)
  local result, err = rex.call(method, args)
  if not result then
    if type(err) == 'table' then fail(err.code or 'unavailable', err.message or 'Rex request failed') end
    text_error(err, 'Rex request failed')
  end
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

-- rescan drops the cached scan of a session and scans again. The Rescan widget and tunnels.ports
-- both call it. It changes only this in-memory cache, so it takes no operation key.
local function rescan(session_id)
  scans[session_id or ''] = nil
  return scan(session_id)
end

local function catalog()
  local r = hub('hub.store.get', {keys = {'forwards'}}).records.forwards
  if not r or type(r.rev) ~= 'string' then fail('internal', 'Missing forward catalog') end
  local value = r.value or {}
  value.intents, value.forwards, value.cleanups, value.stops = value.intents or {}, value.forwards or {}, value.cleanups or {}, value.stops or {}
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
-- result_for answers the Forward result for the creator of intent: the view result for the user,
-- the forward for an agent. Maintenance that adopts an intent saves the same result.
local function result_for(intent, block_id)
  if type(intent.creator) == 'table' and intent.creator.kind == 'agent' then
    return {forward = block_id, port = intent.port, target = intent.target, session_id = intent.session_id, source_block = intent.source_block, state = 'starting'}
  end
  return done_result
end
-- commit turns intent id into the forward of block_id, with the operation result, in one batch.
local function commit(id, intent, block_id)
  update(function(s)
    s.intents[id] = nil
    s.forwards[block_id] = {session_id = intent.session_id, source_block = intent.source_block, port = intent.port,
      target = intent.target, profile = intent.profile, op = id, created = intent.created, creator = intent.creator}
  end, {key = id, fingerprint = intent.fingerprint, result = result_for(intent, block_id)})
end
-- drop removes intent id and records the operation result, so a retry never creates again.
local function drop(id, intent, result)
  update(function(s) s.intents[id] = nil; s.cleanups[intent.profile] = s.cleanups[intent.profile] or {phase = 'new'} end, {key = id, fingerprint = intent.fingerprint, result = result})
end

-- refused_before_create answers {code, message} when err (a table or Rex error text) is a refusal
-- that Rex gives before it creates a block, else nil. Only input validation is known to be one:
-- bad_request, observed on Rex 0.0.1792158932-g88fd41 (a label over 128 characters). Any other code,
-- internal or unknown included, can follow a create, so the outcome stays unknown.
local function refused_before_create(err)
  local code, msg
  if type(err) == 'table' then
    code, msg = err.code, err.message
  else
    local text = tostring(err or '')
    code = text:match('code=([%w_]+)%)$')
    msg = text:match('failed: (.-) %(status=%d+ code=[%w_]+%)$') or text
  end
  if code == 'bad_request' then return {code = code, message = type(msg) == 'string' and msg ~= '' and msg or 'Rex refused the request'} end
end
local cleanup_errors = {} -- profile -> the last failure, shown in the panel
local cleanup_seq = 0
local down_prefix = 'lazyrex-tunnel-down:'
local maintain
-- receipt answers the exit code of `down` when the screen of block_id has the exact receipt line of
-- attempt key, else nil.
local function receipt(block_id, key)
  local screen = rex.call('com.superlogical.terminal.format', {session_id = plugin_session, block_id = block_id, args = {format = 'text', trim = true, unwrap = true}})
  if not screen or type(screen.content) ~= 'string' or type(key) ~= 'string' then return nil end
  local want = 'lazyrex-tunnel-down-exit ' .. key .. ' '
  for line in (screen.content .. '\n'):gmatch('([^\n]*)\n') do
    line = line:gsub('%s+$', '')
    if line:sub(1, #want) == want and line:sub(#want + 1):match('^%d+$') then return tonumber(line:sub(#want + 1)) end
  end
end
-- advance_cleanups moves each cleanup one step: new -> sending (saved before session.new_block) ->
-- running (block known) -> closing (the result is saved; the block closes) -> done (exit 0: the
-- record is removed) or retry (after 5 s). A running block that disappears is retried: its process
-- ended with the block. A sending record with an unknown
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
        -- tunnels-down.sh prints a receipt with the key and the exit code of `down` and waits, so
        -- that an attempt stays provable until it is adopted. A process that ended without a
        -- receipt was stopped: that attempt is over, and down runs again.
        local code = receipt(c.block_id, c.key)
        local process = not code and rex.call('com.superlogical.terminal.process', {session_id = plugin_session, block_id = c.block_id, args = {}})
        if code then
          c.result = code == 0 and {ok = true} or {error = 'exit status ' .. code}
        elseif process and not process.child and process.last_exit then
          c.result = {error = 'stopped before its result: ' .. tostring(process.last_exit.error or process.last_exit.exit_code)}
        end
        if c.result then
          -- A table field, not a local: in Rex Lua a closure's write to a captured local can be lost
          -- after a caught error (LazyRex docs/rex-protocol.md, "Rex Lua runtime").
          local result, done = c.result, {saved = false}
          update(function(s)
            local x = s.cleanups[profile]
            done.saved = type(x) == 'table' and x.phase == 'running' and x.block_id == c.block_id
            if done.saved then x.phase, x.result = 'closing', result end
          end)
          if done.saved then c.phase = 'closing' end
        end
      end
    end
    if c.phase == 'closing' then
      -- The result is saved before block.close, because the close ends a live wrapper. The record
      -- keeps the block until the close succeeds or a Rex listing shows that the block is gone.
      local gone = by_id and not by_id[c.block_id]
      if not gone and by_id then
        local ok, closed, err = pcall(rex.call, 'block.close', {session_id = plugin_session, block_id = c.block_id})
        gone = ok and closed ~= nil
        if not gone then cleanup_errors[profile] = 'the cleanup block did not close: ' .. tostring(ok and err or closed) end
      end
      if gone then
        local result = type(c.result) == 'table' and c.result or {error = 'unknown result'}
        if result.ok then
          cleanup_errors[profile] = nil
          update(function(s) if s.cleanups[profile] and s.cleanups[profile].block_id == c.block_id then s.cleanups[profile] = nil end end)
          invalidate()
        else
          cleanup_errors[profile] = result.error
          set_cleanup(profile, function(x) if x.block_id == c.block_id then x.phase, x.block_id, x.result, x.retry_at = 'retry', nil, nil, now + 5 end end)
        end
      end
    elseif c.phase == 'sending' then
      local block = by_id and proven(by_id, down_prefix .. c.key, c.key, c.saved_at, plugin_session, 'tunnels-down.sh')
      if block then set_cleanup(profile, function(x) x.phase, x.block_id = 'running', block.block_id end)
      elseif not by_id then set_cleanup(profile, function(x) x.phase, x.retry_at = 'retry', now end) end
      -- Otherwise the create result stays unknown: the profile stays owned.
    elseif c.phase == 'new' or (c.phase == 'retry' and now >= (c.retry_at or 0)) then
      local opentunnel, why = find_opentunnel()
      if not opentunnel then cleanup_errors[profile] = why
      else
        cleanup_seq = cleanup_seq + 1
        local key = instance_id .. '-' .. now .. '-' .. cleanup_seq
        set_cleanup(profile, function(x) x.phase, x.key, x.saved_at, x.block_id, x.result = 'sending', key, now, nil, nil end)
        local created, err = rex.call('session.new_block', {session_id = plugin_session, flavor = 'com.superlogical.terminal.shell',
          label = down_prefix .. key, options = {command = {'/bin/sh', plugin_dir .. '/tunnels-down.sh', key, opentunnel, profile},
          login = false, exit = {on_completion = false}}})
        if created and created.block_id then
          set_cleanup(profile, function(x) if x.key == key then x.phase, x.block_id = 'running', created.block_id end end)
        else
          -- A refusal before any create ends this attempt. The record stays, so the profile stays
          -- reserved: down did not run. Any other error keeps the result unknown (sending).
          local refused = refused_before_create(err)
          if refused then
            cleanup_errors[profile] = refused.message
            set_cleanup(profile, function(x) if x.key == key then x.phase, x.block_id, x.retry_at = 'retry', nil, now + 5 end end)
          end
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
    local block = by_id and proven(by_id, label_of(id), id, intent.saved_at, intent.session_id, 'tunnels-run.sh')
    if not by_id then drop(id, intent, {error = {code = 'not_found', message = 'The session closed before the tunnel started'}})
    elseif block then
      commit(id, intent, block.block_id)
      state.forwards[block.block_id] = {session_id = intent.session_id, source_block = intent.source_block, port = intent.port, target = intent.target, profile = intent.profile, op = id, created = intent.created, creator = intent.creator}
    else
      rows[#rows + 1] = {intent_id = id, fw = intent, state = 'Unknown start result'}
    end
  end
  local stopping = {}
  for _, st in pairs(state.stops) do stopping[st.forward] = true end
  for block_id, fw in pairs(state.forwards) do
    local by_id = blocks(fw.session_id)
    local block = by_id and by_id[block_id]
    -- finish_stops removes a forward that a stop names, with the stop's operation result.
    if not block and stopping[block_id] then rows[#rows + 1] = {block_id = block_id, fw = fw, url = fw.url, state = 'Stopping'}
    elseif not block then gone[block_id] = true
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
      if stopping[block_id] then row.state = 'Stopping' end
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

-- Stop (panel Stop and tunnels.stop). A caller is 'user' (the view path) or an agent that the hub
-- identifies; it never comes from the arguments. The stop is saved before block.close as stops[op
-- key] = {forward, session_id, fingerprint}, and one final batch removes the forward and the stop
-- and writes the operation result. A retry with the same key, or maintenance after a failed final
-- batch or a restart, finishes the same stop, so the key always replays its first result.
-- part frames a value with its length, so different (caller, key) pairs give different op keys.
-- A stop op key contains '/', which a Forward key cannot contain, so the two never collide.
local function part(value) value = tostring(value); return #value .. ':' .. value .. '/' end
local function stop_key(caller, key)
  return 'stop/' .. (caller == 'user' and part('user') or part('agent') .. part(caller.agent)) .. part(key)
end
-- creator answers the creator of a forward. A missing or malformed creator is the user.
local function creator(fw)
  local c = fw.creator
  if type(c) == 'table' and c.kind == 'agent' and type(c.agent) == 'string' and c.agent ~= '' then return c end
  return {kind = 'user'}
end
-- finish_stop closes the block of a saved stop if Rex lists it, then commits the final batch. It
-- answers the operation result. A failed Rex read or close raises, and the stop stays saved.
local function finish_stop(id, st)
  local fw = catalog().forwards[st.forward]
  if fw then
    local by_id = blocks_of(st.session_id, sessions())
    if by_id and by_id[st.forward] then rex_ok('block.close', {session_id = st.session_id, block_id = st.forward}) end
  end
  local result = {forward = st.forward, stopped = true}
  local saved = update(function(s)
    local f = s.forwards[st.forward]
    if f then s.cleanups[f.profile] = s.cleanups[f.profile] or {phase = 'new'}; s.forwards[st.forward] = nil end
    s.stops[id] = nil
  end, {key = id, fingerprint = st.fingerprint, result = result})
  -- Another invocation committed the same final batch first.
  if saved.op_exists then return saved.op_exists.result end
  return result
end
local function finish_stops()
  for id, st in pairs(catalog().stops) do pcall(finish_stop, id, st) end
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
    if next(state.stops) then finish_stops() end
    if next(state.forwards) or next(state.intents) then reconcile() end
    local cleanup = advance_cleanups()
    state = catalog()
    return {cleanup = cleanup or next(state.stops) ~= nil, live = next(state.forwards) ~= nil or next(state.intents) ~= nil}
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

-- stop_forward stops the forward of block_id for caller. The user and any agent may stop any
-- forward (decision "Agents may act on anything").
local function stop_forward(caller, block_id, key)
  if type(block_id) ~= 'string' or block_id == '' then fail('invalid_input', 'forward is required') end
  if type(key) ~= 'string' or key == '' or #key > 200 then fail('invalid_input', 'key is required') end
  local id = stop_key(caller, key)
  local fingerprint = 'stop-v1/' .. part(block_id)
  local saved = hub('hub.store.op', {key = id})
  if saved.found then return result_of(saved, fingerprint) end
  local state = catalog()
  local st = state.stops[id]
  if st then
    if st.fingerprint ~= fingerprint then fail('operation_conflict', 'This key has different content') end
  else
    local fw = state.forwards[block_id]
    if not fw then fail('not_found', 'This forward has stopped') end
    st = {forward = block_id, session_id = fw.session_id, port = fw.port, profile = fw.profile, fingerprint = fingerprint, saved_at = os.time()}
    update(function(s)
      if not s.forwards[block_id] then fail('not_found', 'This forward has stopped') end
      if s.stops[id] and s.stops[id].fingerprint ~= fingerprint then fail('operation_conflict', 'This key has different content') end
      s.stops[id] = s.stops[id] or st
    end)
  end
  local result = finish_stop(id, st)
  invalidate()
  kick()
  return result
end

-- enc writes every byte outside [A-Za-z0-9-] as '_' and two hex digits, so an agent ID and key fit
-- a Rex label and the ps proof (no space or quote).
local function enc(value) return (tostring(value):gsub('[^%w%-]', function(c) return string.format('_%02x', c:byte()) end)) end
-- source_of answers the form option value of a listener; tunnels.ports gives it as source.
local function source_of(p) return p.session_id .. '|' .. (p.block_id or '') .. '|' .. tostring(p.port) .. '|' .. (p.address or '') end
-- from_source answers the request of a listener choice (the form option value or the agent source).
local function from_source(choice)
  local session_id, block_id, port, address = choice:match('^([^|]+)|([^|]*)|(%d+)|(.*)$')
  if not session_id then fail('invalid_input', 'Select a port') end
  port = valid_port(port)
  return {session_id = session_id, source_block = block_id ~= '' and block_id or nil, port = port, target = target(address, port)}
end
local function fingerprint_matches(stored, req)
  return stored == req.fingerprint or (req.legacy ~= nil and stored == req.legacy)
end

-- start_forward runs one Forward request for the view and the agent path. req = {id, fingerprint,
-- legacy (view only: the v1 fingerprint of records saved before forward-v2), creator, resolve =
-- function answering {session_id, source_block, port, target}}.
-- The replay lookup comes first: a saved result or intent never depends on the current scan.
local function start_forward(req)
  local id = req.id
  local saved = hub('hub.store.op', {key = id})
  if saved.found then
    if not fingerprint_matches(saved.fingerprint, req) then fail('operation_conflict', 'This key has different content') end
    if type(saved.result) == 'table' and saved.result.error then fail(saved.result.error.code, saved.result.error.message) end
    return saved.result
  end
  local state = catalog()
  local intent = state.intents[id]
  if intent then
    if not fingerprint_matches(intent.fingerprint, req) then fail('operation_conflict', 'This key has different content') end
    -- Sent before with an unknown result: never send it again. Look for its block.
    local by_id = blocks_of(intent.session_id, sessions())
    if not by_id then drop(id, intent, {error = {code = 'not_found', message = 'The session closed before the tunnel started'}}); fail('not_found', 'The session closed before the tunnel started') end
    local block = proven(by_id, label_of(id), id, intent.saved_at, intent.session_id, 'tunnels-run.sh')
    if not block then fail('unresolved', 'The tunnel block has an unknown start result; a late Rex reply can still create it') end
    commit(id, intent, block.block_id)
    invalidate()
    return result_for(intent, block.block_id)
  end
  intent = req.resolve()
  if not sessions()[intent.session_id] then fail('not_found', 'The session of this port is closed') end
  -- Check the binary before the intent is saved: a request that is never sent must not hold a port.
  local opentunnel, why = find_opentunnel()
  if not opentunnel then fail('not_found', why) end
  intent.profile = profile_prefix .. intent.port
  intent.creator = req.creator
  intent.fingerprint = req.fingerprint
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
    -- A saved stop keeps its port until its final batch: two keys can stop one forward, and each
    -- finishes on its own. A cleanup can still run `down` for this profile, which would stop the new `serve`.
    for _, st in pairs(s.stops) do
      if st.port == intent.port then fail('conflict', 'Port ' .. intent.port .. ' is still stopping its previous tunnel. Try again in a moment.') end
    end
    if s.cleanups[intent.profile] then fail('conflict', 'Port ' .. intent.port .. ' is still stopping its previous tunnel. Try again in a moment.') end
    s.intents[id] = intent
  end)
  local command = {'/bin/sh', plugin_dir .. '/tunnels-run.sh', id, opentunnel, intent.profile, intent.target}
  local created, err = rex.call('session.new_block', {session_id = intent.session_id, flavor = 'com.superlogical.terminal.shell',
    label = label_of(id), options = {command = command, login = false, exit = {on_completion = false}}})
  if not (created and created.block_id) then
    local e = refused_before_create(err)
    if e then
      -- Rex refused the request before it created a block. The intent and its port go; the key
      -- replays the error.
      local result = {error = {code = e.code, message = e.message}}
      update(function(s) s.intents[id] = nil end, {key = id, fingerprint = intent.fingerprint, result = result})
      invalidate()
      fail(e.code, e.message)
    end
    -- The outcome can be unknown. The intent stays; the panel shows it and looks for its label.
    invalidate()
    fail('unavailable', 'Rex did not confirm the tunnel block: ' .. message(err))
  end
  commit(id, intent, created.block_id)
  invalidate()
  kick()
  return result_for(intent, created.block_id)
end

-- forward is the form submit (view path). Its key is the hub operation key, as before forward-v2.
local function forward(args)
  local id = args.operation_key
  if type(id) ~= 'string' or not id:match('^[%w%-_%.:]+$') or #id > 100 then fail('invalid_input', 'Invalid operation key') end
  local values = type(args.input) == 'table' and type(args.input.values) == 'table' and args.input.values or {}
  local ctx = type(args.context) == 'table' and args.context or {}
  local choice = type(values.port) == 'string' and values.port or ''
  local other = type(values.other) == 'string' and values.other or ''
  local ctx_session = type(ctx.session_id) == 'string' and ctx.session_id or ''
  local ctx_source = type(ctx.source_block_id) == 'string' and ctx.source_block_id or ''
  local scan_mode = choice ~= '' and choice ~= 'other'
  return start_forward({
    id = id,
    fingerprint = 'forward-v2/' .. (scan_mode and part('scan') .. part(choice) or part('other') .. part(ctx_session) .. part(ctx_source) .. part(other)),
    legacy = 'forward/' .. #choice .. ':' .. choice .. '/' .. #other .. ':' .. other .. '/' .. tostring(ctx.session_id),
    creator = {kind = 'user'},
    resolve = function()
      if scan_mode then return from_source(choice) end
      if ctx_session == '' then fail('invalid_input', 'The form has no session') end
      local port = valid_port(other)
      -- "Other port…" has no process: the source is the pane that ran the palette command.
      return {session_id = ctx_session, source_block = ctx_source ~= '' and ctx_source or nil, port = port, target = '127.0.0.1:' .. port}
    end,
  })
end

-- agent_forward is tunnels.forward (agent path). caller is the agent; session_id and block_id are
-- its pane from hub.identify, the defaults of the manual port form.
local function agent_forward(caller, own_session, own_block, args)
  local key = args.key
  if type(key) ~= 'string' or key == '' or #key > 100 then fail('invalid_input', 'key is required (1 to 100 characters)') end
  local has_source, has_port = args.source ~= nil, args.port ~= nil
  if has_source == has_port then fail('invalid_input', 'Give either source (from tunnels.ports) or port') end
  if has_source and (args.session_id ~= nil or args.block_id ~= nil) then fail('invalid_input', 'source names its session and pane; do not give session_id or block_id with it') end
  local id = 'fwd/' .. part(enc(caller.agent)) .. part(enc(key))
  if #id > 600 then fail('invalid_input', 'The agent ID and key are too long') end
  local fingerprint
  if has_source then
    if type(args.source) ~= 'string' or args.source == '' then fail('invalid_input', 'source must be a source from tunnels.ports') end
    fingerprint = 'forward-agent-v1/' .. part('source') .. part(args.source)
  else
    if type(args.port) ~= 'number' then fail('invalid_input', 'port must be a whole number from 1 to 65535') end
    for _, name in ipairs({'session_id', 'block_id'}) do
      if args[name] ~= nil and (type(args[name]) ~= 'string' or args[name] == '') then fail('invalid_input', name .. ' must be a non-empty string') end
    end
    fingerprint = 'forward-agent-v1/' .. part('port') .. part(args.session_id or '') .. part(args.block_id or '') .. part(args.port)
  end
  return start_forward({
    id = id, fingerprint = fingerprint, creator = caller,
    resolve = function()
      if has_source then return from_source(args.source) end
      local port = valid_port(args.port)
      local session_id = args.session_id or own_session
      if type(session_id) ~= 'string' or session_id == '' then fail('invalid_input', 'session_id is required: the hub knows no session of this agent') end
      local by_id = blocks_of(session_id, sessions())
      if not by_id then fail('not_found', 'The session of this port is closed') end
      local source_block = args.block_id
      if source_block then
        if not by_id[source_block] then fail('not_found', 'block_id is not a pane of that session') end
      elseif own_block and by_id[own_block] then
        source_block = own_block
      end
      return {session_id = session_id, source_block = source_block, port = port, target = '127.0.0.1:' .. port}
    end,
  })
end

local function panel_action(args)
  local input = type(args.input) == 'table' and args.input or {}
  local item = input.item_id
  local block_id = type(args.node_id) == 'string' and args.node_id:match('^fw/(.+)$')
  if not block_id then fail('invalid_input', 'Unknown Tunnels action') end
  if item == 'stop' then return stop_forward('user', block_id, args.operation_key) end
  local fw = catalog().forwards[block_id]
  if not fw then fail('not_found', 'This forward has stopped') end
  local by_id = blocks_of(fw.session_id, sessions())
  local block = by_id and by_id[block_id]
  if not block then
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
    options[#options + 1] = {value = source_of(p),
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
  }, submit_action = {name = 'forward', label = 'Forward', enabled = true, tool = 'tunnels.forward'}}
  nodes[#nodes + 1] = {id = 'rescan', type = 'widget', text = 'The list is from the last scan.', action = {name = 'rescan', label = 'Rescan', enabled = true, tool = 'tunnels.ports'}}
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
      items[#items + 1] = {id = name, label = shown and 'Hide Logs' or 'Show Logs', detail = '', action = {name = name, label = shown and 'Hide Logs' or 'Show Logs', enabled = true, user_only = 'navigation'}}
      items[#items + 1] = {id = 'stop', label = 'Stop', detail = '', action = {name = 'stop', label = 'Stop', enabled = true, tool = 'tunnels.stop'}}
    elseif row.intent_id then
      -- No action: the port stays reserved until Rex proves the block or the session closes.
      node_id = 'intent/' .. row.intent_id
      items[#items + 1] = {id = 'unknown', label = 'Waiting for Rex', detail = 'The tunnel block may still start. The port stays reserved until it does or its session closes.'}
    else
      -- A saved stop whose block is gone: maintenance commits its result.
      node_id = 'fw/' .. row.block_id
      items[#items + 1] = {id = 'stopping', label = 'Stopping', detail = 'The tunnel block is closed. The port stays reserved until the stop is saved.'}
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
  nodes[#nodes + 1] = {id = 'new', type = 'widget', text = 'Forward a port from a pane', action = {name = 'new', label = 'Forward Port…', enabled = true, user_only = 'navigation'}}
  return {title = running > 0 and ('Tunnels (' .. running .. ' connected)') or 'Tunnels', nodes = nodes}
end

-- list_tunnels answers what the panel shows, for tunnels.list. It runs the same reconcile.
local function list_tunnels()
  local rows = reconcile()
  local known = sessions()
  local forwards, pending = {}, {}
  for _, row in ipairs(rows) do
    local fw = row.fw
    if row.intent_id then
      pending[#pending + 1] = {id = row.intent_id, port = fw.port, target = fw.target, session_id = fw.session_id, state = row.state, created = fw.created}
    else
      local c = creator(fw)
      forwards[#forwards + 1] = {id = row.block_id, port = fw.port, target = fw.target, url = row.url, state = row.state,
        session_id = fw.session_id, session_label = known[fw.session_id] and known[fw.session_id].label or nil,
        source_block = fw.source_block, created = fw.created, created_by = c.kind == 'agent' and c.agent or 'user',
        logs_shown = row.block ~= nil and row.block.placement ~= 'detached'}
    end
  end
  local cleanups = {}
  for profile in pairs(catalog().cleanups) do cleanups[#cleanups + 1] = {profile = profile, error = cleanup_errors[profile]} end
  table.sort(cleanups, function(a, b) return a.profile < b.profile end)
  return {forwards = forwards, pending = pending, cleanups = cleanups}
end

local function ports_for(session_id, args)
  if args.session_id ~= nil then
    if type(args.session_id) ~= 'string' or not sessions()[args.session_id] then fail('invalid_input', 'session_id must name an open session') end
    session_id = args.session_id
  end
  local result = rescan(session_id)
  invalidate()
  local ports = {}
  for i, p in ipairs(result.ports or {}) do
    local entry = {}
    for k, v in pairs(p) do entry[k] = v end
    entry.source = source_of(p)
    ports[i] = entry
  end
  return {session_id = session_id, ports = ports, warnings = result.warnings or {}}
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
    rescan(ctx.session_id)
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
-- Agent actions (agent parity). The hub forwards them with the agent's pid; hub.identify names
-- the agent and its pane. Agents may forward and stop any port (decisions
-- "Agents may act on anything" and "Agents use the Tunnels plugin fully").
local agent_actions = {
  {name = 'tunnels.list', kind = 'client', title = 'List forwarded ports',
    description = 'List the forwarded ports with their state, public URL, session and creator, the forwards whose start result is unknown (pending), and the opentunnel services that are still stopping (cleanups). Empty lists can appear as {}.',
    args = {type = 'object', properties = {}, additionalProperties = false}},
  {name = 'tunnels.forward', kind = 'client', title = 'Forward a port to a public URL',
    description = 'Forward a local TCP port to a public opentunnel URL. The port becomes public: anyone with the URL can reach it, and the tunnel does not ask visitors to sign in. '
      .. 'Give either source (the source of a listener from tunnels.ports: its session, pane, port and address) or port (the "Other port" form: the target is 127.0.0.1:port). '
      .. 'With port, session_id defaults to your session and block_id (the source pane) to your pane. Do not give session_id or block_id with source. '
      .. 'The result names the forward; tunnels.list shows its state and URL once it connects. Choose a key and retry with the same content after an unknown outcome.',
    args = {type = 'object', properties = {
      key = {type = 'string', minLength = 1, maxLength = 100},
      source = {type = 'string', minLength = 1, description = 'A source from tunnels.ports. Not with port, session_id or block_id.'},
      port = {type = 'integer', minimum = 1, maximum = 65535, description = 'Forward 127.0.0.1:port. Not with source.'},
      session_id = {type = 'string', minLength = 1, description = 'With port only. Default: your session.'},
      block_id = {type = 'string', minLength = 1, description = 'With port only: the source pane. Default: your pane.'}},
      required = {'key'}, additionalProperties = false}},
  {name = 'tunnels.stop', kind = 'client', title = 'Stop a forwarded port',
    description = 'Stop a forward from tunnels.list (forward = its id), also one that the user or another agent started. Choose a key and retry with the same content after an unknown outcome.',
    args = {type = 'object', properties = {forward = {type = 'string', minLength = 1}, key = {type = 'string', minLength = 1}},
      required = {'forward', 'key'}, additionalProperties = false}},
  {name = 'tunnels.ports', kind = 'client', title = 'Scan listening ports',
    description = 'Scan the listening TCP ports of processes in Rex panes, with the given session (default: yours) first. It refreshes the scan that the Forward Port form shows and changes nothing else, so it takes no key. Empty lists can appear as {}.',
    args = {type = 'object', properties = {session_id = {type = 'string', minLength = 1}}, additionalProperties = false}},
}
local exports = {}
for _, a in ipairs(agent_actions) do exports[#exports + 1] = a.name end
local function exported(name) for _, e in ipairs(exports) do if e == name then return true end end return false end
local function identify(principal)
  if type(principal) ~= 'table' or principal.kind ~= 'peer' or type(principal.pid) ~= 'number' then fail('refused', 'A local requester PID is required') end
  local r = hub('hub.identify', {pid = principal.pid})
  if r.found ~= true or type(r.agent) ~= 'string' or r.agent == '' then fail('refused', 'The hub does not recognize this agent') end
  return {kind = 'agent', agent = r.agent}, r.session_id, r.block_id
end
local function agent_call(name, principal, args)
  local caller, session_id, block_id = identify(principal)
  if type(args) ~= 'table' then fail('invalid_input', 'Arguments must be an object') end
  if name == 'tunnels.list' then return list_tunnels() end
  if name == 'tunnels.forward' then return agent_forward(caller, session_id, block_id, args) end
  if name == 'tunnels.stop' then return stop_forward(caller, args.forward, args.key) end
  if name == 'tunnels.ports' then return ports_for(session_id, args) end
  fail('not_supported', 'Unknown Tunnels action')
end
local actions = {}
for name in pairs(handlers) do actions[#actions + 1] = {name = name, kind = 'client', title = name,
  args = {type = 'object', additionalProperties = true}} end
for _, a in ipairs(agent_actions) do actions[#actions + 1] = a end
-- Only the hub can assert the original caller of a forwarded agent action.
actions[#actions + 1] = {name = 'hub.forward', kind = 'client', title = 'Forward an agent action',
  args = {type = 'object', properties = {action = {type = 'string'}, args = {type = 'object'}, requester_pid = {type = 'integer'}},
    required = {'action', 'args', 'requester_pid'}, additionalProperties = false}}
rex.call('client.keymap', {actions = actions})
hub('hub.register', {plugin = 'tunnels', instance_id = instance_id, exports = exports, commands = {
  {id = 'tunnels', title = 'Tunnels', description = 'Show forwarded ports', keywords = {'tunnel', 'port', 'opentunnel'}, route = '/panels/tunnels', surface = 'panel', landing = true, user_only = 'navigation'},
  {id = 'forward_port', title = 'Forward Port…', description = 'Share a local port with a public URL', keywords = {'tunnel', 'port', 'share', 'opentunnel'}, route = '/forms/forward',
    action = 'tunnels.forward'},
}})
-- A tunnel block that exits or closes, or a closed session, changes the panel.
rex.on('terminal.child_exited', function() invalidate(); kick() end)
rex.on('block_closed', function() invalidate(); kick() end)
rex.on('session_closed', function() invalidate(); kick() end)
rex.on('client_perform_requested', function(ctx, ev)
  local ok, result = pcall(function()
    local from_hub = ev.requester and ev.requester.client_id == hub_id
    if ev.action == 'hub.forward' then
      if not from_hub then fail('refused', 'Only the hub forwards agent actions') end
      local f = ev.args or {}
      if not exported(f.action) then fail('refused', 'The forwarded action is not exported') end
      if type(f.requester_pid) ~= 'number' or f.requester_pid <= 0 or f.requester_pid % 1 ~= 0 then fail('invalid_input', 'A positive requester PID is required') end
      return agent_call(f.action, {kind = 'peer', pid = f.requester_pid}, f.args or {})
    end
    if exported(ev.action) then return agent_call(ev.action, ev.requester and ev.requester.principal, ev.args or {}) end
    local handler = handlers[ev.action]
    if not handler then fail('not_supported', 'Unknown Tunnels action') end
    if not from_hub then fail('refused', 'Only the hub calls Tunnels view actions') end
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
