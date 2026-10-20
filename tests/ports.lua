-- Port discovery (tunnels_ports.lua) and its two paths: the Forward Port form with Rescan (view)
-- and tunnels.ports (tool). Both call one rescan handler that replaces the scan cache of a session.
-- Ported from tests/tunnels-ports-unit.lua and tests/tunnels-ports-lab.mjs. No test here forwards
-- a port. The listeners are /usr/bin/nc on 127.0.0.1 in lab panes.

local plugin_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/tests/[^/]*$')
local ports = dofile(plugin_dir .. '/tunnels_ports.lua')

-- --- The parser and the scan with fixture Rex and process services (no host process) ---

test('lsof parsing: addresses, duplicate sockets, invalid ports', function()
  local rows = ports.parse_lsof('p42\ncnode\nn127.0.0.1:3000\nn127.0.0.1:3000\nn[::1]:4000\nn*:5000\nn*:0\nn*:65536\npbad\nn*:6000\n')
  expect(#rows).to_be(3)
  expect(rows[2].address).to_be('[::1]')
  expect(rows[3].port).to_be(5000)
end)

-- A table field, not a local: in Rex Lua a closure's write to a captured local can be lost after a
-- caught error (LazyRex docs/rex-protocol.md, "Rex Lua runtime").
local count = {n = 0}
local function fixture(mode)
  local api = {}
  function api.call(method)
    if method == 'session.list' then return {sessions = {{session_id = 's'}}} end
    if method == 'session.attach' then return {} end
    if method == 'session.view' then return {windows = {{window_id = 'w', label = 'tab'}}} end
    if method == 'session.list_blocks' then
      if mode == 'listing_error' then return nil, {message = 'unavailable'} end
      return {blocks = {{creator_name = 'com.superlogical.terminal', block_id = 'b', window_id = 'w'}}}
    end
    if method == 'com.superlogical.terminal.process' then return {child = {pid = 10}} end
    error(method)
  end
  function api.exec(argv)
    count.n = count.n + 1
    if argv[1] == '/bin/ps' then
      if mode == 'ps_error' then return {ok = false, stderr = 'denied'} end
      if mode == 'no_pids' then return {ok = true, stdout = '20 1 other\n'} end
      return {ok = true, stdout = '10 1 shell\n11 10 node\n20 1 outside\n30 31 loop\n31 30 loop\n'}
    end
    assert(argv[5] == '10,11', 'only descendant PIDs may be selected')
    if mode == 'empty' then return {ok = false, code = 1, stdout = '', stderr = ''} end
    if mode == 'timeout' then return {ok = false, code = -1, timed_out = true, stdout = 'p11\nn*:9999\n'} end
    if mode == 'missing' then return nil, 'not installed' end
    return {ok = true, stdout = 'p11\ncnode\nn127.0.0.1:3000\np20\ncoutside\nn*:9000\n'}
  end
  return api
end

test('scan: descendant filtering, cycle termination, partial failures, empty selection', function()
  local r = ports.scan('s', fixture('ok'))
  expect(#r.ports).to_be(1)
  expect(r.ports[1].pid).to_be(11)
  expect(r.ports[1].tab).to_be('tab')
  expect(#r.warnings).to_be(0)
  for _, mode in ipairs({'listing_error', 'ps_error', 'timeout', 'missing'}) do
    r = ports.scan('s', fixture(mode))
    expect(#r.ports, mode).to_be(0)
    assert_true(#r.warnings > 0, mode .. ' gives a warning')
  end
  r = ports.scan('s', fixture('empty'))
  expect(#r.ports).to_be(0)
  expect(#r.warnings).to_be(0)
  count.n = 0
  r = ports.scan('s', fixture('no_pids'))
  expect(#r.ports).to_be(0)
  expect(count.n, 'no lsof call without selected PIDs').to_be(1)
end)

-- --- The real plugin on the lab server ---

math.randomseed(os.time())
local base = 41000 + math.random(0, 400) * 20
local alice = agent('alice')

-- listen opens a tab in session that runs a shell with nc as its child, on 127.0.0.1:port.
local function listen(session, port)
  local w = rex.call('session.new_window', {session_id = session, window_label = 'listen-' .. port,
    layout = {block = {flavor = 'com.superlogical.terminal.shell', options = {login = false,
      command = {'/bin/sh', '-c', '/usr/bin/nc -lk 127.0.0.1 ' .. port .. ' >/dev/null; :'}}}}})
  return {session = session, block = w.block_ids[1], window = w.window_id, port = port}
end
local function rows_of(result)
  local rows = {}
  for _, p in pairs(result.ports or {}) do rows[#rows + 1] = p end
  return rows
end
local function row(result, port)
  for _, p in ipairs(rows_of(result)) do if p.port == port then return p end end
end
local function scan(session) return alice:call('tunnels.ports', {session_id = session}) end
local function wait_port(session, port) return wait('port ' .. port .. ' in the scan', function() return row(scan(session), port) end, 15) end

local a, b = session('ports-a'), session('ports-b')
local la, lb = listen(a, base), listen(b, base + 1)

test('a descendant listener belongs to its pane; the given session sorts first', function()
  wait_port(b, la.port)
  local r = wait('both listeners', function() local x = scan(b); return row(x, lb.port) and row(x, la.port) and x end, 15)
  expect(r.session_id).to_be(b)
  expect(next(r.warnings or {}), 'no warnings').to_be(nil)
  local first = rows_of(r)[1]
  expect(first.session_id, 'the given session sorts first').to_be(b)
  for _, l in ipairs({la, lb}) do
    local p = row(r, l.port)
    expect(p.block_id).to_be(l.block)
    expect(p.window_id).to_be(l.window)
    expect(p.session_id).to_be(l.session)
    expect(p.address).to_be('127.0.0.1')
    expect(p.command).to_be('/usr/bin/nc') -- the ps command name, never its arguments
  end
end)

test('the default session is the caller\'s session', function()
  local r = alice:call('tunnels.ports', {})
  expect(r.session_id).to_be(alice.session)
end)

test('a listener outside every pane is not a choice', function()
  local port = base + 2
  local started = rex.exec({'/bin/sh', '-c', '/usr/bin/nc -lk 127.0.0.1 ' .. port .. ' >/dev/null 2>&1 & echo $!'}, {timeout = 5})
  local pid = tonumber((started.stdout or ''):match('%d+'))
  assert_true(pid, 'the outside listener started')
  local ok, err = pcall(function()
    wait('the outside listener listens', function()
      local r = rex.exec({'/usr/sbin/lsof', '-nP', '-a', '-p', tostring(pid), '-iTCP', '-sTCP:LISTEN', '-Fn'}, {timeout = 5})
      return r and r.ok and (r.stdout or ''):find(':' .. port, 1, true)
    end, 10)
    expect(row(scan(a), port)).to_be(nil)
  end)
  rex.exec({'/bin/kill', tostring(pid)}, {timeout = 5}) -- the pid that this test started
  if not ok then error(err, 0) end
end)

test('infrastructure panes are never choices', function()
  for _, label in ipairs({'lazyrex-tunnel:probe', 'lazyrex-plugin:probe', 'lazyrex-view:probe', 'lazyrex-form:probe',
    'lazyrex-placeholder:probe', 'lazyrex-hub', 'lazyrex-dev-process'}) do
    rex.call('session.set_block_label', {session_id = a, block_id = la.block, label = label})
    expect(row(scan(a), la.port), label).to_be(nil)
  end
  rex.call('session.set_block_label', {session_id = a, block_id = la.block, label = 'source'})
  wait_port(a, la.port)
end)

test('a detached pane has no tab; a closed pane disappears', function()
  rex.call('session.detach_block', {session_id = a, block_id = la.block})
  local p = wait('the detached pane', function() local x = row(scan(a), la.port); return x and x.window_id == '' and x end, 10)
  expect(p.tab).to_be('')
  rex.call('block.close', {session_id = b, block_id = lb.block})
  wait('the closed pane leaves the scan', function() return row(scan(a), lb.port) == nil end, 10)
end)

-- --- The cache: Rescan (view) and tunnels.ports (tool) replace it through one handler ---

local function options(form)
  local values = {}
  for _, o in ipairs(node(form:render(), 'forward').fields[1].options) do values[#values + 1] = o.value end
  return table.concat(values, '\n')
end
local function lists(form, port) return options(form):find('|' .. port .. '|', 1, true) ~= nil end

-- listening waits until lsof shows a listener on port, without a plugin scan.
local function listening(port)
  wait('a listener on ' .. port, function()
    local r = rex.exec({'/usr/sbin/lsof', '-nP', '-iTCP:' .. port, '-sTCP:LISTEN', '-Fp'}, {timeout = 5})
    return r and r.ok and (r.stdout or ''):find('p%d')
  end, 10)
end

test('the form keeps its scan until Rescan (view) or tunnels.ports (tool) replaces it', function()
  local c = session('ports-c')
  local first = listen(c, base + 3)
  listening(first.port)
  user:command('forward_port', {session = c, block = first.block})
  local form = user:view('/forms/forward', 'tunnels', c)
  expect(lists(form, first.port)).to_be(true)
  -- A new listener: the cached scan does not show it. Rescan through the view does.
  local second = listen(c, base + 4)
  listening(second.port)
  expect(lists(form, second.port)).to_be(false)
  local op = form:action('rescan', 'rescan', {})
  expect(op.status).to_be('succeeded')
  expect(lists(form, second.port)).to_be(true)
  -- A third listener: the cache hides it until the tool scans the same session.
  local third = listen(c, base + 5)
  listening(third.port)
  expect(lists(form, third.port)).to_be(false)
  expect(row(scan(c), third.port).block_id).to_be(third.block)
  expect(lists(form, third.port)).to_be(true)
end)
