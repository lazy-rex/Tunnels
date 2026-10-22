-- Read tracking is the default (hub 4.2): the hub renders a view again after a write to a table that
-- its render read. The Tunnels renders read its SQL tables and also Rex, so the SDK replies
-- refresh = "all". The open views must still update with no render from the test: the panel by its
-- timer (Rex output only), and the Forward form after tunnels.ports replaces the cached scan.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local alice = agent('alice')
local S = session('tunnels-refresh')
local P = T.port()
local web = T.listen(S, P, 'web')
T.listening(P)
-- shared.tblock: a table field, not a local (LazyRex docs/rex-protocol.md, "Rex Lua runtime").
local shared = {}

local function attempts(v)
  for _, c in ipairs(renders('tunnels')) do if c.view_id == v.id then return c.attempts end end
  return 0
end
-- shown answers the last tree that the hub pushed to v (not a new render).
local function shown(v) return (v:get() or {}).tree or {nodes = {}} end

test('the open panel shows Connected and renders again by its own timer', function()
  local form = T.open_form(web)
  local choice = node(form:render(), 'forward').fields[1].options[1].value
  expect(T.submit(form, choice).status).to_be('succeeded')
  shared.tblock = wait('the tunnel block', function() local b = T.tunnel_blocks(S); return #b == 1 and b[1].block_id end, 20)
  local v = T.panel(S)
  wait('the panel shows Connected', function()
    local ok, n = pcall(node, shown(v), 'fw/' .. shared.tblock)
    return ok and n and n.label:match(' · Connected · https://') ~= nil
  end, 40)
  -- Connected: the timer renders the panel every 15 s, with no action and no commit.
  local a0 = attempts(v)
  wait('a timer render', function() return attempts(v) > a0 end, 25)
end)

test('the open Forward form lists a new listener after tunnels.ports', function()
  local form = T.open_form(web)
  local P2 = T.port()
  T.listen(S, P2, 'web2')
  T.listening(P2)
  local function lists(t)
    local ok, n = pcall(node, t, 'forward')
    if not ok or not n then return false end
    for _, o in ipairs(n.fields[1].options) do if tostring(o.value):find('|' .. P2 .. '|', 1, true) then return true end end
    return false
  end
  -- The form keeps its scan until a rescan: the new listener is not in it yet.
  expect(lists(form:render()), 'the cached scan').to_be(false)
  alice:call('tunnels.ports', {session_id = S})
  wait('the form lists the new port', function() return lists(shown(form)) end, 20)
end)

test('stop the forward', function()
  local r = alice:call('tunnels.stop', {forward = shared.tblock, key = 'refresh-stop'})
  expect(r.stopped).to_be(true)
  wait('no tunnel block', function() return #T.tunnel_blocks(S) == 0 end, 20)
end)

test('an open panel recovers by itself after a failed read of the catalog', function()
  -- No forward and no cleanup, so the panel arms no refresh timer. A timer that an earlier render
  -- armed fires within 15 s; wait it out. Then a gate makes each hub.sql.query fail.
  wait('no cleanup is pending', function() return next(T.catalog().cleanups or {}) == nil end, 30)
  local v = T.open_panel(web)
  wait('the panel is empty', function() local ok, n = pcall(node, v:render(), 'empty'); return ok and n ~= nil end, 10)
  rex.sleep(16)
  local gate = fault({point = 'action', action = 'hub.sql.query', when = 'before', mode = 'gate', plugin = 'tunnels'})
  v:render()
  wait('the panel shows the read error', function() local ok, n = pcall(node, shown(v), 'error'); return ok and n ~= nil end, 10)
  fault_release(gate)
  wait('the panel recovers with no render from the test', function()
    local ok, n = pcall(node, shown(v), 'empty')
    return ok and n ~= nil
  end, 20)
end)

-- A render reads only (the SDK refuses a write in a render). The panel shows the same rows that
-- maintenance then writes: a proven intent as its forward, a new URL, no gone forward, and a pending
-- Stop. The render changes no state; maintenance writes the changes and refreshes the open view.
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local function copy(v)
  if type(v) ~= 'table' then return v end
  local r = {}
  for k, x in pairs(v) do r[k] = copy(x) end
  return r
end
local function count(list, name) local n = 0; for _, x in ipairs(list) do if x == name then n = n + 1 end end; return n end

test('a panel render writes nothing; maintenance writes the same changes and refreshes the view (sandbox)', function()
  local now = os.time()
  local function fw(port, op, created) return {session_id = 's', port = port, target = '127.0.0.1:' .. port, profile = 'lazyrexlab-' .. port, op = op, created = created, creator = {kind = 'user'}} end
  local catalog = {
    intents = {['op-1'] = {session_id = 's', port = 4321, target = '127.0.0.1:4321', profile = 'lazyrexlab-4321', creator = {kind = 'user'},
      fingerprint = 'forward-v2/x', created = '2026-10-22T00:00:00Z', saved_at = now - 10, phase = 'sending'}},
    forwards = {live = fw(4322, 'op-live', '2026-10-22T00:00:01Z'), gone = fw(4323, 'op-gone', '2026-10-22T00:00:02Z'), stopping = fw(4324, 'op-stop', '2026-10-22T00:00:03Z')},
    stops = {['stop/k'] = {forward = 'stopping', session_id = 's', port = 4324, profile = 'lazyrexlab-4324', fingerprint = 'stop-v1/x', saved_at = now}},
  }
  local s = load_sandbox(T.plugin_dir, getfenv(1), {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    ps = function() return {ok = true, stdout = '00:05 /bin/sh ' .. T.plugin_dir .. '/tunnels-run.sh op-1 ' .. T.fixture .. ' lazyrexlab-4321 127.0.0.1:4321\n'} end,
    rex = {
      ['session.list'] = function() return {sessions = {{session_id = 's'}, {session_id = 'plugin'}}} end,
      ['session.list_blocks'] = function(a)
        if a.session_id ~= 's' then return {blocks = {}} end
        return {blocks = {{block_id = 'b1', label = 'lazyrex-tunnel:op-1'}, {block_id = 'live'}, {block_id = 'stopping'}}}
      end,
      ['com.superlogical.terminal.process'] = function() return {child = {pid = 77}} end,
      ['com.superlogical.terminal.format'] = function(a)
        if a.block_id == 'live' then return {content = 'lazyrex-tunnel-url: https://live.example\n"type":"connected"'} end
        return {content = ''}
      end,
      ['block.close'] = function() return {} end,
    }})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  -- The plugin starts with no state (the start maintenance); then the state is set.
  s:tick()
  s.catalog = copy(catalog)
  local reply = s:perform('view.render', {route = '/panels/tunnels', user = 'user', render = 'r1'})
  expect(reply.error, 'the render').to_be(nil)
  local text = rex.json.encode(reply.result)
  for _, want in ipairs({'fw/b1', 'fw/live', 'https://live.example', 'fw/stopping', 'Stopping'}) do
    assert_true(text:find(want, 1, true) ~= nil, 'the panel shows ' .. want .. ': ' .. text)
  end
  assert_true(text:find('fw/gone', 1, true) == nil, 'the panel hides the gone forward')
  expect(s.rev, 'the render wrote nothing').to_be(1)
  expect(s.catalog, 'the state is unchanged').to_equal(catalog)
  expect(next(s.ops), 'no operation result').to_be(nil)
  expect(count(s.hub_calls, 'hub.ui.invalidate'), 'no refresh from the render').to_be(0)
  -- Maintenance (the render's kick) writes what the panel showed, and refreshes the open view.
  s:tick()
  expect(s.catalog.intents['op-1'], 'the intent goes').to_be(nil)
  expect(s.catalog.forwards.b1.op, 'the proven block is the forward').to_be('op-1')
  expect(s.ops['op-1'].result).to_equal({panel = {command = 'tunnels'}})
  expect(s.catalog.forwards.live.url).to_be('https://live.example')
  expect(s.catalog.forwards.gone, 'the gone forward goes').to_be(nil)
  assert_true(s.catalog.cleanups['lazyrexlab-4323'] ~= nil, 'the gone forward leaves a cleanup')
  expect(next(s.catalog.stops), 'the stop finished').to_be(nil)
  expect(s.catalog.forwards.stopping, 'the stopped forward goes').to_be(nil)
  assert_true(count(s.hub_calls, 'hub.ui.invalidate') > 0, 'maintenance refreshes the open view')
end)
