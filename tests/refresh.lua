-- Read tracking is the default (hub 4.2): the hub renders a view again after a write to a table that
-- its render read. Tunnels reads no SQL table; its renders read Rex and hub.store, so the SDK replies
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
  -- armed fires within 15 s; wait it out. Then a gate makes each hub.store.get fail.
  wait('no cleanup is pending', function() return next(T.catalog().cleanups or {}) == nil end, 30)
  local v = T.open_panel(web)
  wait('the panel is empty', function() local ok, n = pcall(node, v:render(), 'empty'); return ok and n ~= nil end, 10)
  rex.sleep(16)
  local gate = fault({point = 'action', action = 'hub.store.get', when = 'before', mode = 'gate', plugin = 'tunnels'})
  v:render()
  wait('the panel shows the read error', function() local ok, n = pcall(node, shown(v), 'error'); return ok and n ~= nil end, 10)
  fault_release(gate)
  wait('the panel recovers with no render from the test', function()
    local ok, n = pcall(node, shown(v), 'empty')
    return ok and n ~= nil
  end, 20)
end)
