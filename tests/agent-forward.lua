-- Forward on the agent path (tunnels.forward) and the shared handler with the view path. The user
-- decision "Agents use the Tunnels plugin fully": agents may forward ports. An agent gives either
-- the source of a listener from tunnels.ports, or a port for the "Other port…" loopback form.
-- Agent keys have their own namespace (fwd/...), so they never meet a view key or another agent's
-- key. The replay lookup comes before any check of the current session, pane or listener.
-- Forwards use the fake opentunnel (lib/guard.lua).

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local alice, bob = agent('alice'), agent('bob')
local S = session('tunnels-agent-forward')
local pane = T.shell(S, 'work')

-- The plugin's framing of agent keys (tunnels.lua, enc and part).
local function enc(v) return (tostring(v):gsub('[^%w%-]', function(c) return string.format('_%02x', c:byte()) end)) end
local function part(v) v = tostring(v); return #v .. ':' .. v .. '/' end
local function agent_id(who, key) return 'fwd/' .. part(enc(who)) .. part(enc(key)) end
-- label_of: the plugin's block label of an agent ID (a 64-bit digest; Rex labels have at most 128 characters).
local function label_of(id)
  local a, b = 0, 0
  for i = 1, #id do local c = id:byte(i); a = (a * 31 + c) % 4294967296; b = (b * 131 + c) % 4294967291 end
  return 'lazyrex-tunnel:' .. string.format('fwd-%08x%08x', a, b)
end

local function quiet()
  wait('no work in progress', function() local c = T.catalog(); return not next(c.cleanups or {}) and not next(c.stops or {}) and not next(c.intents or {}) end, 30)
end
local function stop(id, who) return (who or alice):call('tunnels.stop', {forward = id, key = 'stop-' .. id}) end
local function entries(r, p) local list = {}; for _, x in ipairs(r.ports or {}) do if x.port == p then list[#list + 1] = x end end; return list end
local function save(f) T.edit(function(v) v.intents = v.intents or {}; v.cleanups = v.cleanups or {}; v.stops = v.stops or {}; f(v) end) end
-- ids.alice is the agent ID that the hub gives alice (the creator of her forwards). A table field:
-- in Rex Lua a closure's write to a captured local can be lost after a caught error (LazyRex
-- docs/rex-protocol.md, "Rex Lua runtime").
local ids = {}

test('a failed intent save starts no block and saves no intent; the key then works', function()
  local p = T.port()
  quiet()
  with_injection({match = {writes = 'forwards'}, fail = 'refused write', times = 1}, 1, function()
    local e = expect_error(function() alice:call('tunnels.forward', {key = 'save-fails', port = p, session_id = S}) end, 'refused write')
    expect(e.code).to_be('injected_failure')
  end)
  expect(#T.tunnel_blocks(S)).to_be(0)
  expect((next(T.catalog().intents or {}))).to_be(nil)
  local r = alice:call('tunnels.forward', {key = 'save-fails', port = p, session_id = S})
  expect(r.port).to_be(p)
  ids.alice = T.catalog().forwards[r.forward].creator.agent
  assert_true(type(ids.alice) == 'string' and ids.alice ~= '', 'the forward names its agent')
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('a source from tunnels.ports forwards that listener; the key replays, also after the listener exits', function()
  local p = T.port()
  local web = T.listen(S, p, 'web')
  T.listening(p)
  local found = entries(alice:call('tunnels.ports', {session_id = S}), p)
  expect(#found).to_be(1)
  expect(found[1].source).to_be(S .. '|' .. web.block .. '|' .. p .. '|127.0.0.1')
  local r = alice:call('tunnels.forward', {key = 'src-1', source = found[1].source})
  expect(r.port).to_be(p)
  expect(r.target).to_be('127.0.0.1:' .. p)
  expect(r.session_id).to_be(S)
  expect(r.source_block).to_be(web.block)
  expect(r.state).to_be('starting')
  local fw = T.catalog().forwards[r.forward]
  expect(fw.creator).to_equal({kind = 'agent', agent = ids.alice})
  expect(fw.op).to_be(agent_id(ids.alice, 'src-1'))
  expect(T.blocks(S)[r.forward].label).to_be(label_of(agent_id(ids.alice, 'src-1')))
  expect(T.forward_of(p).created_by).to_be(ids.alice)
  -- Same key and content: the saved result, no second block.
  expect(alice:call('tunnels.forward', {key = 'src-1', source = found[1].source})).to_equal(r)
  expect(#T.tunnel_blocks(S)).to_be(1)
  -- Same key, other content: a conflict.
  expect_error(function() alice:call('tunnels.forward', {key = 'src-1', port = p}) end, 'operation_conflict')
  -- The same key from another agent and from the view is another operation: the port is taken.
  expect_error(function() bob:call('tunnels.forward', {key = 'src-1', source = found[1].source}) end, 'already forwarded')
  local op = T.submit(T.open_form(web), found[1].source, 'src-1')
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('already forwarded')
  -- The listener exits: the saved result still replays (no scan, no listener check).
  rex.call('block.close', {session_id = S, block_id = web.block})
  wait('the listener is gone', function() return T.blocks(S)[web.block] == nil end, 10)
  expect(alice:call('tunnels.forward', {key = 'src-1', source = found[1].source})).to_equal(r)
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('two addresses on one pane and port: each source reaches its own target', function()
  local p = T.port()
  local w = rex.call('session.new_window', {session_id = S, window_label = 'dual-' .. p,
    layout = {block = {flavor = 'com.superlogical.terminal.shell', options = {login = false,
      command = {'/bin/sh', '-c', '/usr/bin/nc -lk 127.0.0.1 ' .. p .. ' >/dev/null & /usr/bin/nc -6 -lk ::1 ' .. p .. ' >/dev/null; :'}}}}})
  local dual = {session = S, block = w.block_ids[1], window = w.window_id}
  local found = wait('two listeners', function()
    local x = entries(alice:call('tunnels.ports', {session_id = S}), p)
    return #x == 2 and x
  end, 15)
  table.sort(found, function(a, b) return a.address < b.address end)
  expect(found[1].address).to_be('127.0.0.1')
  expect(found[2].address).to_be('[::1]')
  -- The form offers the same two choices.
  local values = {}
  for _, o in ipairs(node(T.open_form(dual):render(), 'forward').fields[1].options) do values[o.value] = true end
  for _, x in ipairs(found) do assert_true(values[x.source], 'the form offers ' .. x.source) end
  local targets = {'127.0.0.1:' .. p, '[::1]:' .. p}
  for i, x in ipairs(found) do
    local r = alice:call('tunnels.forward', {key = 'dual-' .. i, source = x.source})
    expect(r.target).to_be(targets[i])
    expect(T.catalog().forwards[r.forward].target).to_be(targets[i])
    expect(r.source_block).to_be(dual.block)
    expect(stop(r.forward).stopped).to_be(true)
    T.no_cleanup_for(p)
  end
  -- Other port… is loopback even while listeners exist on the port.
  local r = alice:call('tunnels.forward', {key = 'dual-manual', port = p, session_id = S, block_id = dual.block})
  expect(r.target).to_be('127.0.0.1:' .. p)
  expect(r.source_block).to_be(dual.block)
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
  rex.call('block.close', {session_id = S, block_id = dual.block})
end)

test('port defaults to the agent session and pane', function()
  local p = T.port()
  local r = alice:call('tunnels.forward', {key = 'own-pane', port = p})
  expect(r.session_id).to_be(alice.session)
  expect(r.target).to_be('127.0.0.1:' .. p)
  local own = T.blocks(alice.session)[r.source_block]
  assert_true(own ~= nil, 'the source pane is a pane of the agent session')
  local ps = rex.call('com.superlogical.terminal.process', {session_id = alice.session, block_id = r.source_block, args = {}})
  expect(ps and ps.child and tonumber(ps.child.pid)).to_be(alice.pid)
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('a 100-character key with punctuation is valid', function()
  local p = T.port()
  local key = string.sub(string.rep([[ /:'"%|.-_\]], 10), 1, 100)
  expect(#key).to_be(100)
  local r = alice:call('tunnels.forward', {key = key, port = p, session_id = S})
  local id = agent_id(ids.alice, key)
  assert_true(#id > 113, 'the ID is longer than a label can hold')
  expect(T.catalog().forwards[r.forward].op).to_be(id)
  expect(T.blocks(S)[r.forward].label).to_be(label_of(id))
  expect(alice:call('tunnels.forward', {key = key, port = p, session_id = S})).to_equal(r)
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('the arguments are checked', function()
  local p = T.port()
  local function bad(args, pattern) expect_error(function() alice:call('tunnels.forward', args) end, pattern) end
  bad({key = 'a1'}, 'either source')
  bad({key = 'a2', port = p, source = S .. '||' .. p .. '|127.0.0.1'}, 'either source')
  bad({key = 'a3', source = S .. '||' .. p .. '|127.0.0.1', session_id = S}, 'do not give session_id or block_id')
  bad({key = 'a4', source = S .. '||' .. p .. '|127.0.0.1', block_id = pane.block}, 'do not give session_id or block_id')
  bad({key = 'a5', source = 'not a source'}, 'Select a port')
  bad({key = 'a6', source = S .. '||' .. p .. '|10.0.0.0.1'}, 'Unsupported listening address')
  bad({key = 'a7', port = p, session_id = S, block_id = 'block:unknown'}, 'not a pane of that session')
  bad({key = 'a8', port = p, session_id = 'session:unknown'}, 'closed')
  -- Rex checks the schema before the plugin sees the call.
  expect_error(function() alice:direct('tunnels.forward', {key = string.rep('k', 101), port = p}) end, 'maxLength')
  expect_error(function() alice:direct('tunnels.forward', {key = 'a9', port = 70000}) end, 'maximum')
  expect_error(function() alice:direct('tunnels.forward', {key = 'a10', port = p, extra = true}) end, 'extra')
  expect(#T.tunnel_blocks(S)).to_be(0)
  expect((next(T.catalog().intents or {}))).to_be(nil)
end)

test('a saved stop or cleanup reserves its port on the tool path', function()
  local p = T.port()
  save(function(v) v.cleanups[T.prefix .. p] = {phase = 'sending', key = 'held-' .. p, saved_at = os.time() + 3600} end)
  expect_error(function() alice:call('tunnels.forward', {key = 'held-1', port = p, session_id = S}) end, 'still stopping')
  -- An injection holds the final batch of the saved stop, so maintenance cannot end it first.
  local held = inject{match = {op_key = 'held-stop-' .. p}, fail = 'held', times = 'always'}
  save(function(v) v.cleanups[T.prefix .. p] = nil; v.stops['held-stop-' .. p] = {forward = 'block:gone', session_id = S, port = p, profile = T.prefix .. p, fingerprint = 'x', saved_at = os.time()} end)
  expect_error(function() alice:call('tunnels.forward', {key = 'held-2', port = p, session_id = S}) end, 'still stopping')
  cancel_injection(held)
  wait('the saved stop ends', function() return (T.catalog().stops or {})['held-stop-' .. p] == nil end, 15)
  T.no_cleanup_for(p)
end)

test('an agent intent with an unknown create result keeps its saved target and is adopted with proof', function()
  local p = T.port()
  -- A source for a listener that does not exist now: recovery never rescans.
  local source = S .. '|' .. pane.block .. '|' .. p .. '|[::1]'
  local id = agent_id(ids.alice, 'unknown-1')
  save(function(v)
    v.intents[id] = {session_id = S, source_block = pane.block, port = p, target = '[::1]:' .. p, profile = T.prefix .. p,
      fingerprint = 'forward-agent-v1/' .. part('source') .. part(source), created = os.date('!%Y-%m-%dT%H:%M:%SZ'),
      saved_at = os.time() - 1, phase = 'sending', creator = {kind = 'agent', agent = ids.alice}}
  end)
  -- Before the block exists: unresolved, and the port stays reserved.
  expect_error(function() alice:call('tunnels.forward', {key = 'unknown-1', source = source}) end, 'unresolved')
  expect_error(function() bob:call('tunnels.forward', {key = 'other', port = p, session_id = S}) end, 'already forwarded')
  local b = rex.call('session.new_block', {session_id = S, flavor = 'com.superlogical.terminal.shell', label = label_of(id),
    options = {command = {'/bin/sh', T.plugin_dir .. '/tunnels-run.sh', id, T.fixture, T.prefix .. p, '[::1]:' .. p}, login = false, exit = {on_completion = false}}}).block_id
  local r = wait('the intent is adopted', function()
    local ok, x = pcall(alice.call, alice, 'tunnels.forward', {key = 'unknown-1', source = source})
    return ok and x
  end, 15)
  expect(r).to_equal({forward = b, port = p, target = '[::1]:' .. p, session_id = S, source_block = pane.block, state = 'starting'})
  expect(T.catalog().forwards[b].creator).to_equal({kind = 'agent', agent = ids.alice})
  expect(alice:call('tunnels.forward', {key = 'unknown-1', source = source})).to_equal(r)
  expect(stop(b).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('a legacy user operation key that looks like an agent key is not an agent operation', function()
  local p = T.port()
  -- Legacy user keys have no '/'. This one spells the agent framing with other separators.
  put_operation{key = 'fwd.' .. #ids.alice .. ':' .. enc(ids.alice) .. '.6:legacy.', fingerprint = 'forward/5:other/4:9999/' .. S, result = {panel = {command = 'tunnels'}}}
  local r = alice:call('tunnels.forward', {key = 'legacy', port = p, session_id = S})
  expect(r.port).to_be(p)
  expect(T.catalog().forwards[r.forward].op).to_be(agent_id(ids.alice, 'legacy'))
  expect(stop(r.forward).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

test('view keys: a legacy v1 record replays; a new key with another source pane conflicts; a "/" key is refused', function()
  local p = T.port()
  local two = T.shell(S, 'two')
  -- A result saved by the plugin before forward-v2 (the v1 fingerprint has no source pane).
  put_operation{key = 'legacy-view-' .. p, fingerprint = 'forward/5:other/' .. #tostring(p) .. ':' .. p .. '/' .. S, result = {panel = {command = 'tunnels'}}}
  local op = T.submit(T.open_form(pane), p, 'legacy-view-' .. p)
  expect(op.status).to_be('succeeded')
  expect(#T.tunnel_blocks(S), 'the replay started nothing').to_be(0)
  -- A new view operation: the source pane is part of the fingerprint.
  local first = T.submit(T.open_form(pane), p, 'view-v2-' .. p)
  expect(first.status).to_be('succeeded')
  -- The hub keeps the arguments of a view operation and refuses the same key with other ones
  -- before the plugin sees it. The plugin's own check of the source pane is tested in the sandbox.
  expect_error(function() T.submit(T.open_form(two), p, 'view-v2-' .. p) end, 'different arguments')
  local slash = T.submit(T.open_form(pane), T.port(), 'fwd/1:x/1:y/')
  expect(slash.status).to_be('failed')
  local f = T.forward_of(p)
  expect(f.created_by).to_be('user')
  expect(stop(f.id).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

-- The plugin's view fingerprints (sandbox): the hub refuses a changed view operation first, so only
-- the sandbox can send the plugin a saved key with other inputs.
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)
local function form_sandbox(ops)
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    ops = ops})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end
local function form_forward(s, key, port, source_block)
  return s:perform('view.action', {user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward',
    input = {values = {port = 'other', other = tostring(port)}}, context = {session_id = 's', source_block_id = source_block}, operation_key = key})
end

test('the view path replays a v1 result and conflicts on a changed source pane (sandbox)', function()
  local v1 = {fingerprint = 'forward/5:other/4:4321/s', result = {panel = {command = 'tunnels'}}}
  local s = form_sandbox({['old-key'] = v1})
  -- v1 has no source pane, so any pane replays the saved result. No create.
  expect(form_forward(s, 'old-key', 4321, 'pane-a').result).to_equal({panel = {command = 'tunnels'}})
  expect(form_forward(s, 'old-key', 4321, 'pane-b').result).to_equal({panel = {command = 'tunnels'}})
  expect(form_forward(s, 'old-key', 4322, 'pane-a').error.code).to_be('operation_conflict')
  expect(#s.creates).to_be(0)
  -- A new key is saved with forward-v2, which has the source pane.
  expect(form_forward(s, 'new-key', 4323, 'pane-a').result).to_equal({panel = {command = 'tunnels'}})
  expect(#s.creates).to_be(1)
  expect(s.ops['new-key'].fingerprint).to_be('forward-v2/5:other/1:s/6:pane-a/4:4323/')
  expect(form_forward(s, 'new-key', 4323, 'pane-a').result).to_equal({panel = {command = 'tunnels'}})
  expect(form_forward(s, 'new-key', 4323, 'pane-b').error.code).to_be('operation_conflict')
  expect(#s.creates).to_be(1)
end)
