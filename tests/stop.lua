-- Stop on both paths: the panel item (view) and tunnels.stop (tool). They call one handler with one
-- rule: the user may stop any forward; an agent may stop only a forward that an agent created. A
-- stop is saved before its block closes, so a key replays its first result after a failed final
-- write, maintenance, or a plugin restart. Forwards use the fake opentunnel (lib/guard.lua).

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)

math.randomseed(os.time())
local base = 43000 + math.random(0, 400) * 20
local next_port = base
local function port() next_port = next_port + 1; return next_port end
local alice, bob = agent('alice'), agent('bob')
local S = session('stop-work')
local source = rex.call('session.list_blocks', {session_id = S}).blocks[1].block_id

-- part and stop_key give the plugin's stop operation key (tunnels.lua, "Stop").
local function part(v) return #v .. ':' .. v .. '/' end
local function stop_key(agent_id, key) return 'stop/' .. part('agent') .. part(agent_id) .. part(key) end

local function catalog() return store('forwards').value or {} end
-- down_calls counts the `down` calls of port p's profile in the fake's call log.
local function down_calls(p)
  local r = rex.exec({'/bin/sh', '-c', 'grep -cx "lazyrexlab-' .. p .. ' down" "$FAKE_OT_DIR/calls.log" || true'}, {timeout = 5})
  return tonumber((r and r.stdout or ''):match('%d+')) or 0
end
local function blocks() local by_id = {}; for _, b in ipairs(rex.call('session.list_blocks', {session_id = S}).blocks) do by_id[b.block_id] = b end; return by_id end
local function listed(id) for _, f in pairs(alice:call('tunnels.list', {}).forwards or {}) do if f.id == id then return f end end end
-- quiet waits until no cleanup, stop or intent is in progress, so an injection meets only the batch under test.
local function quiet()
  wait('no work in progress', function() local c = catalog(); return not next(c.cleanups or {}) and not next(c.stops or {}) and not next(c.intents or {}) end, 30)
end
local function no_cleanup_for(p) return wait('no cleanup for ' .. p, function() return (catalog().cleanups or {})['lazyrexlab-' .. p] == nil end, 30) end

-- forward_by_user forwards p through the palette form (Other port…) and answers the forward row.
local function forward_by_user(p)
  user:command('forward_port', {session = S, block = source})
  local form = user:view('/forms/forward', 'tunnels', S)
  form:render()
  local op = form:action('forward', 'forward', {values = {port = 'other', other = tostring(p)}})
  expect(op.status).to_be('succeeded')
  return wait('the forward of ' .. p, function()
    for _, f in pairs(alice:call('tunnels.list', {}).forwards or {}) do if f.port == p then return f end end
  end, 15)
end

-- seed writes a forward that agent_id created, with a real lab block, as a later agent Forward
-- would. The block runs sleep, not opentunnel.
local function seed(p, agent_id, extra)
  local b = rex.call('session.new_block', {session_id = S, flavor = 'com.superlogical.terminal.shell',
    label = 'lazyrex-tunnel:seed-' .. p, options = {command = {'/bin/sleep', '600'}, login = false, exit = {on_completion = false}}})
  local value = catalog()
  value.forwards = value.forwards or {}
  value.forwards[b.block_id] = {session_id = S, source_block = source, port = p, target = '127.0.0.1:' .. p, profile = 'lazyrexlab-' .. p,
    op = 'seed-' .. p, created = os.date('!%Y-%m-%dT%H:%M:%SZ'), creator = agent_id and {kind = 'agent', agent = agent_id} or nil}
  for k, v in pairs(extra or {}) do value[k] = v end
  write({{key = 'forwards', value = value}})
  return b.block_id
end

local function panel()
  local v = user:view('/panels/tunnels', 'tunnels', S)
  v:render()
  return v
end

test('the user stops a forward from the panel; tunnels.list and Rex agree', function()
  local p = port()
  local f = forward_by_user(p)
  expect(f.created_by).to_be('user')
  expect(f.session_id).to_be(S)
  expect(f.source_block).to_be(source)
  assert_true(blocks()[f.id], 'the tunnel block runs')
  local v = panel()
  local row = node(v:render(), 'fw/' .. f.id)
  expect(row.items[2].action.tool).to_be('tunnels.stop')
  local op = v:action('fw/' .. f.id, 'stop', {item_id = 'stop'})
  expect(op.status).to_be('succeeded')
  expect(op.result).to_equal({forward = f.id, stopped = true})
  expect(listed(f.id)).to_be(nil)
  expect(blocks()[f.id]).to_be(nil)
  no_cleanup_for(p)
end)

test('an agent cannot stop a user forward or a forward without a creator', function()
  local p = port()
  local f = forward_by_user(p)
  expect_error(function() alice:call('tunnels.stop', {forward = f.id, key = 'user-fw'}) end, 'Only the user can stop it')
  local value = catalog()
  value.forwards[f.id].creator = nil
  write({{key = 'forwards', value = value}})
  expect_error(function() alice:call('tunnels.stop', {forward = f.id, key = 'legacy-fw'}) end, 'Only the user can stop it')
  value = catalog()
  value.forwards[f.id].creator = {kind = 'agent', agent = ''}
  write({{key = 'forwards', value = value}})
  expect_error(function() alice:call('tunnels.stop', {forward = f.id, key = 'malformed-fw'}) end, 'Only the user can stop it')
  assert_true(blocks()[f.id], 'the refused stops closed nothing')
  expect(panel():action('fw/' .. f.id, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  no_cleanup_for(p)
end)

test('an agent stops an agent forward; the key replays; another forward with the key conflicts', function()
  local p1, p2, p3 = port(), port(), port()
  local f1, f2, f3 = seed(p1, 'bob'), seed(p2, 'alice'), seed(p3, 'alice')
  expect(listed(f1).created_by).to_be('bob')
  local r = alice:call('tunnels.stop', {forward = f1, key = 'k1'})
  expect(r).to_equal({forward = f1, stopped = true})
  expect(blocks()[f1]).to_be(nil)
  expect(alice:call('tunnels.stop', {forward = f1, key = 'k1'})).to_equal(r)
  expect_error(function() alice:call('tunnels.stop', {forward = f2, key = 'k1'}) end, 'operation_conflict')
  assert_true(blocks()[f2], 'the conflict closed nothing')
  -- The same key from another caller is another operation.
  expect(bob:call('tunnels.stop', {forward = f2, key = 'k1'})).to_equal({forward = f2, stopped = true})
  -- A new key for a forward that is gone.
  expect_error(function() alice:call('tunnels.stop', {forward = f1, key = 'k-gone'}) end, 'not_found')
  -- The user stops an agent forward from the panel; the same view key with another forward conflicts.
  local v = panel()
  local op = v:action('fw/' .. f3, 'stop', {item_id = 'stop'}, 'view-stop-1')
  expect(op.status).to_be('succeeded')
  local p4 = port()
  local f4 = seed(p4, 'alice')
  v:render()
  -- The hub refuses the changed arguments at admission (view_ops); the plugin is not called.
  expect_error(function() v:action('fw/' .. f4, 'stop', {item_id = 'stop'}, 'view-stop-1') end, 'operation_conflict')
  assert_true(blocks()[f4], 'the view conflict closed nothing')
  expect(alice:call('tunnels.stop', {forward = f4, key = 'k4'}).stopped).to_be(true)
  for _, p in ipairs({p1, p2, p3, p4}) do no_cleanup_for(p) end
end)

test('a failed intent save closes no block', function()
  local p = port()
  local f = seed(p, 'alice')
  quiet()
  with_injection({match = {writes = 'forwards'}, fail = 'lost connection', times = 1}, 1, function()
    expect_error(function() alice:call('tunnels.stop', {forward = f, key = 'save-fails'}) end, 'lost connection')
  end)
  assert_true(blocks()[f], 'the block still runs')
  expect(next(catalog().stops or {})).to_be(nil)
  expect(listed(f).id).to_be(f)
  expect(alice:call('tunnels.stop', {forward = f, key = 'save-fails'}).stopped).to_be(true)
  no_cleanup_for(p)
end)

test('a failed final batch: maintenance finishes the stop; the key replays after the port is reused', function()
  local p = port()
  local f = seed(p, 'alice')
  with_injection({match = {op_key = stop_key('alice', 'final-fails')}, fail = 'lost connection', times = 1}, 1, function()
    expect_error(function() alice:call('tunnels.stop', {forward = f, key = 'final-fails'}) end, 'lost connection')
  end)
  expect(blocks()[f]).to_be(nil)
  wait('maintenance finishes the stop', function() return next(catalog().stops or {}) == nil end, 15)
  no_cleanup_for(p)
  -- The port is forwarded again; the old key replays and leaves the new forward alone.
  local again = seed(p, 'alice')
  expect(alice:call('tunnels.stop', {forward = f, key = 'final-fails'})).to_equal({forward = f, stopped = true})
  assert_true(blocks()[again], 'the new forward still runs')
  expect(listed(again).port).to_be(p)
  expect((catalog().cleanups or {})['lazyrexlab-' .. p]).to_be(nil)
  alice:call('tunnels.stop', {forward = again, key = 'final-fails-2'})
  no_cleanup_for(p)
end)

-- saved_stop is a stop record as tunnels.lua saves it before block.close.
local function saved_stop(f, p) return {forward = f, session_id = S, port = p, profile = 'lazyrexlab-' .. p, fingerprint = 'stop-v1/' .. part(f), saved_at = os.time()} end
local function tunnel_count() local n = 0; for _, b in pairs(blocks()) do if (b.label or ''):sub(1, 15) == 'lazyrex-tunnel:' then n = n + 1 end end; return n end

test('two saved stops of one forward both finish through the plugin; one cleanup; both keys replay after reuse', function()
  local p = port()
  local f = seed(p, 'alice')
  local value = catalog()
  value.stops = value.stops or {}
  value.stops[stop_key('alice', 'both-a')] = saved_stop(f, p)
  value.stops[stop_key('bob', 'both-b')] = saved_stop(f, p)
  write({{key = 'forwards', value = value}})
  panel() -- a render kicks maintenance
  wait('both stops finish', function() return next(catalog().stops or {}) == nil end, 15)
  expect(blocks()[f]).to_be(nil)
  no_cleanup_for(p)
  local again = seed(p, 'alice')
  rex.sleep(2) -- maintenance runs every second while work remains
  expect(alice:call('tunnels.stop', {forward = f, key = 'both-a'})).to_equal({forward = f, stopped = true})
  expect(bob:call('tunnels.stop', {forward = f, key = 'both-b'})).to_equal({forward = f, stopped = true})
  assert_true(blocks()[again], 'the new forward still runs')
  expect((catalog().cleanups or {})['lazyrexlab-' .. p]).to_be(nil)
  expect(down_calls(p), 'one down for the stopped forward').to_be(1)
  alice:call('tunnels.stop', {forward = again, key = 'both-c'})
  no_cleanup_for(p)
end)

test('a stop that finishes after another keeps the port reserved and adds no second cleanup', function()
  local p = port()
  local f = seed(p, 'alice')
  local ka, kb = stop_key('alice', 'held-a'), stop_key('bob', 'held-b')
  -- Bob's final batch fails ten times (one per maintenance pass, about one per second), so his
  -- saved stop outlives Alice's; then it finishes through finish_stop with the forward gone.
  inject({match = {op_key = kb}, fail = 'held', times = 10})
  local value = catalog()
  value.stops = value.stops or {}
  value.stops[ka] = saved_stop(f, p)
  value.stops[kb] = saved_stop(f, p)
  write({{key = 'forwards', value = value}})
  panel()
  wait('Alice\'s stop finishes', function() return (catalog().stops or {})[ka] == nil end, 15)
  expect(blocks()[f]).to_be(nil)
  expect((catalog().stops or {})[kb].forward, 'Bob\'s stop is still saved').to_be(f)
  -- The port stays reserved while Bob's stop is saved.
  user:command('forward_port', {session = S, block = source})
  local form = user:view('/forms/forward', 'tunnels', S)
  form:render()
  local before = tunnel_count()
  local op = form:action('forward', 'forward', {values = {port = 'other', other = tostring(p)}})
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('still stopping its previous tunnel')
  expect(tunnel_count()).to_be(before)
  -- Bob's stop finishes through the plugin after the injection is used up.
  wait('Bob\'s stop finishes', function() return (catalog().stops or {})[kb] == nil end, 30)
  no_cleanup_for(p)
  expect(bob:call('tunnels.stop', {forward = f, key = 'held-b'})).to_equal({forward = f, stopped = true})
  expect(down_calls(p), 'one down for the stopped forward').to_be(1)
end)

test('a saved stop resumes after a plugin restart and replays', function()
  local p = port()
  local f = seed(p, 'alice')
  H.hub('hub.admin.stop', {plugin = 'tunnels'})
  local value = catalog()
  value.stops = value.stops or {}
  value.stops[stop_key('alice', 'restart')] = saved_stop(f, p)
  write({{key = 'forwards', value = value}})
  H.hub('hub.admin.start', {plugin = 'tunnels'})
  wait('the restarted plugin finishes the stop', function() return next(catalog().stops or {}) == nil end, 30)
  expect(blocks()[f]).to_be(nil)
  expect(alice:call('tunnels.stop', {forward = f, key = 'restart'})).to_equal({forward = f, stopped = true})
  no_cleanup_for(p)
end)
