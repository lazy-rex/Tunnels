-- Unknown create results (tunnels.lua header). A Forward intent is saved before session.new_block.
-- If the create result is lost, the plugin adopts the block only with process proof: one block with
-- the label lazyrex-tunnel:<key>, whose process runs tunnels-run.sh with the key, started after the
-- intent. Otherwise the intent stays pending and keeps its port until its session closes. A cleanup
-- with an unknown create result keeps its profile, also across a restart. Ported from
-- tests/tunnels-cleanup-contract.lua (real hub instead of a fake Rex) and the plugin header rules.
-- The intents and cleanups are written with write(), as a plugin that lost a reply leaves them.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local alice = agent('alice')
local S = session('tunnels-recovery')
local pane = T.shell(S, 'work')

local function fingerprint(p, session_id) local o = tostring(p); return 'forward/5:other/' .. #o .. ':' .. o .. '/' .. session_id end
local function intent(id, p, session_id, source)
  return {session_id = session_id, source_block = source, port = p, target = '127.0.0.1:' .. p, profile = T.prefix .. p,
    fingerprint = fingerprint(p, session_id), created = os.date('!%Y-%m-%dT%H:%M:%SZ'), saved_at = os.time() - 1,
    phase = 'sending', creator = {kind = 'user'}}
end
local function save(f) local v = T.catalog(); v.intents = v.intents or {}; v.cleanups = v.cleanups or {}; f(v); write({{key = 'forwards', value = v}}) end
local function labeled(session_id, label, command)
  return rex.call('session.new_block', {session_id = session_id, flavor = 'com.superlogical.terminal.shell', label = label,
    options = {command = command, login = false, exit = {on_completion = false}}}).block_id
end
local function pending(id) for _, x in pairs(T.list(alice).pending or {}) do if x.id == id then return x end end end

test('an intent with process proof is adopted, and its key replays', function()
  local p = T.port()
  T.forget(p)
  save(function(v) v.intents['rec-proof'] = intent('rec-proof', p, S, pane.block) end)
  local b = labeled(S, 'lazyrex-tunnel:rec-proof', {'/bin/sh', T.plugin_dir .. '/tunnels-run.sh', 'rec-proof', T.fixture, T.prefix .. p, '127.0.0.1:' .. p})
  local v = T.open_panel(pane) -- a render reconciles
  wait('the block is adopted', function() return T.catalog().forwards[b] ~= nil end, 15)
  expect((T.catalog().intents or {})['rec-proof']).to_be(nil)
  expect(T.forward_of(p, alice).id).to_be(b)
  expect(pending('rec-proof')).to_be(nil)
  expect(T.catalog().forwards[b].creator).to_equal({kind = 'user'})
  -- The same key from the form replays the saved result: no second block.
  local op = T.submit(T.open_form(pane), p, 'rec-proof')
  expect(op.status).to_be('succeeded')
  expect(#T.tunnel_blocks(S)).to_be(1)
  expect(T.panel(S):action('fw/' .. b, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  T.no_cleanup_for(p)
end)

test('an intent without proof stays pending, keeps its port, and is dropped when its session closes', function()
  local S2 = session('tunnels-recovery-two')
  local two = T.shell(S2, 'two')
  local p = T.port()
  save(function(v) v.intents['rec-none'] = intent('rec-none', p, S2, two.block) end)
  -- A block with the label but another process: no proof.
  labeled(S2, 'lazyrex-tunnel:rec-none', {'/bin/sleep', '600'})
  local v = T.open_panel(pane)
  local row = wait('the pending row', function() return T.row(v, 'intent/rec-none') end, 10)
  expect(row.label).to_match('^Port ' .. p .. ' · Unknown start result')
  expect(row.items[1].action).to_be(nil)
  local x = pending('rec-none')
  expect(x.port).to_be(p)
  expect(x.session_id).to_be(S2)
  -- The port stays reserved.
  local op = T.submit(T.open_form(pane), p, 'rec-other')
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('already forwarded')
  -- The same key with the same content: the result is still unknown, and nothing is sent again.
  op = T.submit(T.open_form(two), p, 'rec-none')
  expect(op.status).to_be('failed')
  expect(op.error.code).to_be('unresolved')
  expect(#T.tunnel_blocks(S2)).to_be(1)
  close_session(S2)
  v = T.open_panel(pane)
  wait('the intent is dropped', function() return (T.catalog().intents or {})['rec-none'] == nil end, 15)
  expect(pending('rec-none')).to_be(nil)
  T.no_cleanup_for(p)
end)

test('two labeled blocks are no proof', function()
  local p = T.port()
  -- Both blocks exist before the intent: a maintenance pass between two creates would see one
  -- candidate with proof. saved_at is one second back, so both processes started after it.
  local cmd = {'/bin/sh', T.plugin_dir .. '/tunnels-run.sh', 'rec-two', T.fixture, T.prefix .. p, '127.0.0.1:' .. p}
  local b1, b2 = labeled(S, 'lazyrex-tunnel:rec-two', cmd), labeled(S, 'lazyrex-tunnel:rec-two', cmd)
  save(function(v) v.intents['rec-two'] = intent('rec-two', p, S, pane.block) end)
  T.open_panel(pane)
  rex.sleep(2)
  expect(pending('rec-two').port).to_be(p)
  expect(T.catalog().forwards[b1]).to_be(nil)
  expect(T.catalog().forwards[b2]).to_be(nil)
  -- Clean up as a session close would: close the blocks, drop the intent.
  rex.call('block.close', {session_id = S, block_id = b1})
  rex.call('block.close', {session_id = S, block_id = b2})
  save(function(v) v.intents['rec-two'] = nil; v.cleanups[T.prefix .. p] = {phase = 'new'} end)
  T.open_panel(pane)
  T.no_cleanup_for(p)
end)

test('a cleanup with an unknown create result keeps its port across a restart and starts no down', function()
  local p = T.port()
  local profile = T.prefix .. p
  save(function(v) v.cleanups[profile] = {phase = 'sending', key = 'unknown-down', saved_at = os.time()} end)
  T.open_panel(pane) -- a render kicks maintenance
  rex.sleep(2)
  local op = T.submit(T.open_form(pane), p)
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('still stopping its previous tunnel')
  expect(#T.tunnel_blocks(S)).to_be(0)
  -- No down starts for an unknown create: no cleanup block, no down call.
  expect(#T.down_blocks()).to_be(0)
  expect(T.down_calls(p)).to_be(0)
  T.restart()
  rex.sleep(3)
  local c = T.catalog().cleanups[profile]
  expect(c.phase).to_be('sending')
  expect(c.key).to_be('unknown-down')
  expect(#T.down_blocks()).to_be(0)
  expect(T.down_calls(p)).to_be(0)
  op = T.submit(T.open_form(pane), p)
  expect(op.status).to_be('failed')
  -- A cleanup that Rex shows as running with exit 0 releases the profile (lifecycle.lua runs the real path).
  save(function(v) v.cleanups[profile] = nil end)
  local b = T.forward_other(pane, p)
  rex.call('block.close', {session_id = S, block_id = b})
  T.no_cleanup_for(p)
end)
