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
local function save(f) T.edit(function(v) v.intents = v.intents or {}; v.cleanups = v.cleanups or {}; f(v) end) end
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

-- plugin_session answers the session where the plugin runs its cleanup blocks: the LazyRex session
-- that the hub owns.
local function plugin_session()
  for _, s in ipairs(rex.call('session.list', {}).sessions or {}) do if s.label == 'LazyRex' then return s.session_id end end
  error('no LazyRex session in the lab', 0)
end

local function process_of(session_id, block_id)
  return rex.call('com.superlogical.terminal.process', {session_id = session_id, block_id = block_id, args = {}})
end

test('an exited block with the label of a cleanup attempt is no proof: the profile stays reserved', function()
  -- The original create of attempt key can still be outstanding (a late Rex reply). A block that
  -- only has its label and has exited may be unrelated, so it must not release the profile.
  local p = T.port()
  local profile = T.prefix .. p
  local P = plugin_session()
  local key = 'unrelated-' .. p
  local b = labeled(P, 'lazyrex-tunnel-down:' .. key, {'/usr/bin/true'})
  wait('the unrelated block exited', function() local r = process_of(P, b); return r and not r.child and r.last_exit end, 10)
  save(function(v) v.cleanups[profile] = {phase = 'sending', key = key, saved_at = os.time() - 1} end)
  T.open_panel(pane) -- a render kicks maintenance; it runs every second while a cleanup exists
  rex.sleep(4)
  local c = T.catalog().cleanups[profile]
  expect(c.phase).to_be('sending')
  expect(c.key).to_be(key)
  expect(T.down_calls(p)).to_be(0)
  local op = T.submit(T.open_form(pane), p)
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('still stopping its previous tunnel')
  save(function(v) v.cleanups[profile] = nil end)
  rex.call('block.close', {session_id = P, block_id = b})
end)

test('a cleanup attempt whose running write was lost is proven and finished, after its down ran', function()
  -- Lab evidence (reviewer lab /tmp/lrt-3109559289): the record stayed 'sending' after the down of
  -- its attempt ran, because the down process had exited and no proof was possible. The run script
  -- now waits after down with a receipt, so the attempt stays provable.
  local p = T.port()
  local profile = T.prefix .. p
  local P = plugin_session()
  local key = 'lost-running-' .. p
  save(function(v) v.cleanups[profile] = {phase = 'sending', key = key, saved_at = os.time() - 1} end)
  -- The block of the attempt, as session.new_block made it before its reply was lost.
  local b = labeled(P, 'lazyrex-tunnel-down:' .. key, {'/bin/sh', T.plugin_dir .. '/tunnels-down.sh', key, T.fixture, profile})
  wait('down ran', function() return T.down_calls(p) == 1 end, 10)
  T.open_panel(pane) -- a render kicks maintenance
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'down ran once').to_be(1)
  wait('the plugin closes the attempt block', function() return T.blocks(P)[b] == nil end, 10)
end)

test('a completed attempt that is still sending at a plugin restart is proven and finished', function()
  -- The plugin is stopped while the attempt runs, so the record is still 'sending' when it starts.
  local p = T.port()
  local profile = T.prefix .. p
  local P = plugin_session()
  local key = 'restart-sending-' .. p
  H.hub('hub.admin.stop', {plugin = 'tunnels'})
  save(function(v) v.cleanups[profile] = {phase = 'sending', key = key, saved_at = os.time() - 1} end)
  local b = labeled(P, 'lazyrex-tunnel-down:' .. key, {'/bin/sh', T.plugin_dir .. '/tunnels-down.sh', key, T.fixture, profile})
  wait('down ran', function() return T.down_calls(p) == 1 end, 10)
  expect(T.catalog().cleanups[profile].phase).to_be('sending')
  H.hub('hub.admin.start', {plugin = 'tunnels'})
  wait('the plugin answers again', function() return pcall(T.list, alice) end, 20)
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'down ran once').to_be(1)
  wait('the plugin closes the attempt block', function() return T.blocks(P)[b] == nil end, 10)
end)

test('an adopted attempt that is killed before its receipt runs down again', function()
  local p = T.port()
  local profile = T.prefix .. p
  local P = plugin_session()
  local key = 'killed-' .. p
  T.flag('slow-down', true)
  local b = labeled(P, 'lazyrex-tunnel-down:' .. key, {'/bin/sh', T.plugin_dir .. '/tunnels-down.sh', key, T.fixture, profile})
  wait('down runs', function() return T.down_calls(p) == 1 end, 10)
  save(function(v) v.cleanups[profile] = {phase = 'running', key = key, saved_at = os.time() - 1, block_id = b} end)
  T.flag('slow-down', false)
  -- Kill the wrapper and its down (one process group) before the receipt. The test made this
  -- block, and checks that the PID runs its attempt.
  local pid = tonumber(process_of(P, b).child.pid)
  local ps = rex.exec({'/bin/ps', '-o', 'command=', '-p', tostring(pid)}, {timeout = 3})
  assert_true(ps and ps.ok and ps.stdout:find(key, 1, true), 'the PID runs the attempt')
  rex.exec({'/bin/kill', '-KILL', '--', '-' .. pid}, {timeout = 3})
  T.open_panel(pane) -- a render kicks maintenance
  -- The attempt is over without a result: the record retries with a new attempt, which finishes.
  wait('a retry', function() local c = T.catalog().cleanups[profile]; return not c or c.key ~= key end, 15)
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'down ran again').to_be(2)
  wait('the plugin closes the killed block', function() return T.blocks(P)[b] == nil end, 10)
end)

-- The receipt and the close (sandbox): the stub Rex can refuse block.close, which the lab cannot.
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)
local function cleanup_sandbox(screen, closes)
  local state = {closes = 0, listed = true}
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    catalog = {cleanups = {['lazyrexlab-4321'] = {phase = 'running', key = 'k1', saved_at = 0, block_id = 'd'}}},
    rex = {
      ['session.list'] = function() return {sessions = {{session_id = 'plugin'}}} end,
      ['session.list_blocks'] = function() return {blocks = state.listed and {{block_id = 'd', placement = 'detached'}} or {}} end,
      ['com.superlogical.terminal.format'] = function() return {content = screen} end,
      ['com.superlogical.terminal.process'] = function() return {child = {pid = 1}} end,
      ['block.close'] = function()
        state.closes = state.closes + 1
        local answer = closes[state.closes]
        if answer then return {} end
        return nil, 'stream response "control-15" failed: refused (status=500 code=internal)'
      end,
    }})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s, state
end
local function cleanup_of(s) return (s.catalog.cleanups or {})['lazyrexlab-4321'] end

test('a failed close keeps the cleanup and its block; the next close finishes it (sandbox)', function()
  local s, state = cleanup_sandbox('Disconnected profile lazyrexlab-4321.\n\nlazyrex-tunnel-down-exit k1 0', {false, true})
  s:tick()
  expect(state.closes).to_be(1)
  local c = cleanup_of(s)
  expect(c.phase).to_be('closing')
  expect(c.block_id).to_be('d')
  expect(c.result).to_equal({ok = true})
  s:tick()
  expect(state.closes).to_be(2)
  expect(cleanup_of(s)).to_be(nil)
  expect(#s.creates, 'no new down').to_be(0)
end)

test('after a failed close, a listing without the block finishes the cleanup (sandbox)', function()
  local s, state = cleanup_sandbox('lazyrex-tunnel-down-exit k1 1', {false})
  s:tick()
  expect(cleanup_of(s).phase).to_be('closing')
  expect(cleanup_of(s).result).to_equal({error = 'exit status 1'})
  state.listed = false
  s:tick()
  expect(state.closes, 'no close of an absent block').to_be(1)
  local c = cleanup_of(s)
  expect(c.phase).to_be('retry')
  expect(c.block_id).to_be(nil)
end)

test('only the exact receipt line of the attempt counts (sandbox)', function()
  local screen = table.concat({'lazyrex-tunnel-down-exit other 0', 'xlazyrex-tunnel-down-exit k1 0',
    'lazyrex-tunnel-down-exit k1 0 more', 'lazyrex-tunnel-down-exit k10 0', 'output lazyrex-tunnel-down-exit k1 0'}, '\n')
  local s, state = cleanup_sandbox(screen, {true})
  s:tick()
  expect(state.closes).to_be(0)
  expect(cleanup_of(s).phase).to_be('running')
end)

-- A cleanup create that Rex refuses before it creates a block (bad_request, as for Forward) ends
-- that attempt: it goes to retry with the error. Any other create error can follow a create, so the
-- attempt stays sending (unknown result) and keeps the profile.
local function create_cleanup_sandbox(err)
  -- The stub appends to a table made before it (not through s, which is assigned later).
  local calls = {}
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    catalog = {cleanups = {['lazyrexlab-4321'] = {phase = 'new'}}},
    rex = {
      ['session.list'] = function() return {sessions = {{session_id = 'plugin'}, {session_id = 's'}}} end,
      ['session.list_blocks'] = function(a) return {blocks = a.session_id == 's' and {{block_id = 'src', placement = 'placed'}} or {}} end,
      ['session.new_block'] = function(a) calls[#calls + 1] = a; return nil, err end,
    }})
  s.calls = calls
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end

test('a definite Rex refusal of the cleanup create ends the attempt; the cleanup retries (sandbox)', function()
  for _, err in ipairs({'stream response "control-15" failed: input: validating: label must be at most 128 characters (status=400 code=bad_request)',
      {code = 'bad_request', message = 'label must be at most 128 characters'}}) do
    local s = create_cleanup_sandbox(err)
    s:tick()
    local c = cleanup_of(s)
    expect(c.phase, 'not an unknown result').to_be('retry')
    expect(c.block_id).to_be(nil)
    assert_true(type(c.retry_at) == 'number' and c.retry_at > os.time(), 'the retry waits')
    -- down did not run, so the profile stays reserved: Forward of the port is refused.
    local reply = s:perform('view.action', {user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward',
      input = {values = {port = 'other', other = '4321'}}, context = {session_id = 's', source_block_id = 'src'}, operation_key = 'after-refusal'})
    assert_true(reply.error, 'Forward fails')
    expect(reply.error.code).to_be('conflict')
    expect(reply.error.message).to_match('still stopping')
    expect(#s.calls, 'only the one cleanup create').to_be(1)
  end
end)

test('a cleanup create error other than a validation refusal stays an unknown result (sandbox)', function()
  for _, err in ipairs({'stream response "control-15" failed: crash (status=500 code=internal)', 'connection reset',
      {code = 'timeout', message = 'deadline'}, {code = 'not_found', message = 'session'}}) do
    local s = create_cleanup_sandbox(err)
    s:tick()
    expect(cleanup_of(s).phase, type(err) == 'table' and err.code or err).to_be('sending')
  end
end)
