-- A definite hub refusal is a final failure with the hub's code. It must not become "unavailable":
-- the hub retries an unavailable view operation (outcome unknown), so the operation would never end
-- and would hold later operations of this plugin in the hub's queue (Profiles defect 572a58a).
-- The refusal here is an injected store failure (code injected_failure) on the stop's intent save.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local alice = agent('alice')
local S = session('tunnels-errors')
local pane = T.shell(S, 'work')

-- seed writes a forward that an agent created, with a real lab block that runs sleep.
local function seed(p)
  local b = rex.call('session.new_block', {session_id = S, flavor = 'com.superlogical.terminal.shell',
    label = 'lazyrex-tunnel:seed-' .. p, options = {command = {'/bin/sleep', '600'}, login = false, exit = {on_completion = false}}}).block_id
  local value = T.catalog()
  value.forwards = value.forwards or {}
  value.forwards[b] = {session_id = S, source_block = pane.block, port = p, target = '127.0.0.1:' .. p, profile = T.prefix .. p,
    op = 'seed-' .. p, created = os.date('!%Y-%m-%dT%H:%M:%SZ'), creator = {kind = 'agent', agent = 'alice'}}
  write({{key = 'forwards', value = value}})
  return b
end
local function quiet()
  wait('no work in progress', function() local c = T.catalog(); return not next(c.cleanups or {}) and not next(c.stops or {}) end, 30)
end

test('a refused store write ends the view operation with the hub code; the next stop runs', function()
  local p = T.port()
  local b = seed(p)
  local v = T.open_panel(pane)
  wait('the row', function() return T.row(v, 'fw/' .. b) end, 10)
  quiet()
  local op
  with_injection({match = {writes = 'forwards'}, fail = 'refused write', times = 1}, 1, function()
    local _, key = v:admit('action', {node_id = 'fw/' .. b, action = 'stop', input = {item_id = 'stop'}})
    op = v:settle(key, 10)
  end)
  expect(op.status).to_be('failed')
  expect(op.error.code).to_be('injected_failure')
  expect(op.error.message).to_match('refused write')
  assert_true(T.blocks(S)[b], 'the refused stop closed nothing')
  -- The queue is free: the next stop of the same forward runs.
  local next_op = v:action('fw/' .. b, 'stop', {item_id = 'stop'})
  expect(next_op.status).to_be('succeeded')
  T.no_cleanup_for(p)
end)

test('a refused store write reaches an agent with the hub code', function()
  local p = T.port()
  local b = seed(p)
  quiet()
  with_injection({match = {writes = 'forwards'}, fail = 'refused write', times = 1}, 1, function()
    local e = expect_error(function() alice:call('tunnels.stop', {forward = b, key = 'refused'}) end, 'refused write')
    expect(e.code).to_be('injected_failure')
  end)
  expect(alice:call('tunnels.stop', {forward = b, key = 'refused'}).stopped).to_be(true)
  T.no_cleanup_for(p)
end)
