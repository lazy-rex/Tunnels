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
  T.edit(function(value)
    value.forwards = value.forwards or {}
    value.forwards[b] = {session_id = S, source_block = pane.block, port = p, target = '127.0.0.1:' .. p, profile = T.prefix .. p,
    op = 'seed-' .. p, created = os.date('!%Y-%m-%dT%H:%M:%SZ'), creator = {kind = 'agent', agent = alice.id}}
  end)
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
  local op = with_injection({match = {sql_commit_writes = 'stops'}, fail = 'refused write', times = 1}, 1, function()
    local _, key = v:admit('action', {node_id = 'fw/' .. b, action = 'stop', input = {item_id = 'stop'}})
    -- The first operation read raises once, so wait catches an error during settle. The test gets
    -- op as a return value: a local that the callback set reads stale after the catch (LazyRex
    -- docs/rex-protocol.md, "Rex Lua runtime").
    local original, once = H.operation, {raised = false}
    H.operation = function(...)
      if not once.raised then once.raised = true; error('test: transient operation read') end
      return original(...)
    end
    local ok, result = pcall(v.settle, v, key, 10)
    H.operation = original
    if not ok then error(result, 0) end
    assert_true(once.raised, 'the operation read raised once')
    return result
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
  with_injection({match = {sql_commit_writes = 'stops'}, fail = 'refused write', times = 1}, 1, function()
    local e = expect_error(function() alice:call('tunnels.stop', {forward = b, key = 'refused'}) end, 'refused write')
    expect(e.code).to_be('injected_failure')
  end)
  expect(alice:call('tunnels.stop', {forward = b, key = 'refused'}).stopped).to_be(true)
  T.no_cleanup_for(p)
end)

-- rex_ok(): a Rex refusal keeps its code too. Rex refuses only on races that the plugin checks
-- first (a block or anchor that closes between the listing and the call), so these tests run the
-- plugin in the sandbox (tests/lib/sandbox.lua). The stub returns the error text that Rex
-- 0.0.1792158932-g88fd41 gave in the lab for the same calls.
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)
local function rex_text(message, status, code)
  return 'stream response "control-15" failed: ' .. message .. (code and (' (status=' .. status .. ' code=' .. code .. ')') or '')
end
-- forward_sandbox answers a sandbox with one detached tunnel block t whose source pane src is placed.
local function forward_sandbox(overrides)
  overrides['session.list_blocks'] = overrides['session.list_blocks'] or function()
    return {blocks = {{block_id = 't', placement = 'detached'}, {block_id = 'src', placement = 'placed'}}}
  end
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    catalog = {forwards = {t = {session_id = 's', source_block = 'src', port = 4321, target = '127.0.0.1:4321', profile = 'lazyrexlab-4321',
      op = 'seed', created = '2026-10-19T00:00:00Z', creator = {kind = 'user'}}}},
    rex = overrides})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end
local function panel_action(s, item)
  return s:perform('view.action', {user = 'user', route = '/panels/tunnels', node_id = 'fw/t', action = item, input = {item_id = item}, operation_key = 'k-' .. item})
end

test('a Rex refusal of Show Logs keeps its code and message (sandbox)', function()
  local s = forward_sandbox({['session.move_block'] = function()
    return nil, rex_text('block src not found in any window', 404, 'not_found')
  end})
  local reply = panel_action(s, 'show')
  assert_true(reply.error, 'Show Logs fails')
  expect(reply.error.code).to_be('not_found')
  expect(reply.error.message).to_be('block src not found in any window')
end)

test('a Rex refusal of the stop close keeps its code; the stop stays saved (sandbox)', function()
  local s = forward_sandbox({['block.close'] = function()
    return nil, rex_text('block not found: t', 404, 'not_found')
  end})
  local reply = panel_action(s, 'stop')
  assert_true(reply.error, 'Stop fails')
  expect(reply.error.code).to_be('not_found')
  expect(reply.error.message).to_be('block not found: t')
  expect(next(s.catalog.stops or {}), 'the stop is saved for a retry or maintenance').not_to_be(nil)
  expect(s.catalog.forwards.t.port).to_be(4321)
end)

test('a Rex error without a code, or with timeout, stays unavailable (sandbox)', function()
  for _, text in ipairs({rex_text('connection reset'), rex_text('deadline', 504, 'timeout'), rex_text('gone', 503, 'disconnected')}) do
    local s = forward_sandbox({['session.move_block'] = function() return nil, text end})
    local reply = panel_action(s, 'show')
    expect(reply.error.code, text).to_be('unavailable')
  end
end)

-- A definite Rex refusal of the tunnel create: no block exists, so the intent must not stay as an
-- unknown result that holds the port. The text is what Rex 0.0.1792158932-g88fd41 gave in the lab
-- for a label over 128 characters.
local function form_forward(s, key, port)
  return s:perform('view.action', {user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward',
    input = {values = {port = 'other', other = tostring(port)}}, context = {session_id = 's', source_block_id = 'src'}, operation_key = key})
end
local function create_sandbox(create)
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    rex = {['session.new_block'] = create}})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end

test('a definite Rex refusal of the tunnel create ends the Forward with its code and keeps no intent (sandbox)', function()
  local calls = {n = 0}
  local s = create_sandbox(function() calls.n = calls.n + 1; return nil, rex_text('input: validating: label must be at most 128 characters', 400, 'bad_request') end)
  local reply = form_forward(s, 'refused-create', 4321)
  assert_true(reply.error, 'Forward fails')
  expect(reply.error.code).to_be('bad_request')
  expect(reply.error.message).to_match('label must be at most 128 characters')
  expect(next(s.catalog.intents or {}), 'no intent holds the port').to_be(nil)
  expect(next(s.catalog.cleanups or {}), 'no cleanup: no block ran').to_be(nil)
  -- The key replays the refusal; it never creates again.
  local again = form_forward(s, 'refused-create', 4321)
  expect(again.error.code).to_be('bad_request')
  expect(calls.n, 'one create').to_be(1)
end)

test('a create error other than a validation refusal keeps the intent as an unknown result (sandbox)', function()
  -- Text and table forms. Only bad_request is known to come before a create.
  for _, err in ipairs({rex_text('connection reset'), rex_text('deadline', 504, 'timeout'), rex_text('crash', 500, 'internal'),
      rex_text('new', 409, 'some_future_code'), {code = 'timeout', message = 'deadline'}, {code = 'disconnected', message = 'gone'},
      {code = 'internal', message = 'crash'}, {code = 'not_found', message = 'session'}}) do
    local s = create_sandbox(function() return nil, err end)
    local reply = form_forward(s, 'lost-create', 4321)
    local label = type(err) == 'table' and err.code or err
    expect(reply.error.code, label).to_be('unavailable')
    expect(s.catalog.intents['lost-create'].port, label).to_be(4321)
  end
end)

test('a table bad_request is a refusal too (sandbox)', function()
  local s = create_sandbox(function() return nil, {code = 'bad_request', message = 'label must be at most 128 characters'} end)
  expect(form_forward(s, 'table-refused', 4321).error.code).to_be('bad_request')
  expect((next(s.catalog.intents or {}))).to_be(nil)
end)

test('an internal error after a real create keeps the reservation; the retry adopts the block with proof (sandbox)', function()
  local st = {created = false, calls = 0}
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    -- ps shows the run script with the key, started one second ago.
    ps = function() return {ok = true, stdout = '   00:01 /bin/sh ' .. T.plugin_dir .. '/tunnels-run.sh internal-1 ' .. T.fixture .. ' lazyrexlab-4321 127.0.0.1:4321\n'} end,
    rex = {
      -- Rex creates the block, then answers internal.
      ['session.new_block'] = function() st.calls = st.calls + 1; st.created = true; return nil, rex_text('crash after create', 500, 'internal') end,
      ['session.list_blocks'] = function()
        return {blocks = st.created and {{block_id = 'b1', label = 'lazyrex-tunnel:internal-1', placement = 'detached'}} or {}}
      end,
      ['com.superlogical.terminal.process'] = function() return {child = {pid = 77}} end,
    }})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  expect(form_forward(s, 'internal-1', 4321).error.code).to_be('unavailable')
  expect(s.catalog.intents['internal-1'].port, 'the port stays reserved').to_be(4321)
  expect(form_forward(s, 'other-key', 4321).error.code).to_be('conflict')
  local again = form_forward(s, 'internal-1', 4321)
  expect(again.result).to_equal({panel = {command = 'tunnels'}})
  expect(s.catalog.forwards.b1.port).to_be(4321)
  expect((next(s.catalog.intents or {}))).to_be(nil)
  expect(st.calls, 'no second create').to_be(1)
end)
