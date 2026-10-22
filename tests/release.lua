-- Release reservation (decision "Cleanup attempt fence", J). A legacy cleanup record (no fence_v) in
-- phase sending has an unknown create result, and nothing releases it automatically. The user (the
-- panel row, then the confirmation form) or an agent (tunnels.release) releases it with an explicit
-- risk acceptance. Both paths call one handler. The sandbox tests use tests/lib/sandbox.lua; the lab
-- tests run the real hub, the renderer path and the fake opentunnel.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)

local WARNING = 'The old stop command may still run. If it runs, it stops the next forward of this profile.'
local PROFILE = 'lazyrexlab-4321'
local function legacy(key) return {phase = 'sending', key = key, saved_at = os.time() - 1} end
local function release_sandbox(c)
  local s = load_sandbox(T.plugin_dir, base, {
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture}, executables = {[T.fixture] = true},
    catalog = {cleanups = {[PROFILE] = c}}})
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end
local function record(s) return (s.catalog.cleanups or {})[PROFILE] end
-- agent_release calls tunnels.release as the agent alice, through hub.forward.
local function agent_release(s, args) return s:perform('hub.forward', {action = 'tunnels.release', args = args, requester_pid = 7}) end
local function release_args(attempt, key) return {profile = PROFILE, attempt = attempt, accept_risk = true, key = key} end
-- open_form runs the panel action of the cleanup row and answers the form route.
local function open_form(s)
  local reply = s:perform('view.action', {user = 'user', route = '/panels/tunnels', node_id = 'cleanup/' .. PROFILE, action = 'release', input = {}, operation_key = 'open'})
  assert_true(reply.result and reply.result.form, 'the form opens: ' .. show(reply))
  return reply.result.form
end
local function submit(s, route, values, key)
  return s:perform('view.action', {user = 'user', route = route, node_id = 'release', action = 'release', input = {values = values}, operation_key = key})
end
local function find(nodes, id) for _, n in ipairs(nodes or {}) do if n.id == id then return n end end end

test('an agent release ends a legacy sending record; the result says released (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  local reply = agent_release(s, release_args('A', 'k1'))
  expect(reply.result).to_equal({released = true, profile = PROFILE, attempt = 'A'})
  expect(record(s)).to_be(nil)
  local saved = s.ops['release/5:agent/5:alice/2:k1/']
  assert_true(saved, 'the operation result is saved in the same batch')
  expect(saved.result).to_equal(reply.result)
  expect(s.rev, 'one write').to_be(2)
end)

test('accept_risk must be the boolean true: nothing changes and nothing is saved (sandbox)', function()
  for _, value in ipairs({false, 'true', 1}) do
    local s = release_sandbox(legacy('A'))
    local args = release_args('A', 'k1')
    args.accept_risk = value
    local reply = agent_release(s, args)
    expect(reply.error.code, tostring(value)).to_be('invalid_input')
    -- false reaches the plugin, which names the risk. Another type is refused by the SDK argument
    -- check (the schema says boolean), as the hub keymap check refused it on a direct call before.
    expect(reply.error.message).to_match(value == false and 'The old stop command may still run' or 'accept_risk must be boolean')
    expect(record(s).key).to_be('A')
    expect(s.rev, 'no write').to_be(1)
    expect(next(s.ops), 'no operation result').to_be(nil)
  end
  local s = release_sandbox(legacy('A'))
  local args = release_args('A', 'k1')
  args.accept_risk = nil
  expect(agent_release(s, args).error.code).to_be('invalid_input')
  expect(s.rev).to_be(1)
  -- The check comes before the replay lookup: a saved release of the key does not answer it.
  agent_release(s, release_args('A', 'k2'))
  args = release_args('A', 'k2')
  args.accept_risk = false
  expect(agent_release(s, args).error.code).to_be('invalid_input')
end)

test('the form needs the checkbox: nothing changes without it (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  local route = open_form(s)
  for _, values in ipairs({{}, {accept = false}, {accept = 'true'}}) do
    local reply = submit(s, route, values, 'f1')
    expect(reply.error.code).to_be('invalid_input')
    expect(reply.error.message).to_match('I accept this risk')
  end
  expect(record(s).key).to_be('A')
  expect(s.rev, 'no write').to_be(1)
  local reply = submit(s, route, {accept = true}, 'f1')
  expect(reply.result).to_equal({released = true, profile = PROFILE, attempt = 'A', close_form = true})
  expect(record(s)).to_be(nil)
end)

test('only a legacy sending record of the same attempt is released; others refuse with conflict (sandbox)', function()
  local cases = {
    {'another attempt owns the profile', legacy('B')},
    {'a fenced record', {phase = 'sending', key = 'A', saved_at = 0, fence_v = 1, attempt = '/x/A'}},
    {'a legacy running record', {phase = 'running', key = 'A', saved_at = 0, block_id = 'b'}},
    {'a legacy closing record', {phase = 'closing', key = 'A', saved_at = 0, block_id = 'b', result = {ok = true}}},
    {'a retry record', {phase = 'retry', key = 'A', retry_at = 0}},
    {'a new record', {phase = 'new'}},
  }
  for _, case in ipairs(cases) do
    local s = release_sandbox(case[2])
    local reply = agent_release(s, release_args('A', 'k1'))
    expect(reply.error and reply.error.code, case[1]).to_be('conflict')
    expect(record(s), case[1] .. ': the record stays').to_equal(case[2])
    expect(next(s.ops), case[1] .. ': no result is saved').to_be(nil)
  end
  local s = release_sandbox(nil)
  expect(agent_release(s, release_args('A', 'k1')).error.code, 'no record').to_be('conflict')
end)

test('after a revision conflict the checks run on the new record (sandbox)', function()
  -- Another writer replaces the record between the read and the write: attempt B now owns the profile.
  local s = release_sandbox(legacy('A'))
  s.before_batch = function(x) x.catalog.cleanups[PROFILE] = legacy('B'); x.rev = x.rev + 1 end
  local reply = agent_release(s, release_args('A', 'k1'))
  expect(s.conflicts, 'the first write met a conflict').to_be(1)
  if not (reply.error and reply.error.code == 'conflict') then error('expected conflict: ' .. show(reply), 0) end
  expect(record(s).key, 'B stays').to_be('B')
  expect(next(s.ops)).to_be(nil)
  -- The phase changes between the read and the write.
  s = release_sandbox(legacy('A'))
  s.before_batch = function(x) x.catalog.cleanups[PROFILE].phase = 'running'; x.rev = x.rev + 1 end
  expect(agent_release(s, release_args('A', 'k1')).error.code).to_be('conflict')
  expect(record(s).phase).to_be('running')
  -- An unrelated change: the retry keeps it and releases the record.
  s = release_sandbox(legacy('A'))
  s.before_batch = function(x) x.catalog.forwards = {b9 = {port = 9}}; x.rev = x.rev + 1 end
  expect(agent_release(s, release_args('A', 'k1')).result.released).to_be(true)
  expect(s.conflicts).to_be(1)
  expect(record(s)).to_be(nil)
  expect(s.catalog.forwards.b9.port, 'the other change stays').to_be(9)
end)

test('a replay answers the first result after attempt B owns the profile; B stays (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  local first = agent_release(s, release_args('A', 'k1')).result
  s.catalog.cleanups = {[PROFILE] = legacy('B')}
  local rev = s.rev
  expect(agent_release(s, release_args('A', 'k1')).result).to_equal(first)
  expect(record(s).key, 'B stays').to_be('B')
  expect(s.rev, 'no write').to_be(rev)
  -- The same key with other content.
  expect(agent_release(s, release_args('B', 'k1')).error.code).to_be('operation_conflict')
  expect(record(s).key).to_be('B')
end)

test('the view and the agent path share the handler and keep separate key namespaces (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  local route = open_form(s)
  expect(submit(s, route, {accept = true}, 'same').result.released).to_be(true)
  expect(s.ops['release/4:user/4:same/'], 'the user key').not_to_be(nil)
  -- The agent's key "same" is another operation: it is no replay of the user's, so it meets the
  -- released profile.
  local reply = agent_release(s, release_args('A', 'same'))
  expect(reply.error.code).to_be('conflict')
  -- The other order: the agent first, then the user with the same key.
  s = release_sandbox(legacy('A'))
  route = open_form(s)
  expect(agent_release(s, release_args('A', 'same')).result.released).to_be(true)
  expect(submit(s, route, {accept = true}, 'same').error.code).to_be('conflict')
end)

test('the panel offers Release reservation only for a legacy sending record; the form names it (sandbox)', function()
  local function panel(s) return s:perform('view.render', {user = 'user', route = '/panels/tunnels'}).result.tree.nodes end
  local s = release_sandbox(legacy('i&d%1 x'))
  local row = find(panel(s), 'cleanup/' .. PROFILE)
  expect(row.action.name).to_be('release')
  expect(row.action.user_only).to_be('navigation')
  expect(row.text).to_match('unknown start result')
  local route = open_form(s)
  expect(route:sub(1, 15)).to_be('/forms/release?')
  local tree = s:perform('view.render', {user = 'user', route = route}).result.tree
  expect(find(tree.nodes, 'profile').text).to_be('Profile: ' .. PROFILE)
  expect(find(tree.nodes, 'attempt').text, 'the key survives the route').to_be('Attempt: i&d%1 x')
  expect(find(tree.nodes, 'warning').text).to_be(WARNING)
  local form = find(tree.nodes, 'release')
  expect(form.submit_action.tool).to_be('tunnels.release')
  expect(form.fields[1]).to_equal({id = 'accept', label = 'I accept this risk', kind = 'boolean', required = true, value = false})
  expect(submit(s, route, {accept = true}, 'k').result.attempt).to_be('i&d%1 x')
  for _, c in ipairs({{phase = 'sending', key = 'A', saved_at = 0, fence_v = 1, attempt = '/x/A'}, {phase = 'retry', key = 'A', retry_at = os.time() + 60}}) do
    s = release_sandbox(c)
    row = find(panel(s), 'cleanup/' .. PROFILE)
    expect(row.action, c.phase .. ': no release').to_be(nil)
    local reply = s:perform('view.action', {user = 'user', route = '/panels/tunnels', node_id = 'cleanup/' .. PROFILE, action = 'release', input = {}, operation_key = 'open'})
    expect(reply.error.code).to_be('conflict')
  end
end)

test('a stale or malformed form route releases nothing (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  local route = open_form(s)
  s.catalog.cleanups[PROFILE] = legacy('B')
  local tree = s:perform('view.render', {user = 'user', route = route}).result.tree
  expect(find(tree.nodes, 'release'), 'no submit for a changed record').to_be(nil)
  expect(submit(s, route, {accept = true}, 'k').error.code).to_be('conflict')
  expect(record(s).key).to_be('B')
  for _, bad in ipairs({'/forms/release?profile=' .. PROFILE .. '&attempt=%2', '/forms/release?profile=&attempt=B', '/forms/release?attempt=B'}) do
    expect(submit(s, bad, {accept = true}, 'k').error.code, bad).to_be('invalid_input')
  end
  expect(record(s).key).to_be('B')
end)

test('tunnels.list shows the key, the phase and the legacy and releasable flags (sandbox)', function()
  local s = release_sandbox(legacy('A'))
  s.catalog.cleanups['lazyrexlab-4322'] = {phase = 'sending', key = 'F', saved_at = 0, fence_v = 1, attempt = '/x/F'}
  s.catalog.cleanups['lazyrexlab-4323'] = {phase = 'new'}
  local rows = s:perform('hub.forward', {action = 'tunnels.list', args = {}, requester_pid = 7}).result.cleanups
  expect(rows[1]).to_equal({profile = PROFILE, phase = 'sending', key = 'A', legacy = true, releasable = true})
  expect(rows[2]).to_equal({profile = 'lazyrexlab-4322', phase = 'sending', key = 'F', legacy = false, releasable = false})
  expect(rows[3]).to_equal({profile = 'lazyrexlab-4323', phase = 'new', legacy = false, releasable = false})
end)

-- Lab: the real hub and renderer path.
local alice = agent('alice')
local S = session('tunnels-release')
local pane = T.shell(S, 'work')
local function seed(p, key)
  T.edit(function(v) v.cleanups = v.cleanups or {}; v.cleanups[T.prefix .. p] = legacy(key) end)
end
local function cleanup_row(p)
  for _, c in ipairs(T.list().cleanups or {}) do if c.profile == T.prefix .. p then return c end end
end
-- close stops the forward of block b and waits until its cleanup ends.
local function close(p, b)
  expect(alice:call('tunnels.stop', {forward = b, key = 'stop-' .. b}).stopped).to_be(true)
  T.no_cleanup_for(p)
end

test('an agent releases a legacy sending record; Forward of the port works again', function()
  local p = T.port()
  seed(p, 'legacy-' .. p)
  T.open_panel(pane) -- a render kicks maintenance; the legacy record stays
  local row = wait('the legacy row', function() return cleanup_row(p) end, 10)
  expect(row.releasable).to_be(true)
  expect(row.key).to_be('legacy-' .. p)
  expect_error(function() T.forward_other(pane, p) end, 'still stopping')
  local r = alice:call('tunnels.release', {profile = T.prefix .. p, attempt = 'legacy-' .. p, accept_risk = true, key = 'rel-' .. p})
  expect(r).to_equal({released = true, profile = T.prefix .. p, attempt = 'legacy-' .. p})
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'the release runs no down').to_be(0)
  -- tunnels-run.sh runs down itself before serve. The stop adds one down: its cleanup.
  local b = T.forward_other(pane, p)
  local before = T.down_calls(p)
  close(p, b)
  expect(T.down_calls(p), 'the cleanup of the stop').to_be(before + 1)
end)

test('the user releases through the panel row and the form; the form needs the checkbox', function()
  local p = T.port()
  local profile = T.prefix .. p
  seed(p, 'legacy-' .. p)
  local v = T.open_panel(pane)
  wait('the release action', function() local n = T.row(v, 'cleanup/' .. profile); return n and n.action and n.action.name == 'release' end, 10)
  local op = v:action('cleanup/' .. profile, 'release', {})
  expect(op.status).to_be('succeeded')
  local form = user:view(op.result.form, 'tunnels', S)
  local tree = form:render()
  expect(node(tree, 'warning').text).to_be(WARNING)
  expect(node(tree, 'attempt').text).to_be('Attempt: legacy-' .. p)
  local refused = form:action('release', 'release', {values = {accept = false}})
  expect(refused.status).to_be('failed')
  expect(refused.error.code).to_be('invalid_input')
  expect(cleanup_row(p).key, 'the record stays').to_be('legacy-' .. p)
  local done = form:action('release', 'release', {values = {accept = true}})
  expect(done.status).to_be('succeeded')
  expect(done.result.released).to_be(true)
  T.no_cleanup_for(p)
end)

test('a replay answers the first result after a new legacy record owns the profile; it stays', function()
  local p = T.port()
  local profile = T.prefix .. p
  seed(p, 'a-' .. p)
  local args = {profile = profile, attempt = 'a-' .. p, accept_risk = true, key = 'replay-' .. p}
  local first = alice:call('tunnels.release', args)
  seed(p, 'b-' .. p)
  expect(alice:call('tunnels.release', args)).to_equal(first)
  expect(cleanup_row(p).key, 'B stays').to_be('b-' .. p)
  alice:call('tunnels.release', {profile = profile, attempt = 'b-' .. p, accept_risk = true, key = 'replay-b-' .. p})
  T.no_cleanup_for(p)
end)
