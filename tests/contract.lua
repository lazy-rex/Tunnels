-- The plugin contract on the real hub: the exports reach the agent face; only the hub may forward
-- a call or call view.*; a caller that the hub does not know is refused for every export; a
-- forwarded call is the same as a direct call of the same agent. No test here forwards a port.

local exports = {'tunnels.list', 'tunnels.stop', 'tunnels.ports'}

local function client(label)
  local r = rex.call('target.resolve', {kinds = {'client'}, queries = {label}})
  local x = r and r.results and r.results[1]
  if not x or x.status ~= 'resolved' then error('cannot resolve client ' .. label, 0) end
  return x.target.client_id
end

local alice = agent('alice')
local plugin = client('lazyrex-plugin:tunnels')

test('the agent face lists every export, and the plugin declares them', function()
  local face = rex.call('client.inspect', {client_id = client('lazyrex')})
  local names = {}
  for _, a in ipairs(face.actions) do names[a.name] = true end
  for _, e in ipairs(exports) do expect(names[e], e).to_be(true) end
  expect(names['tunnels.forward'], 'Forward has no agent action yet').to_be(nil)
  expect(names['view.render'], 'view actions are not exported').to_be(nil)
  local own = {}
  for _, a in ipairs(rex.call('client.inspect', {client_id = plugin}).actions) do own[#own + 1] = a.name end
  for _, e in ipairs(exports) do expect(own).to_contain(e) end
  expect(own).to_contain('hub.forward')
end)

test('a caller outside every pane is refused for every export', function()
  local args = {['tunnels.list'] = {}, ['tunnels.stop'] = {forward = 'block:x', key = 'k'}, ['tunnels.ports'] = {}}
  for _, e in ipairs(exports) do
    expect_error(function() H.perform(plugin, e, args[e]) end, 'does not recognize this agent')
  end
end)

test('only the hub may call hub.forward or view.*', function()
  local forged = {action = 'tunnels.list', args = {}, requester_pid = alice.pid}
  expect_error(function() alice:direct('hub.forward', forged) end, 'Only the hub')
  expect_error(function() H.perform(plugin, 'hub.forward', forged) end, 'Only the hub')
  local stop = {user = 'user', route = '/panels/tunnels', node_id = 'fw/block:x', action = 'stop', input = {item_id = 'stop'}, operation_key = 'forged'}
  expect_error(function() alice:direct('view.action', stop) end, 'Only the hub')
  expect_error(function() H.perform(plugin, 'view.action', stop) end, 'Only the hub')
  expect_error(function() alice:direct('view.render', {route = '/panels/tunnels', user = 'user'}) end, 'Only the hub')
end)

test('the agent face refuses an action that the plugin does not export', function()
  expect_error(function() alice:call('view.render', {route = '/panels/tunnels', user = 'user'}) end, 'view.render')
end)

test('a forwarded call is the same as a direct call of the same agent', function()
  expect(alice:call('tunnels.list', {})).to_equal(alice:direct('tunnels.list', {}))
end)

test('the arguments are checked', function()
  expect_error(function() alice:call('tunnels.stop', {forward = 'block:x'}) end, 'key')
  -- Rex checks the schema before the plugin sees the call.
  expect_error(function() alice:direct('tunnels.stop', {forward = '', key = 'k'}) end, 'minLength')
  expect_error(function() alice:direct('tunnels.stop', {forward = 'block:x', key = ''}) end, 'minLength')
  expect_error(function() alice:direct('tunnels.list', {extra = true}) end, 'extra')
  expect_error(function() alice:call('tunnels.stop', {forward = 'block:unknown', key = 'k'}) end, 'not_found')
  expect_error(function() alice:call('tunnels.ports', {session_id = 'session:unknown'}) end, 'invalid_input')
end)
