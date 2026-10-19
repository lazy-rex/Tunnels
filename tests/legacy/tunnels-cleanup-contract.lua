-- Contract test: the real Tunnels plugin with fake Rex/store services. Opens no tunnel.
-- Run in an isolated Rex session with plugin=/absolute/path/to/plugins/tunnels.lua.
-- This checks handler admission and plugin reload; it does not replace the real lab lifecycle test.
local plugin_path = assert(rex.args.plugin, 'plugin path is required')
local events, timers = {}, {}
local state = {intents = {}, forwards = {}, cleanups = {['lazyrex-1234'] = {phase = 'running', block_id = 'down'}}}
local observed = {creates = 0, exited = false}
rex = {
  args = {hub_client_id = 'hub', instance_id = 'instance', plugin_session = 's'},
  on = function(name, fn) events[name] = fn end,
  after = function(_, fn) timers[#timers + 1] = fn end,
  exec = function() return {ok = true} end,
  call = function(method, args)
    if method == 'client.perform' then
      if args.action == 'hub.store.get' then return {result = {records = {forwards = {rev = '1', value = state}}}} end
      if args.action == 'hub.store.batch' then state = args.args.ops[1].value; return {result = {revs = {forwards = '2'}}} end
      if args.action == 'hub.store.op' then return {result = {found = false}} end
      return {result = {}}
    end
    if method == 'session.list' then return {sessions = {{session_id = 's'}}} end
    if method == 'session.list_blocks' then return {blocks = {{block_id = 'down'}}} end
    if method == 'com.superlogical.terminal.process' then
      if observed.exited then return {last_exit = {exit_code = 0}} end
      return {child = {pid = 123}}
    end
    if method == 'session.new_block' then observed.creates = observed.creates + 1; return {block_id = 'new'} end
    if method == 'client.reply' then observed.reply = args end
    return {}
  end,
}
local function start()
  events = {}; timers = {}
  dofile(plugin_path)
  table.remove(timers, 1)()
end
local function forward()
  events.client_perform_requested({}, {requester = {client_id = 'hub'}, action = 'view.action', args = {
   user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward', operation_key = 'new-forward',
   input = {values = {port = 'other', other = '1234'}}, context = {session_id = 's', source_block_id = 'source'}}, call_id = 'probe'})
end
start(); forward()
assert(observed.reply.error and observed.reply.error.code == 'conflict' and observed.creates == 0)
assert(state.cleanups['lazyrex-1234'].block_id == 'down')
rex.args.instance_id = 'restarted'
start(); forward()
assert(observed.reply.error and observed.creates == 0 and state.cleanups['lazyrex-1234'])
print('PASS: cleanup owns profile before and after plugin reload; no duplicate cleanup or forward create')
observed.exited = true
table.remove(timers, 1)()
assert(not state.cleanups['lazyrex-1234'])
forward()
assert(not observed.reply.error and observed.creates == 1 and state.forwards.new)
print('PASS: observed cleanup exit zero releases profile and allows new forward')
state.intents = {}; state.forwards = {}; state.cleanups = {['lazyrex-1234'] = {phase = 'sending', key = 'unknown', saved_at = os.time()}}
observed.creates = 0
start(); forward()
assert(observed.reply.error and observed.creates == 0 and state.cleanups['lazyrex-1234'].phase == 'sending')
print('PASS: unknown cleanup create stays reserved without repeating create')
