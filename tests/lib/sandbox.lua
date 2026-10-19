-- The plugin in a sandbox: tunnels.lua loaded with a stub rex and a stub os.getenv. The stub runs
-- no process and reaches no Rex server or hub. Usage:
--   local sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
--   local s = sandbox(plugin_dir, base_env, {vars = {...}, executables = {[path] = true},
--     catalog = <forwards record value>, rex = {[method] = function(args) return result, err end}})
-- It answers the stub state: the event handlers, the last reply, the new_block calls, the saved
-- catalog, and loaded / load_error. s:perform(action, args) sends a hub request to the plugin and answers the reply.
return function(plugin_dir, base, opts)
  opts = opts or {}
  local vars, executables, overrides = opts.vars or {}, opts.executables or {}, opts.rex or {}
  local catalog = opts.catalog or {}
  local s = {handlers = {}, creates = {}, execs = {}, catalog = catalog}
  local stub = {
    args = {hub_client_id = 'hub', instance_id = 'instance', plugin_session = 'plugin'},
    on = function(name, fn) s.handlers[name] = fn end,
    after = function() end, -- No timer runs: maintenance stays off.
    exec = function(argv)
      s.execs[#s.execs + 1] = argv
      if argv[1] == '/bin/test' and argv[2] == '-x' then return {ok = executables[argv[3]] == true} end
      error('the sandbox runs no process: ' .. tostring(argv[1]))
    end,
    call = function(method, args)
      if overrides[method] then return overrides[method](args) end
      if method == 'client.perform' then
        if args.action == 'hub.store.get' then return {result = {records = {forwards = {rev = '1', value = catalog}}}} end
        if args.action == 'hub.store.op' then return {result = {found = false}} end
        if args.action == 'hub.store.batch' then catalog = args.args.ops[1].value; s.catalog = catalog; return {result = {revs = {forwards = '2'}}} end
        return {result = {}}
      end
      if method == 'session.list' then return {sessions = {{session_id = 's'}}} end
      if method == 'session.list_blocks' then return {blocks = {}} end
      if method == 'session.new_block' then s.creates[#s.creates + 1] = args; return {block_id = 'new'} end
      if method == 'client.reply' then s.reply = args end
      return {}
    end,
  }
  local env = setmetatable({rex = stub, os = setmetatable({getenv = function(name) return vars[name] end}, {__index = os})}, {__index = base})
  local chunk = assert(loadfile(plugin_dir .. '/tunnels.lua'))
  setfenv(chunk, env)
  s.loaded, s.load_error = pcall(chunk)
  function s:perform(action, args)
    self.reply = nil
    self.handlers.client_perform_requested({}, {requester = {client_id = 'hub'}, action = action, call_id = 'c', args = args})
    return self.reply
  end
  return s
end
