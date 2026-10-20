-- The plugin in a sandbox: tunnels.lua loaded with a stub rex and a stub os.getenv. The stub runs
-- no process and reaches no Rex server or hub. Usage:
--   local sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
--   local s = sandbox(plugin_dir, base_env, {vars = {...}, executables = {[path] = true},
--     catalog = <forwards record value>, ops = {[key] = {fingerprint, result}}, ps = function(argv) return result end,
--     rex = {[method] = function(args) return result, err end}})
-- It answers the stub state: the event handlers, the last reply, the new_block calls, the saved
-- catalog, the saved operation records (ops), and loaded / load_error. s:perform(action, args) sends a hub request to the plugin and answers the reply.
-- s:tick() runs the timers that the plugin set.
-- s.fs is a small file system in memory for the cleanup fence: path -> {dir = true}, {link = target}
-- or {data = text}. The stub answers /bin/test -d, /bin/mkdir [-p], /bin/ln -s, /usr/bin/readlink
-- and /bin/cat from it. opts.fs gives the start state; opts.exec(argv) answers a call first, when it
-- returns a result (for failures that the file system cannot show).
-- server.whoami answers pid 4242. A full process read (/bin/ps -axww) lists s.processes (lines
-- "<pid> <command>"; opts.processes, default only the plugin, pid 4242).
return function(plugin_dir, base, opts)
  opts = opts or {}
  local vars, executables, overrides = opts.vars or {}, opts.executables or {}, opts.rex or {}
  if vars.HOME == nil then vars.HOME = '/sandbox/home' end
  -- The stub keeps its state in fields of s: a closure that reassigns a captured local can write a
  -- detached copy after a caught error (LazyRex docs/rex-protocol.md, "Rex Lua runtime").
  local s = {handlers = {}, creates = {}, execs = {}, timers = {}, catalog = opts.catalog or {}, ops = opts.ops or {}, fs = opts.fs or {},
    processes = opts.processes or {'4242 /usr/local/bin/rex do tunnels.lua'}}
  local function parent(path) return path:match('^(.*)/[^/]+$') end
  local function fs_exec(argv)
    local fs, cmd = s.fs, argv[1]
    if cmd == '/bin/test' and argv[2] == '-d' then return {ok = fs[argv[3]] ~= nil and fs[argv[3]].dir == true} end
    if cmd == '/bin/mkdir' and argv[2] == '-p' then
      local path = ''
      for part in argv[3]:gmatch('[^/]+') do path = path .. '/' .. part; fs[path] = fs[path] or {dir = true} end
      return {ok = true}
    end
    if cmd == '/bin/mkdir' then
      if fs[argv[2]] or not (fs[parent(argv[2])] or {}).dir then return {ok = false, stderr = 'mkdir failed'} end
      fs[argv[2]] = {dir = true}
      return {ok = true}
    end
    if cmd == '/bin/ln' and argv[2] == '-s' then
      if fs[argv[4]] or not (fs[parent(argv[4])] or {}).dir then return {ok = false, stderr = 'File exists'} end
      fs[argv[4]] = {link = argv[3]}
      return {ok = true}
    end
    if cmd == '/usr/bin/readlink' then
      local e = fs[argv[2]]
      if e and e.link then return {ok = true, stdout = e.link .. '\n'} end
      return {ok = false}
    end
    if cmd == '/bin/cat' then
      local e = fs[argv[2]]
      if e and e.data then return {ok = true, stdout = e.data} end
      return {ok = false}
    end
  end
  local stub = {
    args = {hub_client_id = 'hub', instance_id = 'instance', plugin_session = 'plugin'},
    on = function(name, fn) s.handlers[name] = fn end,
    after = function(_, fn) s.timers[#s.timers + 1] = fn end, -- A timer runs only on s:tick().
    exec = function(argv)
      s.execs[#s.execs + 1] = argv
      local answer = opts.exec and opts.exec(argv)
      if answer then return answer end
      if argv[1] == '/bin/test' and argv[2] == '-x' then return {ok = executables[argv[3]] == true} end
      if argv[1] == '/bin/ps' and argv[2] == '-axww' then return {ok = true, stdout = table.concat(s.processes, '\n') .. '\n'} end
      if opts.ps and argv[1] == '/bin/ps' then return opts.ps(argv) end
      answer = fs_exec(argv)
      if answer then return answer end
      error('the sandbox runs no process: ' .. tostring(argv[1]))
    end,
    call = function(method, args)
      if overrides[method] then return overrides[method](args) end
      if method == 'client.perform' then
        if args.action == 'hub.store.get' then return {result = {records = {forwards = {rev = '1', value = s.catalog}}}} end
        if args.action == 'hub.store.op' then
          local op = s.ops[args.args.key]
          if op then return {result = {found = true, fingerprint = op.fingerprint, result = op.result}} end
          return {result = {found = false}}
        end
        if args.action == 'hub.store.batch' then
          s.catalog = args.args.ops[1].value
          if args.args.op then s.ops[args.args.op.key] = args.args.op end
          return {result = {revs = {forwards = '2'}}}
        end
        return {result = {}}
      end
      if method == 'server.whoami' then return {principal = {kind = 'peer', pid = 4242}} end
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
  -- tick runs the timers that are due now (maintenance, kicks), once each.
  function s:tick()
    local due = self.timers
    self.timers = {}
    for _, fn in ipairs(due) do fn() end
  end
  return s
end
