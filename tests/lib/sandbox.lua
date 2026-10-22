-- The plugin in a sandbox: tunnels.lua loaded with a stub rex and a stub os.getenv. The stub runs
-- no process and reaches no Rex server or hub. Usage:
--   local sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
--   local s = sandbox(plugin_dir, base_env, {vars = {...}, executables = {[path] = true},
--     catalog = <forwards record value>, ops = {[key] = {fingerprint, result}}, ps = function(argv) return result end,
--     rex = {[method] = function(args) return result, err end}})
-- It answers the stub state: the event handlers, the last reply, the new_block calls, the hub actions
-- that the plugin called (hub_calls), the saved
-- catalog, the saved operation records (ops), and loaded / load_error. s:perform(action, args) sends a hub request to the plugin and answers the reply.
-- s:tick() runs the timers that the plugin set. The registration timer has run at load.
-- s.fs is a small file system in memory for the cleanup fence: path -> {dir = true}, {link = target}
-- or {data = text}. The stub answers /bin/test -d, /bin/mkdir [-p], /bin/ln -s, /usr/bin/readlink
-- and /bin/cat from it. opts.fs gives the start state; opts.exec(argv) answers a call first, when it
-- returns a result (for failures that the file system cannot show).
-- The store (tunnels_store.lua) is a fake over s.catalog and s.ops with the same calls: catalog, op
-- and update. Each update counts one write in s.rev. s.before_batch(s), if set, runs once at the start
-- of the next update, as another writer that commits before the plugin's transaction. An update whose
-- op key is saved answers op_exists (the same fingerprint) or fails with operation_conflict, and changes
-- nothing. hub.identify answers the
-- agent alice. server.whoami answers pid 4242. A full process read (/bin/ps -axww) lists s.processes (lines
-- "<pid> <command>"; opts.processes, default only the plugin, pid 4242).
return function(plugin_dir, base, opts)
  opts = opts or {}
  local vars, executables, overrides = opts.vars or {}, opts.executables or {}, opts.rex or {}
  if vars.HOME == nil then vars.HOME = '/sandbox/home' end
  -- The stub keeps its state in fields of s: a closure that reassigns a captured local can write a
  -- detached copy after a caught error (LazyRex docs/rex-protocol.md, "Rex Lua runtime").
  local s = {handlers = {}, creates = {}, execs = {}, timers = {}, hub_calls = {}, catalog = opts.catalog or {}, ops = opts.ops or {}, fs = opts.fs or {},
    processes = opts.processes or {'4242 /usr/local/bin/rex do tunnels.lua'}, rev = 1}
  local function parent(path) return path:match('^(.*)/[^/]+$') end
  local function copy(v)
    if type(v) ~= 'table' then return v end
    local r = {}
    for k, x in pairs(v) do r[k] = copy(x) end
    return r
  end
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
    json = rex.json, -- the SDK measures each request with rex.json.encode
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
        s.hub_calls[#s.hub_calls + 1] = args.action
        if args.action == 'hub.identify' then return {result = {found = true, agent = 'alice', session_id = 's'}} end
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
  -- The fake store answers copies: a change that the plugin does not write must not reach s.catalog.
  local store = {}
  function store.catalog()
    local c = copy(s.catalog)
    c.intents, c.forwards, c.cleanups, c.stops = c.intents or {}, c.forwards or {}, c.cleanups or {}, c.stops or {}
    return c
  end
  function store.op(key)
    local op = s.ops[key]
    if op then return {found = true, fingerprint = op.fingerprint, result = copy(op.result)} end
    return {found = false}
  end
  function store.update(f, op)
    local hook = s.before_batch
    s.before_batch = nil
    if hook then hook(s) end
    if op and s.ops[op.key] and s.ops[op.key].fingerprint ~= op.fingerprint then error({code = 'operation_conflict', message = 'This key has different content'}, 0) end
    if op and s.ops[op.key] then return {op_exists = store.op(op.key)} end
    local state = store.catalog()
    f(state)
    s.catalog, s.rev = state, s.rev + 1
    if op then s.ops[op.key] = copy(op) end
    return {}
  end
  env.dofile = function(path)
    if path:match('/tunnels_store%.lua$') then return {open = function() return store end} end
    return base.dofile(path)
  end
  -- The LazyRex SDK, loaded fresh with the stub rex (its state is per plugin): sdk/lua of the LazyRex
  -- checkout that runs the tests (H.args.sdk, else beside H.args.lib = <checkout>/lab/test).
  local args = base.H and base.H.args or {}
  local checkout = type(args.lib) == 'string' and args.lib:match('^(.*)/lab/test/?$')
  local sdk_dir = assert(args.sdk or (checkout and checkout .. '/sdk/lua'), 'The LazyRex SDK directory is unknown')
  local sdk_chunk = assert(loadfile(sdk_dir .. '/lazyrex.lua'))
  setfenv(sdk_chunk, env)
  local sdk = sdk_chunk()
  env.require = function(name) if name == 'lazyrex' then return sdk end return base.require(name) end
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
  -- The SDK registration timer runs at load: the migrations, the start functions (the start kick of
  -- maintenance) and hub.register. So the first s:tick() of a test runs the start maintenance.
  if s.loaded then s:tick() end
  return s
end
