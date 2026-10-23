-- The cleanup attempt fence (tunnels.lua, "Fenced attempts"; reviewed design v3). Each new attempt
-- has a random key and its own directory, made before its record is saved. The script and the
-- plugin both claim <attempt>/claim; exactly one claim succeeds. A plugin claim ends the attempt (a
-- late create runs no down); a script claim waits for the attempt's exit file. A sending record is
-- always fenced: the cleanups table refuses one without fence_v. The sandbox tests use the stub file system of
-- tests/lib/sandbox.lua; the lab tests run the real tunnels-down.sh with the fake opentunnel.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)
local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)

local PROFILE = 'lazyrexlab-4321'
local ROOT = '/sandbox/home/.local/state/lazyrex-tunnels/attempts'
-- fence_sandbox answers a sandbox whose catalog has the cleanup c of PROFILE (and fence, if given).
local function fence_sandbox(c, o)
  o = o or {}
  -- The stub reaches the sandbox through box: a table field, not a captured local (LazyRex
  -- docs/rex-protocol.md, "Rex Lua runtime").
  local box = {calls = {}}
  local stubs = {
    ['session.list'] = function() return {sessions = {{session_id = 'plugin'}}} end,
    ['session.list_blocks'] = function() return {blocks = {}} end,
    ['session.new_block'] = function(args)
      local cat = box.s.catalog
      box.calls[#box.calls + 1] = {args = args, record = cat.cleanups and cat.cleanups[PROFILE]}
      if o.create then return o.create(args) end
      return nil, 'connection reset' -- an unknown result: the record stays sending
    end,
  }
  for method, fn in pairs(o.rex or {}) do stubs[method] = fn end -- o.rex replaces a default stub
  local s = load_sandbox(T.plugin_dir, base, {
    vars = o.vars or {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture},
    executables = {[T.fixture] = true}, fs = o.fs, exec = o.exec, processes = o.processes,
    catalog = {fence = o.fence, cleanups = {[PROFILE] = c}},
    rex = stubs})
  box.s, s.calls = s, box.calls
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  return s
end
local function record(s) return (s.catalog.cleanups or {})[PROFILE] end
local function copy(t) local r = {}; for k, v in pairs(t) do r[k] = v end; return r end
-- fenced answers a fenced sending record with its attempt directory in fs.
local function fenced(fs, key)
  local dir = ROOT .. '/f1'
  fs[ROOT] = {dir = true}; fs[dir] = {dir = true}; fs[dir .. '/' .. key] = {dir = true}
  return {phase = 'sending', key = key, saved_at = os.time() - 1, fence_v = 1, attempt = dir .. '/' .. key}, dir
end

test('a new attempt gets a fence, a random key and its own directory before its create (sandbox)', function()
  local s = fence_sandbox({phase = 'new'})
  s:tick()
  local c = record(s)
  expect(c.phase).to_be('sending')
  expect(c.fence_v).to_be(1)
  expect(c.key).to_match('^%x+$')
  expect(#c.key).to_be(32)
  local fence = s.catalog.fence
  expect(fence).to_match('^' .. ROOT:gsub('%-', '%%-') .. '/%x+$')
  expect(c.attempt).to_be(fence .. '/' .. c.key)
  assert_true(s.fs[c.attempt] and s.fs[c.attempt].dir, 'the attempt directory exists')
  expect(#s.calls).to_be(1)
  -- The record was saved, with its attempt, before the create.
  expect(s.calls[1].record.attempt).to_be(c.attempt)
  expect(s.calls[1].record.phase).to_be('sending')
  local argv = s.calls[1].args.options.command
  expect(argv[2]).to_be(T.plugin_dir .. '/tunnels-down.sh')
  expect(argv[3]).to_be(c.key)
  expect(argv[5]).to_be(PROFILE)
  expect(argv[6]).to_be(c.attempt)
  expect(s.calls[1].args.label).to_be('lazyrex-tunnel-down:' .. c.key)
end)

test('an attempt directory that cannot be made sends no create and saves no attempt (sandbox)', function()
  local s = fence_sandbox({phase = 'new'}, {exec = function(argv)
    if argv[1] == '/bin/mkdir' and argv[2] ~= '-p' and argv[2]:match('/%x+/%x+$') then return {ok = false, stderr = 'File exists'} end
  end})
  s:tick()
  expect(#s.calls, 'no create').to_be(0)
  expect(record(s).phase).to_be('new')
  expect(record(s).attempt).to_be(nil)
end)

test('the saved fence is used after a HOME or XDG change (sandbox)', function()
  local fs = {['/old'] = {dir = true}, ['/old/fence'] = {dir = true}}
  local s = fence_sandbox({phase = 'new'}, {fs = fs, fence = '/old/fence',
    vars = {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture, XDG_STATE_HOME = '/elsewhere'}})
  s:tick()
  expect(record(s).attempt).to_match('^/old/fence/%x+$')
  expect(s.catalog.fence).to_be('/old/fence')
end)

test('a fenced attempt without proof: the plugin claims it, and a new attempt runs (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'aa')
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
  s:tick()
  expect(fs[c.attempt .. '/claim'].link).to_be('plugin')
  expect(record(s).phase).to_be('retry')
  expect(#s.calls).to_be(0)
  s:tick()
  expect(#s.calls, 'a new attempt').to_be(1)
  assert_true(record(s).key ~= 'aa', 'with a new key')
end)

test('a lost reply of the plugin claim: readlink tells the owner (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'bb')
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', exec = function(argv)
    -- ln runs, but its result is lost.
    if argv[1] == '/bin/ln' then fs[argv[4]] = fs[argv[4]] or {link = argv[3]}; return {ok = false, error = 'timeout'} end
  end})
  s:tick()
  expect(record(s).phase).to_be('retry')
end)

test('a script claim with exit 0 releases the profile; another code retries (sandbox)', function()
  for code, want in pairs({['0\n'] = 'released', ['0'] = 'released', ['1\n'] = 'retry', ['255\n'] = 'retry'}) do
    local fs = {}
    local c = fenced(fs, 'cc')
    fs[c.attempt .. '/claim'] = {link = 'script'}
    fs[c.attempt .. '/exit'] = {data = code}
    local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
    s:tick()
    if want == 'released' then expect(record(s), code).to_be(nil)
    else expect(record(s).phase, code).to_be('retry') end
    expect(fs[c.attempt .. '/claim'].link, 'the script claim stays').to_be('script')
  end
end)

-- WRAPPER and DOWN are ps lines of a live wrapper of key KEY and of a live down child of PROFILE.
local function wrapper_line(key) return '501 /bin/sh ' .. T.plugin_dir .. '/tunnels-down.sh ' .. key .. ' ' .. T.fixture .. ' ' .. PROFILE .. ' /x/' .. key end
local DOWN = '502 /bin/sh ' .. T.fixture .. ' --profile ' .. PROFILE .. ' down'
local PLUGIN = '4242 /usr/local/bin/rex do tunnels.lua'

test('a script claim without a valid exit file is no result: it never releases the profile (sandbox)', function()
  -- No wrapper and no down child run, so the process checks end the attempt: retry, never release.
  for _, data in ipairs({false, '', '256\n', '0 x', 'x\n', '1000\n', '-1\n', '0\n\n'}) do
    local fs = {}
    local c = fenced(fs, 'dd')
    fs[c.attempt .. '/claim'] = {link = 'script'}
    if data then fs[c.attempt .. '/exit'] = {data = data} end
    local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
    s:tick()
    expect(record(s).phase, tostring(data)).to_be('retry')
    expect(#s.calls, tostring(data)).to_be(0)
  end
  -- An unreadable exit file (cat fails) is no result either.
  local fs = {}
  local c = fenced(fs, 'de')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  fs[c.attempt .. '/exit'] = {data = '0\n'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', exec = function(argv) if argv[1] == '/bin/cat' then return {ok = false} end end})
  s:tick()
  expect(record(s).phase).to_be('retry')
end)

test('a script claim without a result waits while its wrapper or a down child runs (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'wa')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', processes = {PLUGIN, wrapper_line('wa')}})
  s:tick()
  expect(record(s).phase, 'the wrapper runs').to_be('sending')
  s.processes = {PLUGIN, DOWN}
  s:tick()
  expect(record(s).phase, 'a down child runs').to_be('sending')
  -- The wrapper of another key does not hold this attempt.
  s.processes = {PLUGIN, wrapper_line('other')}
  s:tick()
  expect(record(s).phase, 'nothing of this attempt runs').to_be('retry')
end)

test('the down check uses a second, new process list (sandbox)', function()
  -- The first list shows nothing; the down child shows only in the second list.
  local fs = {}
  local c = fenced(fs, 'wb')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  local reads = {n = 0}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', exec = function(argv)
    if argv[1] == '/bin/ps' and argv[2] == '-axww' then
      reads.n = reads.n + 1
      return {ok = true, stdout = PLUGIN .. '\n' .. (reads.n % 2 == 0 and DOWN .. '\n' or '')}
    end
  end})
  s:tick()
  expect(reads.n, 'two reads').to_be(2)
  expect(record(s).phase).to_be('sending')
end)

test('a bad process read keeps the profile (sandbox)', function()
  local bad = {
    ['ps fails'] = {exec = function(argv) if argv[1] == '/bin/ps' then return {ok = false, stderr = 'ps: failed'} end end},
    ['ps has no output'] = {exec = function(argv) if argv[1] == '/bin/ps' then return {ok = true} end end},
    ['ps does not list the plugin'] = {processes = {'1 /sbin/launchd'}},
    ['the plugin pid is unknown'] = {rex = {['server.whoami'] = function() return nil, 'refused' end}},
  }
  for name, o in pairs(bad) do
    local fs = {}
    local c = fenced(fs, 'wc')
    fs[c.attempt .. '/claim'] = {link = 'script'}
    o.fs, o.fence = fs, ROOT .. '/f1'
    local s = fence_sandbox(c, o)
    s:tick()
    expect(record(s).phase, name).to_be('sending')
    -- A script claim with exit 0 waits for a good read too (the release gate).
    fs[c.attempt .. '/exit'] = {data = '0\n'}
    s:tick()
    assert_true(record(s) ~= nil, name .. ': no release')
  end
end)

test('the release gate: exit 0 does not free the profile while a down child of it runs (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'wd')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  fs[c.attempt .. '/exit'] = {data = '0\n'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', processes = {PLUGIN, DOWN}})
  s:tick()
  expect(record(s).phase).to_be('sending')
  -- A wrapper alone does not hold the gate: only a down child can stop the next forward.
  s.processes = {PLUGIN, wrapper_line('wd')}
  s:tick()
  expect(record(s)).to_be(nil)
end)

test('the release gate holds a closing record whose result is 0 (sandbox)', function()
  -- The block is gone and the result is 0, but a down child of the profile runs.
  local s = fence_sandbox({phase = 'closing', key = 'k1', saved_at = 0, block_id = 'gone', result = {ok = true}}, {processes = {PLUGIN, DOWN}})
  s:tick()
  expect(record(s).phase).to_be('closing')
  s.processes = {PLUGIN}
  s:tick()
  expect(record(s)).to_be(nil)
end)

test('a running block that disappears retries only when nothing of its attempt runs (sandbox)', function()
  for _, fenced_record in ipairs({true, false}) do
    local c = {phase = 'running', key = 'we', saved_at = 0, block_id = 'gone'}
    if fenced_record then c.fence_v, c.attempt = 1, ROOT .. '/f1/we' end
    local s = fence_sandbox(c, {processes = {PLUGIN, wrapper_line('we')}})
    s:tick()
    expect(record(s).phase, 'the wrapper runs').to_be('running')
    s.processes = {PLUGIN, DOWN}
    s:tick()
    expect(record(s).phase, 'a down child runs').to_be('running')
    expect(#s.calls, 'no new attempt while one runs').to_be(0)
    -- Nothing runs: retry, and a new attempt (a later timer of the same tick can already send it).
    s.processes = {PLUGIN}
    s:tick()
    s:tick()
    expect(#s.calls, 'a new attempt').to_be(1)
    assert_true(record(s).key ~= 'we', 'with a new key')
  end
end)

test('a wrapper that ended without a receipt fails its attempt only when no down child runs (sandbox)', function()
  local c = {phase = 'running', key = 'wf', saved_at = 0, block_id = 'd', fence_v = 1, attempt = ROOT .. '/f1/wf'}
  local s = fence_sandbox(c, {processes = {PLUGIN, DOWN}, rex = {
    ['session.list_blocks'] = function() return {blocks = {{block_id = 'd', placement = 'detached'}}} end,
    ['com.superlogical.terminal.format'] = function() return {content = 'killed'} end,
    ['com.superlogical.terminal.process'] = function() return {last_exit = {exit_code = 137}} end,
    ['block.close'] = function() return {} end,
  }})
  s:tick()
  expect(record(s).phase, 'a down child runs').to_be('running')
  expect(record(s).result).to_be(nil)
  -- Nothing runs: the attempt fails (closing, the block closes, then retry). It never releases.
  s.processes = {PLUGIN}
  s:tick()
  assert_true(record(s) ~= nil, 'no release')
  expect(record(s).phase).to_be('retry')
end)

test('an unknown owner or a missing attempt directory keeps the profile (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'ee')
  fs[c.attempt .. '/claim'] = {link = 'other'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
  s:tick()
  expect(record(s).phase).to_be('sending')
  fs = {}
  c = copy(c)
  c.attempt = ROOT .. '/gone/ee'
  s = fence_sandbox(c, {fs = fs})
  s:tick()
  expect(record(s).phase).to_be('sending')
  expect(fs[c.attempt .. '/claim']).to_be(nil)
end)

-- A plugin session that session.list does not show is no process or fence proof.
local NO_SESSION = {['session.list'] = function() return {sessions = {}} end}

test('a missing plugin session does not bypass a live script claim (sandbox)', function()
  -- The regression of the review: the record went to retry while its wrapper still ran.
  local fs = {}
  local c = fenced(fs, 'ga')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', processes = {PLUGIN, wrapper_line('ga')}, rex = NO_SESSION})
  s:tick()
  expect(record(s).phase, 'the wrapper can still run down').to_be('sending')
  -- The fence decision applies without the session: nothing of the attempt runs, so it retries.
  s.processes = {PLUGIN}
  s:tick()
  expect(record(s).phase).to_be('retry')
  expect(#s.calls, 'no create without the session').to_be(0)
end)

test('a missing plugin session: a plugin claim retries; a script exit 0 goes through the gate (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'gb')
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', rex = NO_SESSION})
  s:tick()
  expect(fs[c.attempt .. '/claim'].link).to_be('plugin')
  expect(record(s).phase).to_be('retry')
  fs = {}
  c = fenced(fs, 'gc')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  fs[c.attempt .. '/exit'] = {data = '0\n'}
  s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', processes = {PLUGIN, DOWN}, rex = NO_SESSION})
  s:tick()
  expect(record(s).phase, 'a down child runs').to_be('sending')
  s.processes = {PLUGIN}
  s:tick()
  expect(record(s)).to_be(nil)
end)

test('a missing plugin session starts no new attempt (sandbox)', function()
  for _, phase in ipairs({'new', 'retry'}) do
    local s = fence_sandbox({phase = phase, retry_at = 0}, {rex = NO_SESSION})
    s:tick()
    expect(#s.calls, phase .. ': no create').to_be(0)
    for _, argv in ipairs(s.execs) do assert_true(argv[1] ~= '/bin/mkdir', phase .. ': no attempt directory') end
    expect(record(s).phase, phase).to_be(phase)
  end
end)

test('a missing plugin session keeps a running or a closing record as it is (sandbox)', function()
  local running = fence_sandbox({phase = 'running', key = 'ge', saved_at = 0, block_id = 'b'}, {rex = NO_SESSION})
  running:tick()
  expect(record(running).phase).to_be('running')
  expect(record(running).block_id).to_be('b')
  local closing = fence_sandbox({phase = 'closing', key = 'gf', saved_at = 0, block_id = 'b', result = {ok = true}}, {rex = NO_SESSION})
  closing:tick()
  expect(record(closing).phase).to_be('closing')
end)

-- Lab: the real script.
local S = session('tunnels-fence')
local pane = T.shell(S, 'work')
local function plugin_session()
  for _, s in ipairs(rex.call('session.list', {}).sessions or {}) do if s.label == 'LazyRex' then return s.session_id end end
  error('no LazyRex session in the lab', 0)
end
local function sh(argv) local r = rex.exec(argv, {timeout = 10}); assert_true(r and r.ok, 'exec ' .. table.concat(argv, ' ')); return r end
-- names answers the entries of directory dir. The listing is a local before the for: in Rex Lua a
-- for header that indexes a call result (f().x:gmatch(...)) runs no iteration (LazyRex
-- docs/rex-protocol.md, "Rex Lua runtime").
local function names(dir)
  local list, out = {}, sh({'/bin/ls', dir}).stdout or ''
  for name in out:gmatch('[^\n]+') do list[#list + 1] = name end
  return list
end
-- close closes the tunnel block b of port p and waits until its cleanup ends. The plugin removes the
-- forward and adds its cleanup in one commit, so the wait for no cleanup starts after the forward is gone.
local function close(p, b)
  rex.call('block.close', {session_id = S, block_id = b})
  wait('the forward of ' .. p .. ' ends', function() return (T.catalog().forwards or {})[b] == nil end, 15)
  T.no_cleanup_for(p)
end
local function screen(P, b)
  local r = rex.call('com.superlogical.terminal.format', {session_id = P, block_id = b, args = {format = 'text', trim = true, unwrap = true}})
  return r and r.content or ''
end
-- script_block runs tunnels-down.sh in a block of session P. label defaults to the cleanup label of key.
local function script_block(P, key, profile, attempt, label)
  return rex.call('session.new_block', {session_id = P, flavor = 'com.superlogical.terminal.shell', label = label or ('lazyrex-tunnel-down:' .. key),
    options = {command = {'/bin/sh', T.plugin_dir .. '/tunnels-down.sh', key, T.fixture, profile, attempt}, login = false, exit = {on_completion = false}}}).block_id
end
local lab_attempts = H.args.lab .. '/home/fence-test'
sh({'/bin/mkdir', '-p', lab_attempts})

test('a late create after the plugin claim runs no down', function()
  local p = T.port()
  local key = 'late' .. p
  local attempt = lab_attempts .. '/' .. key
  sh({'/bin/mkdir', attempt})
  sh({'/bin/ln', '-s', 'plugin', attempt .. '/claim'})
  local P = plugin_session()
  local b = script_block(P, key, T.prefix .. p, attempt)
  wait('the fenced line', function() return screen(P, b):find('lazyrex-tunnel-down-fenced ' .. key, 1, true) end, 10)
  expect(T.down_calls(p), 'no down').to_be(0)
  expect(sh({'/usr/bin/readlink', attempt .. '/claim'}).stdout).to_be('plugin\n')
  rex.call('block.close', {session_id = P, block_id = b})
end)

test('the script claims, runs down once and saves its exit; a duplicate script runs no down', function()
  local p = T.port()
  local key = 'dup' .. p
  local attempt = lab_attempts .. '/' .. key
  sh({'/bin/mkdir', attempt})
  local P = plugin_session()
  local b1 = script_block(P, key, T.prefix .. p, attempt)
  wait('the receipt', function() return screen(P, b1):find('lazyrex-tunnel-down-exit ' .. key .. ' 0', 1, true) end, 10)
  expect(sh({'/usr/bin/readlink', attempt .. '/claim'}).stdout).to_be('script\n')
  expect(sh({'/bin/cat', attempt .. '/exit'}).stdout).to_be('0\n')
  local b2 = script_block(P, key, T.prefix .. p, attempt)
  wait('the duplicate is fenced', function() return screen(P, b2):find('lazyrex-tunnel-down-fenced ' .. key, 1, true) end, 10)
  expect(T.down_calls(p), 'one down').to_be(1)
  rex.call('block.close', {session_id = P, block_id = b1})
  rex.call('block.close', {session_id = P, block_id = b2})
end)

test('a script with a missing attempt directory runs no down', function()
  local p = T.port()
  local key = 'nodir' .. p
  local P = plugin_session()
  local b = script_block(P, key, T.prefix .. p, lab_attempts .. '/missing-' .. key)
  wait('the fenced line', function() return screen(P, b):find('lazyrex-tunnel-down-fenced ' .. key, 1, true) end, 10)
  expect(T.down_calls(p), 'no down').to_be(0)
  rex.call('block.close', {session_id = P, block_id = b})
end)

test('a script without an attempt, or with an empty argument, refuses with exit 2 and runs no down', function()
  local p = T.port()
  local profile = T.prefix .. p
  local attempt = lab_attempts .. '/args' .. p
  sh({'/bin/mkdir', attempt})
  local script = T.plugin_dir .. '/tunnels-down.sh'
  for name, args in pairs({
    ['no attempt'] = {'k' .. p, T.fixture, profile},
    ['empty key'] = {'', T.fixture, profile, attempt},
    ['empty opentunnel'] = {'k' .. p, '', profile, attempt},
    ['empty profile'] = {'k' .. p, T.fixture, '', attempt},
    ['empty attempt'] = {'k' .. p, T.fixture, profile, ''},
  }) do
    local r = rex.exec({'/bin/sh', script, unpack(args)}, {timeout = 10})
    expect(r and r.code, name).to_be(2)
    expect(r.stderr, name).to_match('usage: tunnels%-down%.sh')
  end
  expect(T.down_calls(p), 'no down').to_be(0)
  expect(#names(attempt), 'no claim').to_be(0)
end)

-- lost_create saves a fenced sending cleanup of port p with key and attempt, as after a lost create
-- reply. A block that a test starts has another label, so the plugin cannot prove it as this attempt.
local function lost_create(p, key, attempt)
  local saved_at = os.time() - 1
  T.edit(function(v)
    v.cleanups = v.cleanups or {}
    v.cleanups[T.prefix .. p] = {phase = 'sending', key = key, saved_at = saved_at, fence_v = 1, attempt = attempt}
  end)
end
-- waiting_for answers the cleanup row of port p from tunnels.list when its error has text.
local function waiting_for(p, text)
  return wait('the cleanup of ' .. p .. ' waits: ' .. text, function()
    local list = T.list().cleanups or {}
    for _, c in pairs(list) do if c.profile == T.prefix .. p and c.error and c.error:find(text, 1, true) then return c end end
  end, 15)
end
local function exists(path) local r = rex.exec({'/bin/test', '-e', path}, {timeout = 10}); return r and r.ok end
-- lab_test runs a test that holds a down or gates a wrapper with raise. It removes those files
-- after the body, also when the body fails, so no held process outlives the test.
local raised = {}
local function raise(name) raised[#raised + 1] = name; T.flag(name, true) end
local function lab_test(title, body)
  test(title, function()
    local ok, err = pcall(body)
    for i = #raised, 1, -1 do T.flag(raised[i], false); raised[i] = nil end
    if not ok then error(err, 0) end
  end)
end
-- alive answers whether process pid runs (and its command has text, if given).
local function alive(pid, text)
  local r = rex.exec({'/bin/ps', '-o', 'command=', '-p', tostring(pid)}, {timeout = 10})
  if not (r and r.ok) then return false end
  local command = r.stdout or ''
  return command ~= '' and (not text or command:find(text, 1, true) ~= nil)
end
-- child_of answers the pid of the one process whose command has text (and whose parent is
-- parent, if given), or nil.
local function child_of(parent, text)
  local found
  local out = sh({'/bin/ps', '-axww', '-o', 'pid=', '-o', 'ppid=', '-o', 'command='}).stdout or ''
  for line in out:gmatch('[^\n]+') do
    local pid, ppid, command = line:match('^%s*(%d+)%s+(%d+)%s+(.*)$')
    if pid and (parent == nil or tonumber(ppid) == parent) and command:find(text, 1, true) then
      if found then return nil end
      found = tonumber(pid)
    end
  end
  return found
end

lab_test('the lab gate pauses a claimed wrapper before its down; the profile stays reserved while it waits', function()
  local p = T.port()
  local profile, key = T.prefix .. p, 'gate' .. p
  local attempt = lab_attempts .. '/' .. key
  sh({'/bin/mkdir', attempt})
  raise('down-gate-' .. key)
  -- The script starts and claims first; then the test saves the record. In the other order a
  -- maintenance pass can claim the attempt for the plugin before the script starts.
  local P = plugin_session()
  local b = script_block(P, key, profile, attempt, 'fence-test:' .. key)
  wait('the wrapper waits at the gate', function() return exists(T.fake .. '/down-gated-' .. key) end, 10)
  lost_create(p, key, attempt)
  -- The order: the claim is the script's, and down has not run.
  expect(sh({'/usr/bin/readlink', attempt .. '/claim'}).stdout).to_be('script\n')
  expect(T.down_calls(p), 'no down yet').to_be(0)
  T.open_panel(pane) -- a render kicks maintenance
  waiting_for(p, 'the stop of ' .. profile .. ' still runs')
  expect(T.catalog().cleanups[profile].key, 'the same attempt').to_be(key)
  T.flag('down-gate-' .. key, false)
  wait('the receipt', function() return screen(P, b):find('lazyrex-tunnel-down-exit ' .. key .. ' 0', 1, true) end, 10)
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'down ran once').to_be(1)
  rex.call('block.close', {session_id = P, block_id = b})
end)

lab_test('a killed wrapper whose down child lives keeps the profile until the child ends; then a retry releases it', function()
  local p = T.port()
  local profile, key = T.prefix .. p, 'kill' .. p
  local attempt = lab_attempts .. '/' .. key
  sh({'/bin/mkdir', attempt})
  raise('hold-down-' .. profile)
  -- The script claims and starts its down first; then the test saves the record (see the gate test).
  local P = plugin_session()
  local b = script_block(P, key, profile, attempt, 'fence-test:' .. key)
  wait('the down child runs', function() return T.down_calls(p) == 1 end, 10)
  expect(sh({'/usr/bin/readlink', attempt .. '/claim'}).stdout).to_be('script\n')
  lost_create(p, key, attempt)
  -- The wrapper: the one process with the test's own key in its tunnels-down.sh argv. The test
  -- started it and checks its pid by argv before the kill.
  local pid = child_of(nil, '/tunnels-down.sh ' .. key .. ' ')
  assert_true(pid, 'the wrapper pid')
  -- The down child: the one process whose parent is the wrapper and whose argv is the down of profile.
  local child = child_of(pid, '--profile ' .. profile .. ' down')
  assert_true(child, 'the down child of the wrapper')
  sh({'/bin/kill', '-KILL', tostring(pid)})
  -- The exact child outlives the wrapper (the fake ignores the hangup while it holds).
  wait('the wrapper is gone', function() return not alive(pid) end, 10)
  assert_true(alive(child, '--profile ' .. profile .. ' down'), 'the down child ' .. child .. ' still runs')
  T.open_panel(pane)
  waiting_for(p, 'an opentunnel down of ' .. profile .. ' still runs')
  expect(T.catalog().cleanups[profile].key, 'the same attempt').to_be(key)
  assert_true(not exists(attempt .. '/exit'), 'no exit file')
  assert_true(alive(child, '--profile ' .. profile .. ' down'), 'the down child still runs while the profile is kept')
  -- End only the test-owned child: it leaves its hold and exits.
  T.flag('hold-down-' .. profile, false)
  wait('the down child ' .. child .. ' ends', function() return not alive(child) end, 10)
  T.no_cleanup_for(p, 30)
  expect(T.down_calls(p), 'the retry ran down again').to_be(2)
  rex.call('block.close', {session_id = P, block_id = b})
end)

lab_test('a hanging down of the profile holds the release of a result 0', function()
  local p = T.port()
  local profile, key = T.prefix .. p, 'hang' .. p
  local attempt = lab_attempts .. '/' .. key
  -- The attempt ended: a script claim and exit 0.
  sh({'/bin/mkdir', attempt})
  sh({'/bin/ln', '-s', 'script', attempt .. '/claim'})
  sh({'/bin/sh', '-c', 'printf "0\\n" > "$1"', 'exit-file', attempt .. '/exit'})
  -- An older down of the profile that still hangs, in a block of its own.
  raise('hold-down-' .. profile)
  local P = plugin_session()
  local h = rex.call('session.new_block', {session_id = P, flavor = 'com.superlogical.terminal.shell', label = 'fence-test-hang:' .. p,
    options = {command = {'/bin/sh', T.fixture, '--profile', profile, 'down'}, login = false, exit = {on_completion = false}}}).block_id
  wait('the old down hangs', function() return T.down_calls(p) == 1 end, 10)
  lost_create(p, key, attempt)
  T.open_panel(pane)
  waiting_for(p, 'an opentunnel down of ' .. profile .. ' still runs')
  T.flag('hold-down-' .. profile, false)
  T.no_cleanup_for(p)
  expect(T.down_calls(p), 'no new down').to_be(1)
  rex.call('block.close', {session_id = P, block_id = h})
end)

test('a fenced attempt whose create result was lost is released by a new attempt; Forward works again', function()
  local p = T.port()
  local profile = T.prefix .. p
  -- The plugin made the fence and the attempt directory and saved the record; the create reply was
  -- lost and no block exists (something closed it, or it was never created).
  -- The record keeps its own attempt path, so the test uses a fence directory of its own.
  local dir = H.args.lab .. '/home/.local/state/lazyrex-tunnels/attempts/lostfence'
  sh({'/bin/mkdir', '-p', dir})
  local key = 'lost' .. p
  sh({'/bin/mkdir', dir .. '/' .. key})
  local saved_at = os.time() - 1
  T.edit(function(v)
    v.cleanups = v.cleanups or {}
    v.cleanups[profile] = {phase = 'sending', key = key, saved_at = saved_at, fence_v = 1, attempt = dir .. '/' .. key}
  end)
  T.open_panel(pane) -- a render kicks maintenance
  T.no_cleanup_for(p)
  expect(sh({'/usr/bin/readlink', dir .. '/' .. key .. '/claim'}).stdout).to_be('plugin\n')
  expect(T.down_calls(p), 'the new attempt ran down once').to_be(1)
  close(p, T.forward_other(pane, p))
end)

test('a normal cleanup is fenced: the record has an attempt that the script claimed', function()
  local p = T.port()
  local b = T.forward_other(pane, p)
  local fence = T.catalog().fence
  local before = {}
  if fence then for _, name in ipairs(names(fence)) do before[name] = true end end
  close(p, b)
  -- The cleanup of p ended. Its attempt is the one new directory in the fence.
  local fresh = {}
  for _, name in ipairs(names(T.catalog().fence)) do if not before[name] then fresh[#fresh + 1] = name end end
  expect(#fresh, 'one new attempt directory').to_be(1)
  local attempt = T.catalog().fence .. '/' .. fresh[1]
  expect(sh({'/usr/bin/readlink', attempt .. '/claim'}).stdout).to_be('script\n')
  expect(sh({'/bin/cat', attempt .. '/exit'}).stdout).to_be('0\n')
  expect(attempt:sub(1, #H.args.lab), 'the fence is in the lab').to_be(H.args.lab)
end)
