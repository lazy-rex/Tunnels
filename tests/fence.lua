-- The cleanup attempt fence (tunnels.lua, "Fenced attempts"; reviewed design v3). Each new attempt
-- has a random key and its own directory, made before its record is saved. The script and the
-- plugin both claim <attempt>/claim; exactly one claim succeeds. A plugin claim ends the attempt (a
-- late create runs no down); a script claim waits for the attempt's exit file. A record without
-- fence_v (an older plugin) is never claimed. The sandbox tests use the stub file system of
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
  local s = load_sandbox(T.plugin_dir, base, {
    vars = o.vars or {LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = T.fixture},
    executables = {[T.fixture] = true}, fs = o.fs, exec = o.exec,
    catalog = {fence = o.fence, cleanups = {[PROFILE] = c}},
    rex = {
      ['session.list'] = function() return {sessions = {{session_id = 'plugin'}}} end,
      ['session.list_blocks'] = function() return {blocks = {}} end,
      ['session.new_block'] = function(args)
        local cat = box.s.catalog
        box.calls[#box.calls + 1] = {args = args, record = cat.cleanups and cat.cleanups[PROFILE]}
        if o.create then return o.create(args) end
        return nil, 'connection reset' -- an unknown result: the record stays sending
      end,
    }})
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

test('a script claim without a valid exit file keeps the profile (sandbox)', function()
  for _, data in ipairs({false, '', '256\n', '0 x', 'x\n', '1000\n', '-1\n', '0\n\n'}) do
    local fs = {}
    local c = fenced(fs, 'dd')
    fs[c.attempt .. '/claim'] = {link = 'script'}
    if data then fs[c.attempt .. '/exit'] = {data = data} end
    local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
    s:tick()
    expect(record(s).phase, tostring(data)).to_be('sending')
    expect(#s.calls, tostring(data)).to_be(0)
  end
  -- An unreadable exit file (cat fails) is no result either.
  local fs = {}
  local c = fenced(fs, 'de')
  fs[c.attempt .. '/claim'] = {link = 'script'}
  fs[c.attempt .. '/exit'] = {data = '0\n'}
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1', exec = function(argv) if argv[1] == '/bin/cat' then return {ok = false} end end})
  s:tick()
  expect(record(s).phase).to_be('sending')
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

test('a record without fence_v is never claimed (sandbox)', function()
  local fs = {}
  local c = fenced(fs, 'ff')
  c.fence_v = nil
  local s = fence_sandbox(c, {fs = fs, fence = ROOT .. '/f1'})
  s:tick()
  expect(record(s).phase).to_be('sending')
  for _, argv in ipairs(s.execs) do assert_true(argv[1] ~= '/bin/ln', 'no claim') end
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
local function script_block(P, key, profile, attempt)
  return rex.call('session.new_block', {session_id = P, flavor = 'com.superlogical.terminal.shell', label = 'lazyrex-tunnel-down:' .. key,
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
