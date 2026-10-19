-- Isolation: no test may reach the real opentunnel or publish a port (team rule).
-- 1. The lab guard: this lab forces the fake binary, a private FAKE_OT_DIR and XDG_CONFIG_HOME, and
--    a lab profile prefix. The runner and the plugin get the same environment from the harness, so
--    the runner checks its own. A failure fails the file; it never skips.
-- 2. The plugin's own refusal: tunnels.lua runs in a sandbox with a stub rex and a stub os.getenv.
--    The stub runs no process and creates no block, so a refusal is visible as an error reply.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
local plugin_dir = tests_dir:match('^(.*)/tests$')
local fixture = plugin_dir .. '/tests/fake-opentunnel.sh'

-- under answers whether path is inside dir, at a directory boundary.
local function under(path, dir)
  return type(path) == 'string' and path:sub(1, #dir + 1) == dir .. '/' and not path:find('/../', 1, true)
end

test('the lab forces the fake opentunnel and private paths', function()
  local lab = (os.getenv('REX_SERVER') or ''):match('^unix://(/.*)/rex%.sock$')
  assert_true(lab, 'REX_SERVER names a lab socket')
  expect(os.getenv('LAZYREX_TUNNELS_OPENTUNNEL')).to_be(fixture)
  expect(os.getenv('LAZYREX_TUNNELS_PROFILE_PREFIX')).to_be('lazyrexlab-')
  assert_true(under(os.getenv('FAKE_OT_DIR'), lab), 'FAKE_OT_DIR is inside the lab: ' .. tostring(os.getenv('FAKE_OT_DIR')))
  assert_true(under(os.getenv('XDG_CONFIG_HOME'), lab), 'XDG_CONFIG_HOME is inside the lab: ' .. tostring(os.getenv('XDG_CONFIG_HOME')))
  assert_true(under(os.getenv('HOME'), lab), 'HOME is inside the lab: ' .. tostring(os.getenv('HOME')))
end)

-- sandbox loads tunnels.lua with the environment vars and the executables given. It answers the
-- stub state: the client_perform_requested handler, the replies and the new_block calls.
local function sandbox(vars, executables)
  local s = {handlers = {}, creates = {}, execs = {}}
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
      if method == 'client.perform' then
        if args.action == 'hub.store.get' then return {result = {records = {forwards = {rev = '1', value = {}}}}} end
        if args.action == 'hub.store.op' then return {result = {found = false}} end
        if args.action == 'hub.store.batch' then return {result = {revs = {forwards = '2'}}} end
        return {result = {}}
      end
      if method == 'session.list' then return {sessions = {{session_id = 's'}}} end
      if method == 'session.list_blocks' then return {blocks = {}} end
      if method == 'session.new_block' then s.creates[#s.creates + 1] = args; return {block_id = 'new'} end
      if method == 'client.reply' then s.reply = args end
      return {}
    end,
  }
  local base = getfenv(1)
  local env = setmetatable({rex = stub, os = setmetatable({getenv = function(name) return vars[name] end}, {__index = os})}, {__index = base})
  local chunk = assert(loadfile(plugin_dir .. '/tunnels.lua'))
  setfenv(chunk, env)
  s.loaded, s.load_error = pcall(chunk)
  return s
end

local function forward(s)
  s.handlers.client_perform_requested({}, {requester = {client_id = 'hub'}, action = 'view.action', call_id = 'c', args = {
    user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward', operation_key = 'isolation-1',
    input = {values = {port = 'other', other = '4321'}}, context = {session_id = 's'}}})
  return s.reply
end

local function refused(vars, executables, pattern)
  local s = sandbox(vars, executables)
  assert_true(s.loaded, 'the plugin loads: ' .. tostring(s.load_error))
  local reply = forward(s)
  assert_true(reply.error, 'Forward is refused')
  expect(reply.error.code).to_be('not_found')
  expect(reply.error.message).to_match(pattern)
  expect(#s.creates).to_be(0)
end

test('a lab prefix without the override is refused, and no install place is searched', function()
  refused({LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', HOME = '/nonexistent'},
    {['/opt/homebrew/bin/opentunnel'] = true}, 'lab profile prefix needs the fake opentunnel')
end)

test('a lab prefix with a real executable is refused', function()
  refused({LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = '/opt/homebrew/bin/opentunnel'},
    {['/opt/homebrew/bin/opentunnel'] = true}, 'lab profile prefix needs the fake opentunnel')
end)

test('a lab prefix with another file named fake-opentunnel.sh is refused', function()
  refused({LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = '/tmp/x/tests/fake-opentunnel.sh'},
    {['/tmp/x/tests/fake-opentunnel.sh'] = true}, 'lab profile prefix needs the fake opentunnel')
end)

test('an override must be an absolute executable path', function()
  refused({LAZYREX_TUNNELS_OPENTUNNEL = 'tests/fake-opentunnel.sh'}, {['tests/fake-opentunnel.sh'] = true}, 'absolute path to an executable')
  refused({LAZYREX_TUNNELS_OPENTUNNEL = fixture}, {}, 'absolute path to an executable')
end)

test('a profile prefix must end with -', function()
  for _, prefix in ipairs({'lab', '', '-', 'lab/x-', 'a b-'}) do
    local s = sandbox({LAZYREX_TUNNELS_PROFILE_PREFIX = prefix, LAZYREX_TUNNELS_OPENTUNNEL = fixture}, {[fixture] = true})
    expect(s.loaded, prefix).to_be(false)
    expect(tostring(s.load_error)).to_match('must be letters, digits, _ or %- and end with %-')
  end
end)

test('a lab prefix with the exact fixture creates one tunnel block that runs the fixture', function()
  local s = sandbox({LAZYREX_TUNNELS_PROFILE_PREFIX = 'lazyrexlab-', LAZYREX_TUNNELS_OPENTUNNEL = fixture}, {[fixture] = true})
  local reply = forward(s)
  assert_true(not reply.error, 'Forward succeeds: ' .. show(reply.error))
  expect(#s.creates).to_be(1)
  local command = s.creates[1].options.command
  expect(command[4]).to_be(fixture)
  expect(command[5]).to_be('lazyrexlab-4321')
end)
