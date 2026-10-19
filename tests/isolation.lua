-- Isolation: no test may reach the real opentunnel or publish a port (team rule).
-- 1. The lab guard: this lab forces the fake binary, a private FAKE_OT_DIR and XDG_CONFIG_HOME, and
--    a lab profile prefix. The runner and the plugin get the same environment from the harness, so
--    the runner checks its own. A failure fails the file; it never skips.
-- 2. The plugin's own refusal: tunnels.lua runs in a sandbox with a stub rex and a stub os.getenv.
--    The stub runs no process and creates no block, so a refusal is visible as an error reply.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
local plugin_dir = tests_dir:match('^(.*)/tests$')
local fixture = plugin_dir .. '/tests/fake-opentunnel.sh'

test('the lab forces the fake opentunnel and private paths', function()
  dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
end)

local load_sandbox = dofile(tests_dir .. '/lib/sandbox.lua')
local base = getfenv(1)
local function sandbox(vars, executables) return load_sandbox(plugin_dir, base, {vars = vars, executables = executables}) end

local function forward(s)
  return s:perform('view.action', {user = 'user', route = '/forms/forward', node_id = 'forward', action = 'forward',
    operation_key = 'isolation-1', input = {values = {port = 'other', other = '4321'}}, context = {session_id = 's'}})
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
