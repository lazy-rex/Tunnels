-- The shared test helpers that tests count with (lib/tunnels.lua). A count must never read as 0
-- when its read failed. No test here forwards a port.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local dir = assert(os.getenv('TMPDIR'), 'the lab sets TMPDIR') .. '/tunnels-helpers-' .. os.time()
local function sh(script) local r = rex.exec({'/bin/sh', '-c', script}, {timeout = 10}); assert(r and r.ok, 'setup: ' .. script) end
sh("mkdir -p '" .. dir .. "' && : > '" .. dir .. "/empty.log' && printf 'a down\\nb down\\na down\\na downx\\n' > '" .. dir .. "/calls.log'")

test('count_lines: a missing log counts 0', function()
  expect(T.count_lines(dir .. '/missing.log', 'a down')).to_be(0)
end)

test('count_lines: an empty log counts 0', function()
  expect(T.count_lines(dir .. '/empty.log', 'a down')).to_be(0)
end)

test('count_lines: whole lines only', function()
  expect(T.count_lines(dir .. '/calls.log', 'a down')).to_be(2)
  expect(T.count_lines(dir .. '/calls.log', 'b down')).to_be(1)
  expect(T.count_lines(dir .. '/calls.log', 'c down')).to_be(0)
end)

test('count_lines: a read failure raises', function()
  -- A directory exists but grep cannot read it as a file (exit status 2).
  expect_error(function() T.count_lines(dir, 'a down') end, 'count_lines: the read of')
end)

test('count_lines: an exec failure or output that is not one number raises', function()
  local function stub(r) return function() return r end end
  expect_error(function() T.count_lines('x', 'y', stub(nil)) end, 'no result')
  expect_error(function() T.count_lines('x', 'y', stub({ok = false, exit_code = 2, stdout = '', stderr = 'boom'})) end, 'boom')
  expect_error(function() T.count_lines('x', 'y', stub({ok = true, exit_code = 0, stdout = ''})) end, 'count_lines')
  expect_error(function() T.count_lines('x', 'y', stub({ok = true, exit_code = 0, stdout = '1\n2\n'})) end, 'count_lines')
  expect(T.count_lines('x', 'y', stub({ok = true, exit_code = 0, stdout = '3\n'}))).to_be(3)
end)

test('state from a wait callback survives a caught error: return value and table field', function()
  -- Rex Lua 0.0.1792158932-g88fd41 (lab): after a pcall catches an error, a closure created before
  -- the catch writes a detached copy of a captured local. wait() runs its callback in a pcall, so a
  -- callback that fails once must give its state by a return value or a table field.
  local seen = {polls = 0, last = nil}
  local got = wait('the second poll', function()
    seen.polls = seen.polls + 1
    if seen.polls == 1 then error('a transient read error') end
    seen.last = 'poll-' .. seen.polls
    return seen.last
  end, 5)
  expect(got).to_be('poll-2')
  expect(seen.polls).to_be(2)
  expect(seen.last).to_be('poll-2')
end)
