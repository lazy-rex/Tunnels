-- The lab guard (team rule: no test reaches the real opentunnel or publishes a port). A test file
-- that forwards a port calls it at load: a failure fails the file before any test runs. The runner
-- and the plugin get the same environment from the harness, so the runner checks its own.
-- Usage: local plugin_dir = dofile(<tests dir> .. '/lib/guard.lua')(<tests dir>)
return function(tests_dir)
  local plugin_dir = assert(tests_dir:match('^(.*)/tests$'), 'tests dir expected')
  local function under(path, dir)
    return type(path) == 'string' and path:sub(1, #dir + 1) == dir .. '/' and not path:find('/../', 1, true)
  end
  local lab = (os.getenv('REX_SERVER') or ''):match('^unix://(/.*)/rex%.sock$')
  local problems = {}
  if not lab then problems[#problems + 1] = 'REX_SERVER does not name a lab socket' else
    for _, name in ipairs({'FAKE_OT_DIR', 'XDG_CONFIG_HOME', 'HOME'}) do
      if not under(os.getenv(name), lab) then problems[#problems + 1] = name .. ' is not inside the lab: ' .. tostring(os.getenv(name)) end
    end
  end
  if os.getenv('LAZYREX_TUNNELS_OPENTUNNEL') ~= plugin_dir .. '/tests/fake-opentunnel.sh' then
    problems[#problems + 1] = 'LAZYREX_TUNNELS_OPENTUNNEL is not the fixture: ' .. tostring(os.getenv('LAZYREX_TUNNELS_OPENTUNNEL'))
  end
  if os.getenv('LAZYREX_TUNNELS_PROFILE_PREFIX') ~= 'lazyrexlab-' then
    problems[#problems + 1] = 'LAZYREX_TUNNELS_PROFILE_PREFIX is not lazyrexlab-: ' .. tostring(os.getenv('LAZYREX_TUNNELS_PROFILE_PREFIX'))
  end
  if #problems > 0 then error('lab guard: ' .. table.concat(problems, '; '), 0) end
  return plugin_dir
end
