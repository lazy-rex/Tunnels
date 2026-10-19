-- Run with rex do against a lab session. No host processes are inspected.
local ports = dofile(assert(rex.args.module))
local rows = ports.parse_lsof('p42\ncnode\nn127.0.0.1:3000\nn127.0.0.1:3000\nn[::1]:4000\nn*:5000\nn*:0\nn*:65536\npbad\nn*:6000\n')
assert(#rows == 3 and rows[2].address == '[::1]' and rows[3].port == 5000)
local calls = 0
local function fixture(mode)
  local api = {}
  function api.call(method, args)
    if method == 'session.list' then return {sessions = {{session_id = 's'}}} end
    if method == 'session.attach' then return {} end
    if method == 'session.view' then return {windows = {{window_id = 'w', label = 'tab'}}} end
    if method == 'session.list_blocks' then
      if mode == 'listing_error' then return nil, {message = 'unavailable'} end
      return {blocks = {{creator_name = 'com.superlogical.terminal', block_id = 'b', window_id = 'w'}}}
    end
    if method == 'com.superlogical.terminal.process' then return {child = {pid = 10}} end
    error(method)
  end
  function api.exec(argv)
    calls = calls + 1
    if argv[1] == '/bin/ps' then
      if mode == 'ps_error' then return {ok = false, stderr = 'denied'} end
      if mode == 'no_pids' then return {ok = true, stdout = '20 1 other\n'} end
      return {ok = true, stdout = '10 1 shell\n11 10 node\n20 1 outside\n30 31 loop\n31 30 loop\n'}
    end
    assert(argv[5] == '10,11', 'only descendant PIDs may be selected')
    if mode == 'empty' then return {ok = false, code = 1, stdout = '', stderr = ''} end
    if mode == 'timeout' then return {ok = false, code = -1, timed_out = true, stdout = 'p11\nn*:9999\n'} end
    if mode == 'missing' then return nil, 'not installed' end
    return {ok = true, stdout = 'p11\ncnode\nn127.0.0.1:3000\np20\ncoutside\nn*:9000\n'}
  end
  return api
end
local r = ports.scan('s', fixture('ok'))
assert(#r.ports == 1 and r.ports[1].pid == 11 and r.ports[1].tab == 'tab' and #r.warnings == 0)
for _, mode in ipairs({'listing_error', 'ps_error', 'timeout', 'missing'}) do
  r = ports.scan('s', fixture(mode))
  assert(#r.ports == 0 and #r.warnings > 0, mode)
end
r = ports.scan('s', fixture('empty'))
assert(#r.ports == 0 and #r.warnings == 0)
calls = 0
r = ports.scan('s', fixture('no_pids'))
assert(#r.ports == 0 and calls == 1, 'no lsof call without selected PIDs')
print('PASS: address parsing, duplicate sockets, descendant filtering, cycle termination, partial failures, empty selection')
