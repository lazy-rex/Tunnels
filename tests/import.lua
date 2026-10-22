-- The import from hub.store (tunnels_store.lua, "The import"). The fixture loads tunnels_store.lua
-- with a fake app: a fake hub (hub.store.get, hub.store.ops_scan) and a fake db that records each
-- statement. The lab test then imports through the real hub SQL.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

-- fixture loads the store over value (the hub.store record) and pages (the ops_scan pages), and
-- runs its start function. It answers the record of the fake: execs, printed, hub_calls, error.
local function fixture(value, pages, opts)
  opts = opts or {}
  local f = {execs = {}, printed = {}, hub_calls = {}}
  local db = {}
  function db.migrate() end
  function db.first(sql) if sql:find("name = 'import'", 1, true) then return opts.imported and {value = 'done'} or nil end end
  function db.exec(sql, ...) f.execs[#f.execs + 1] = {sql = sql, args = {...}}; return {changes = 1} end
  function db.query() return {} end
  function db.transaction(fn) return fn() end
  local starts = {}
  local app = {db = db, fail = function(code, message) error({code = code, message = message}, 0) end, start = function(fn) starts[#starts + 1] = fn end}
  function app.hub(action, args)
    f.hub_calls[#f.hub_calls + 1] = action
    if action == 'hub.store.get' then return {records = {forwards = value and {value = value, rev = '1'} or nil}} end
    if action == 'hub.store.ops_scan' then
      local i = args.after == nil and 1 or tonumber(args.after:match('^page(%d+)$')) + 1
      local page = pages[i] or {}
      return {ops = page, next = pages[i + 1] and ('page' .. i) or nil}
    end
    error('fixture hub: ' .. action)
  end
  local chunk = assert(loadfile(T.plugin_dir .. '/tunnels_store.lua'))
  setfenv(chunk, setmetatable({print = function(...) f.printed[#f.printed + 1] = table.concat({...}, ' ') end}, {__index = getfenv(1)}))
  chunk().open(app)
  for _, fn in ipairs(starts) do
    local ok, err = pcall(fn)
    if not ok then f.error = err end
  end
  return f
end
local function inserts(f, table_name)
  local list = {}
  for _, e in ipairs(f.execs) do
    if e.sql:find('^INSERT[%w ]* INTO ' .. table_name .. ' ') then list[#list + 1] = e.args end
  end
  return list
end

local V1 = 'forward/5:other/4:9999/session:x'
test('the import copies the record and every saved operation, and drops only the v1 Forward ones (fixture)', function()
  local value = {
    forwards = {b1 = {session_id = 's', port = 4321, target = '127.0.0.1:4321', profile = 'lazyrex-4321', op = 'f1', created = 'c', creator = {kind = 'agent', agent = 'alice'}}},
    intents = {i1 = {session_id = 's', port = 4322, target = '127.0.0.1:4322', profile = 'lazyrex-4322', creator = {kind = 'user'}, fingerprint = 'forward-v2/x', created = 'c', saved_at = 5, phase = 'sending'}},
    stops = {['stop/k'] = {forward = 'b1', session_id = 's', port = 4321, profile = 'lazyrex-4321', fingerprint = 'stop-v1/x', saved_at = 6}},
    cleanups = {['lazyrex-1'] = {phase = 'new'}, ['lazyrex-2'] = {phase = 'sending', key = 'k', saved_at = 7, fence_v = 1, attempt = '/f/k'}},
    fence = '/f',
  }
  local pages = {
    {{key = 'f1', fingerprint = 'forward-v2/a', result = {forward = 'b1'}}, {key = 'old', fingerprint = V1, result = {panel = {command = 'tunnels'}}}},
    {{key = 'stop/done', fingerprint = 'stop-v1/y', result = {forward = 'b0', stopped = true}}},
  }
  local f = fixture(value, pages)
  expect(f.error, 'the import').to_be(nil)
  expect(#inserts(f, 'forwards')).to_be(1)
  expect(#inserts(f, 'intents')).to_be(1)
  expect(#inserts(f, 'stops')).to_be(1)
  expect(#inserts(f, 'cleanups')).to_be(2)
  local keys = {}
  for _, args in ipairs(inserts(f, 'ops')) do keys[#keys + 1] = args[1] end
  table.sort(keys)
  expect(keys, 'every operation but the v1 Forward one').to_equal({'f1', 'stop/done'})
  expect(#f.printed).to_be(1)
  expect(f.printed[1]).to_match('drops the operation old')
  expect(f.printed[1]).to_match('coord%-tunnels%-v1%-op')
  local meta = {}
  for _, e in ipairs(f.execs) do if e.sql:find('meta', 1, true) then meta[#meta + 1] = e.sql end end
  assert_true(table.concat(meta, '\n'):find("'fence'", 1, true) ~= nil, 'the fence goes to meta')
  assert_true(table.concat(meta, '\n'):find("'import', 'done'", 1, true) ~= nil, 'the import is marked done')
  assert_true(table.concat(meta, '\n'):find('writes', 1, true) == nil, 'writes stays 0')
end)

test('the import refuses a sending cleanup with no fence, and an unknown field; it writes nothing (fixture)', function()
  local f = fixture({cleanups = {['lazyrex-1'] = {phase = 'sending', key = 'k', saved_at = 7}}}, {})
  expect(f.error and f.error.code).to_be('conflict')
  expect(#f.execs, 'nothing is written').to_be(0)
  f = fixture({forwards = {b1 = {port = 1, colour = 'red'}}}, {})
  expect(f.error and f.error.code).to_be('internal')
  expect(f.error.message).to_match('colour')
  f = fixture({other = {}}, {})
  expect(f.error and f.error.code).to_be('internal')
end)

test('a start after the import imports nothing; an empty store imports only the mark (fixture)', function()
  local f = fixture({forwards = {b1 = {port = 1}}}, {{{key = 'x', fingerprint = 'stop-v1/x', result = {}}}}, {imported = true})
  expect(#f.execs).to_be(0)
  expect(#f.hub_calls, 'no hub.store read').to_be(0)
  f = fixture(nil, {})
  expect(f.error).to_be(nil)
  expect(#f.execs, 'only the import mark').to_be(1)
end)

-- The lab import: the hub.store data of an older plugin version, then a start on empty tables.
local S = session('tunnels-import')
local pane = T.shell(S, 'import')
test('a start imports the hub.store data into SQL; a v1 Forward operation is dropped; no write follows (lab)', function()
  local p = T.port()
  local fw = {session_id = S, port = p, target = '127.0.0.1:' .. p, profile = T.prefix .. p, op = 'imp-fw', created = '2026-10-22T00:00:00Z', creator = {kind = 'agent', agent = 'alice'}}
  local intent = {session_id = S, port = p + 1, target = '127.0.0.1:' .. (p + 1), profile = T.prefix .. (p + 1), creator = {kind = 'user'},
    fingerprint = 'forward-v2/imp', created = '2026-10-22T00:00:01Z', saved_at = os.time(), phase = 'sending'}
  H.hub('hub.admin.stop', {plugin = 'tunnels'})
  write({{key = 'forwards', value = {forwards = {[pane.block] = fw}, intents = {['imp-intent'] = intent}, cleanups = {}, stops = {}, fence = '/tmp/imp-fence'}}})
  put_operation{key = 'imp-fw', fingerprint = 'forward-v2/a', result = {panel = {command = 'tunnels'}}}
  put_operation{key = 'imp-stop', fingerprint = 'stop-v1/b', result = {forward = 'block:x', stopped = true}}
  put_operation{key = 'imp-v1', fingerprint = 'forward/5:other/4:9999/' .. S, result = {panel = {command = 'tunnels'}}}
  -- Empty tables and no import mark, as at the first start on SQL.
  for _, t in ipairs({'intents', 'forwards', 'stops', 'cleanups', 'ops'}) do sql_write('DELETE FROM ' .. t) end
  sql_write("DELETE FROM meta WHERE name IN ('import', 'fence')")
  sql_write("UPDATE meta SET value = 0 WHERE name = 'writes'")
  H.hub('hub.admin.start', {plugin = 'tunnels'})
  wait('the import is done', function() return sql("SELECT value FROM meta WHERE name = 'import'")[1] ~= nil end, 20)
  local c = T.catalog()
  expect(c.forwards[pane.block], 'the forward and its optional fields').to_equal(fw)
  expect(c.intents['imp-intent'], 'the intent').to_equal(intent)
  expect(c.fence).to_be('/tmp/imp-fence')
  local keys = {}
  for _, r in ipairs(sql('SELECT key, result FROM ops ORDER BY key')) do keys[#keys + 1] = r.key end
  expect(keys, 'every operation but the v1 Forward one').to_equal({'imp-fw', 'imp-stop'})
  -- Maintenance runs over the imported state: the forward runs, the intent stays unknown. Nothing is written.
  rex.sleep(3)
  expect(sql("SELECT value FROM meta WHERE name = 'writes'")[1].value, 'no write after the import').to_be(0)
  T.edit(function(v) v.forwards[pane.block] = nil; v.intents['imp-intent'] = nil end)
end)
