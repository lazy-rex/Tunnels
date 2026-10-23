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
  function db.first(sql) if sql:find("name = 'import'", 1, true) then return opts.mark and {value = opts.mark} or nil end end
  function db.exec(sql, ...) f.execs[#f.execs + 1] = {sql = sql, args = {...}}; return {changes = 1} end
  function db.query() return {} end
  function db.transaction(fn) return fn() end
  local starts = {}
  local app = {db = db, fail = function(code, message) error({code = code, message = message}, 0) end, start = function(fn) starts[#starts + 1] = fn end}
  function app.hub(action, args)
    f.hub_calls[#f.hub_calls + 1] = action
    if action == 'hub.store.get' then return {records = {forwards = value ~= nil and {value = value, rev = '1'} or nil}} end
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
  f = fixture({forwards = {b1 = {port = 1, creator = {kind = 'user'}, colour = 'red'}}}, {})
  expect(f.error and f.error.code).to_be('internal')
  expect(f.error.message).to_match('colour')
  f = fixture({other = {}}, {})
  expect(f.error and f.error.code).to_be('internal')
end)

test('the import refuses an intent or a forward whose creator is not a user or an agent with an ID; it writes nothing (fixture)', function()
  for name, creator in pairs({none = false, text = 'user', ['no kind'] = {}, bot = {kind = 'bot'}, ['no agent'] = {kind = 'agent'},
      ['empty agent'] = {kind = 'agent', agent = ''}, ['number agent'] = {kind = 'agent', agent = 5}}) do
    local c = creator or nil
    for _, kind in ipairs({'intents', 'forwards'}) do
      local f = fixture({[kind] = {r1 = {session_id = 's', port = 4325, profile = 'lazyrex-4325', creator = c}}}, {})
      expect(f.error and f.error.code, kind .. ', ' .. name).to_be('conflict')
      expect(f.error.message, kind .. ', ' .. name).to_match('r1: its creator is not a user or an agent')
      expect(#f.execs, kind .. ', ' .. name .. ': nothing is written').to_be(0)
    end
  end
end)

test('the import refuses an intent with a v1 Forward fingerprint; it writes nothing (fixture)', function()
  -- Maintenance could adopt the intent and save a new v1 result that a retry can never match. The
  -- dropped v1 operations (coord-tunnels-v1-op) are saved results; an intent is an active reservation.
  local intent = {session_id = 's', port = 4322, target = '127.0.0.1:4322', profile = 'lazyrex-4322', creator = {kind = 'user'},
    fingerprint = 'forward/5:other/4:4322/session:x', created = 'c', saved_at = 5, phase = 'sending'}
  local f = fixture({intents = {i1 = intent}}, {})
  expect(f.error and f.error.code).to_be('conflict')
  expect(f.error.message).to_match('i1')
  expect(#f.execs, 'nothing is written').to_be(0)
end)

test('a mark other than done, a record that is not a table, or a kind that is not a table fails the import; nothing is written (fixture)', function()
  local f = fixture({forwards = {}}, {}, {mark = 'running'})
  expect(f.error and f.error.code, 'a mark other than done').to_be('internal')
  expect(#f.execs).to_be(0)
  expect(#f.hub_calls, 'no hub.store read').to_be(0)
  for name, value in pairs({record = 'x', ['false kind'] = {forwards = false}, ['scalar kind'] = {stops = 5}, ['text kind'] = {intents = 'none'}}) do
    f = fixture(value, {})
    expect(f.error and f.error.code, name).to_be('internal')
    expect(#f.execs, name .. ': nothing is written').to_be(0)
  end
end)

test('a start after the import imports nothing; an empty store imports only the mark (fixture)', function()
  local f = fixture({forwards = {b1 = {port = 1}}}, {{{key = 'x', fingerprint = 'stop-v1/x', result = {}}}}, {mark = 'done'})
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

test('a failed import commits nothing; the next start imports once, with the saved results as they were (lab)', function()
  local p = T.port()
  local fw = {session_id = S, port = p, target = '127.0.0.1:' .. p, profile = T.prefix .. p, op = 'rs-fw', created = '2026-10-22T00:00:02Z', creator = {kind = 'user'}}
  local saved = {
    ['rs-fw'] = {fingerprint = 'forward-v2/rs', result = {panel = {command = 'tunnels'}}},
    ['rs-stop'] = {fingerprint = 'stop-v1/rs', result = {forward = 'block:y', stopped = true}},
  }
  H.hub('hub.admin.stop', {plugin = 'tunnels'})
  write({{key = 'forwards', value = {forwards = {[pane.block] = fw}, intents = {}, cleanups = {}, stops = {}}}})
  for key, op in pairs(saved) do put_operation{key = key, fingerprint = op.fingerprint, result = op.result} end
  for _, t in ipairs({'intents', 'forwards', 'stops', 'cleanups', 'ops'}) do sql_write('DELETE FROM ' .. t) end
  sql_write("DELETE FROM meta WHERE name IN ('import', 'fence')")
  sql_write("UPDATE meta SET value = 0 WHERE name = 'writes'")
  -- The import commit (it writes the rows, the ops and the mark) fails. The schema stays from the migration.
  local held = inject{match = {sql_commit_writes = 'meta'}, fail = 'the import fails', times = 'always'}
  local _, base = calls('none')
  H.hub('hub.admin.start', {plugin = 'tunnels'})
  wait('the import commit failed', function()
    for _, c in ipairs(calls('hub.sql.commit', {after = base.next})) do return true end
  end, 20)
  local function count(t) return sql('SELECT count(*) AS n FROM ' .. t)[1].n end
  for _, t in ipairs({'intents', 'forwards', 'stops', 'cleanups', 'ops'}) do expect(count(t), t .. ' after the failure').to_be(0) end
  expect(sql("SELECT value FROM meta WHERE name = 'import'")[1], 'no mark').to_be(nil)
  expect(sql("SELECT value FROM meta WHERE name = 'writes'")[1].value).to_be(0)
  cancel_injection(held)
  -- The hub starts a failed plugin again; an explicit start also works if it waits.
  pcall(H.hub, 'hub.admin.start', {plugin = 'tunnels'})
  wait('the import is done', function() local m = sql("SELECT value FROM meta WHERE name = 'import'")[1]; return m and m.value == 'done' end, 60)
  expect(T.catalog().forwards[pane.block]).to_equal(fw)
  local got = {}
  for _, r in ipairs(sql('SELECT key, fingerprint, result FROM ops')) do got[r.key] = {fingerprint = r.fingerprint, result = rex.json.decode(r.result)} end
  -- The earlier test's operations are still in hub.store, so they come again; these two come as saved.
  for key, op in pairs(saved) do expect(got[key], key .. ', as it was').to_equal(op) end
  rex.sleep(3)
  expect(sql("SELECT value FROM meta WHERE name = 'writes'")[1].value, 'no write after the import').to_be(0)
  T.edit(function(v) v.forwards[pane.block] = nil end)
end)
