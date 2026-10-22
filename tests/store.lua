-- The SQL store (tunnels_store.lua). The fixture tests load the module with a fake app whose db keeps
-- the state in memory and commits a transaction only when its function returns. The lab tests use
-- the real hub SQL: a round trip of every kind, and the atomic write of an operation and the counter.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

-- fixture answers the store over state (a catalog) and ops ({[key] = {fingerprint, result}}), and
-- the fake: committed (the statements of the committed transactions).
local function fixture(state, ops)
  local f = {committed = {}}
  local pending
  local M = dofile(T.plugin_dir .. '/tunnels_store.lua')
  local db = {}
  function db.migrate() end
  function db.query(sql)
    assert(sql == M.CATALOG, 'fixture db: only the catalog')
    local rows = {}
    for _, k in ipairs(M.KINDS) do
      for key, x in pairs(state[k.field] or {}) do rows[#rows + 1] = {kind = k.field, key = key, value = rex.json.encode(x)} end
    end
    if state.fence then rows[#rows + 1] = {kind = 'meta', key = 'fence', value = rex.json.encode({value = state.fence})} end
    return rows
  end
  function db.first(sql, key)
    assert(sql:find('FROM ops', 1, true), 'fixture db: only ops')
    local op = ops[key]
    return op and {fingerprint = op.fingerprint, result = rex.json.encode(op.result)} or nil
  end
  function db.exec(sql, ...) pending[#pending + 1] = {sql = sql, args = {...}}; return {changes = 1} end
  function db.transaction(fn)
    pending = {}
    local result = fn()
    for _, e in ipairs(pending) do f.committed[#f.committed + 1] = e end
    pending = nil
    return result
  end
  local app = {db = db, fail = function(code, message) error({code = code, message = message}, 0) end, start = function() end}
  return M.open(app), f
end
local function fw(port) return {session_id = 's', port = port, target = '127.0.0.1:' .. port, profile = 'lazyrexlab-' .. port, op = 'o' .. port, created = 'c', creator = {kind = 'user'}} end

test('update with a saved op key: the same fingerprint answers op_exists, another fails with operation_conflict; nothing is written (fixture)', function()
  local saved = {fingerprint = 'stop-v1/a', result = {forward = 'b1', stopped = true}}
  local store, f = fixture({forwards = {b1 = fw(1)}}, {['stop/k'] = saved})
  local done = store.update(function(s) s.forwards.b1 = nil end, {key = 'stop/k', fingerprint = 'stop-v1/a', result = {forward = 'b1', stopped = true}})
  expect(done.op_exists.result).to_equal(saved.result)
  local ok, err = pcall(store.update, function(s) s.forwards.b1 = nil end, {key = 'stop/k', fingerprint = 'stop-v1/other', result = {}})
  expect(ok).to_be(false)
  expect(err.code).to_be('operation_conflict')
  expect(#f.committed, 'no write').to_be(0)
end)

-- Lab: the real SQL. Each kind with optional fields missing, nested creator and result, and the fence.
local alice = agent('alice')
local S = session('tunnels-store')
local pane = T.shell(S, 'store')

test('every kind, a missing optional field, nested JSON and the fence round-trip through SQL exactly (lab)', function()
  local before = T.catalog()
  local c = {
    intents = {['rt-intent'] = {session_id = S, port = 1, target = '127.0.0.1:1', profile = 'rt-1', creator = {kind = 'agent', agent = 'alice'}, fingerprint = 'fp', created = 'c', saved_at = 1792700000, phase = 'sending'}},
    forwards = {['rt-forward'] = {session_id = S, port = 2, target = '[::1]:2', profile = 'rt-2', op = 'o', created = 'c', creator = {kind = 'user'}, url = 'https://rt.example'}},
    stops = {['stop/rt'] = {forward = 'rt-forward', session_id = S, port = 2, profile = 'rt-2', fingerprint = 'stop-v1/rt', saved_at = 1792700001}},
    cleanups = {['rt-3'] = {phase = 'closing', key = 'k', block_id = 'b', result = {error = 'exit status 1', detail = {code = 1, ok = false}}, retry_at = 1792700002, saved_at = 1792700003, attempt = '/f/k', fence_v = 1},
      ['rt-4'] = {phase = 'new'}},
  }
  expect(next(before.forwards) == nil and next(before.intents) == nil, 'no state before').to_be(true)
  -- The plugin is idle here (no state, no open view, so no maintenance timer): it does not act on
  -- the rows between their write and the read.
  local M = dofile(T.plugin_dir .. '/tunnels_store.lua')
  for _, k in ipairs(M.KINDS) do
    for key, record in pairs(c[k.field]) do
      local names, values = M.values_of(k, key, record, rex.json.encode, function(_, m) error(m, 0) end)
      local marks, params = {}, {}
      for i = 1, #names do marks[i], params[i] = '?' .. i, values[i] == nil and {null = true} or values[i] end
      sql_write('INSERT INTO ' .. k.field .. ' (' .. table.concat(names, ', ') .. ') VALUES (' .. table.concat(marks, ', ') .. ')', params)
    end
  end
  sql_write("INSERT OR REPLACE INTO meta (name, value) VALUES ('fence', '/rt/fence')")
  local got = T.catalog()
  for _, k in ipairs(M.KINDS) do
    for key in pairs(c[k.field]) do sql_write('DELETE FROM ' .. k.field .. ' WHERE ' .. k.key .. ' = ?1', {key}) end
  end
  sql_write("DELETE FROM meta WHERE name = 'fence'")
  for _, kind in ipairs({'intents', 'forwards', 'stops', 'cleanups'}) do expect(got[kind], kind).to_equal(c[kind]) end
  expect(got.fence).to_be('/rt/fence')
  -- A missing optional field is nil, not a JSON null sentinel.
  expect(got.cleanups['rt-4'].key).to_be(nil)
  expect(got.forwards['rt-forward'].source_block).to_be(nil)
end)

local function writes() return sql("SELECT value FROM meta WHERE name = 'writes'")[1].value end
local function part(v) v = tostring(v); return #v .. ':' .. v .. '/' end
test('an operation result and the write counter commit with the change, or not at all (lab)', function()
  local p = T.port()
  local r = alice:call('tunnels.forward', {key = 'store-' .. p, port = p, session_id = S, block_id = pane.block})
  wait('no work in progress', function() local c = T.catalog(); return not next(c.cleanups) and not next(c.stops) and not next(c.intents) end, 30)
  local key = 'stop/' .. part('agent') .. part('alice') .. part('store-stop-' .. p)
  local w0 = writes()
  -- The final write of the stop (the forward goes, the op is saved) fails until the injection goes.
  local held = inject{match = {sql_commit_writes = 'ops', sql_param = key}, fail = 'held', times = 'always'}
  expect_error(function() alice:call('tunnels.stop', {forward = r.forward, key = 'store-stop-' .. p}) end, 'held')
  expect(sql('SELECT key FROM ops WHERE key = ?', {key})[1], 'no op').to_be(nil)
  assert_true(T.catalog().forwards[r.forward] ~= nil, 'the forward stays')
  assert_true(T.catalog().stops[key] ~= nil, 'the saved stop stays')
  expect(writes(), 'only the stop save counted').to_be(w0 + 1)
  cancel_injection(held)
  wait('maintenance finishes the stop', function() return sql('SELECT key FROM ops WHERE key = ?', {key})[1] ~= nil end, 15)
  expect(T.catalog().forwards[r.forward], 'the forward goes with the op').to_be(nil)
  assert_true(writes() >= w0 + 2, 'the final write counted')
  T.no_cleanup_for(p)
end)
