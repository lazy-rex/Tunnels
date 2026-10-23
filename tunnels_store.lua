-- The Tunnels state in the plugin's SQL database (decision "One storage system"). tunnels.lua
-- sees one catalog table:
--   {intents = {[op key] = intent}, forwards = {[block ID] = forward}, cleanups = {[profile] =
--   cleanup}, stops = {[op key] = stop}, fence = <path or nil>}
-- Each kind is one table with one column per field. A field that the schema does not name fails the
-- write: a new field needs a migration, so nothing is lost silently. ops keeps each operation result
-- for ever (a key always replays its first result). meta keeps the fence and the write count.
--   local store = dofile(plugin_dir .. '/tunnels_store.lua').open(app)
-- The tests use the schema parts (KINDS, CATALOG, row_json, state_of, values_of) to read and write
-- the same tables as another writer.
local M = {}

-- KINDS: the catalog field (also the table name), its key column and its columns. json columns hold
-- a Lua table as JSON text; the other columns hold a string or a number. check: a row rule that SQL
-- enforces for every writer. A CHECK accepts a NULL result, so it uses IS (NULL IS 1 is false; NULL = 1
-- is NULL).
-- CREATOR: an intent and a forward have a creator: {"kind":"user"}, or {"kind":"agent","agent":<text
-- that is not empty>}. CASE branches run lazily, so json_type never sees text that is not JSON.
local CREATOR = "CASE WHEN json_valid(creator) IS NOT 1 THEN 0 WHEN json_type(creator) IS NOT 'object' THEN 0"
  .. " WHEN json_extract(creator, '$.kind') IS 'user' THEN 1"
  .. " WHEN json_extract(creator, '$.kind') IS 'agent' THEN json_type(creator, '$.agent') IS 'text' AND json_extract(creator, '$.agent') IS NOT ''"
  .. " ELSE 0 END"
M.KINDS = {
  {field = 'intents', key = 'id', columns = {'session_id', 'source_block', 'port', 'target', 'profile', 'creator', 'fingerprint', 'created', 'saved_at', 'phase'}, json = {creator = true}, check = CREATOR},
  {field = 'forwards', key = 'block_id', columns = {'session_id', 'source_block', 'port', 'target', 'profile', 'op', 'created', 'creator', 'url'}, json = {creator = true}, check = CREATOR},
  {field = 'stops', key = 'id', columns = {'forward', 'session_id', 'port', 'profile', 'fingerprint', 'saved_at'}},
  -- A cleanup after new is always fenced (decision "Cleanup attempt fence"): sending saves fence_v
  -- and attempt, and running, closing and retry keep them. Only the claim of its attempt proves that
  -- an attempt with an unknown create result can never run down.
  {field = 'cleanups', key = 'profile', columns = {'phase', 'key', 'block_id', 'result', 'retry_at', 'saved_at', 'attempt', 'fence_v'}, json = {result = true},
    check = "phase IS 'new' OR (fence_v IS 1 AND attempt IS NOT NULL)"},
}
local INTEGER = {port = true, saved_at = true, retry_at = true, fence_v = true}
M.FIELD = {} -- the catalog fields of the kinds
for _, k in ipairs(M.KINDS) do
  k.json = k.json or {}
  M.FIELD[k.field] = true
  k.known = {}
  for _, c in ipairs(k.columns) do k.known[c] = true end
end

do
  local out = {}
  for _, k in ipairs(M.KINDS) do
    local cols = {k.key .. ' TEXT PRIMARY KEY'}
    for _, c in ipairs(k.columns) do cols[#cols + 1] = c .. (INTEGER[c] and ' INTEGER' or ' TEXT') end
    if k.check then cols[#cols + 1] = 'CHECK (' .. k.check .. ')' end
    out[#out + 1] = 'CREATE TABLE ' .. k.field .. ' (' .. table.concat(cols, ', ') .. ')'
  end
  out[#out + 1] = 'CREATE TABLE ops (key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL)'
  -- meta: fence (the cleanup fence path), writes (the count of committed updates).
  out[#out + 1] = 'CREATE TABLE meta (name TEXT PRIMARY KEY, value)'
  out[#out + 1] = "INSERT INTO meta (name, value) VALUES ('writes', 0)"
  M.SCHEMA = out -- one statement each: hub.sql.exec runs one statement for each call
end

-- row_json answers the SQL expression of one row of kind k as JSON text. json_patch('{}', ...) drops
-- the NULL members: a missing field stays nil.
function M.row_json(k)
  local list = {}
  for _, c in ipairs(k.columns) do list[#list + 1] = "'" .. c .. "', " .. (k.json[c] and 'json(' .. c .. ')' or c) end
  return "json_patch('{}', json_object(" .. table.concat(list, ', ') .. '))'
end
-- CATALOG is ONE statement, so a read outside a transaction (a render) is one snapshot.
do
  local parts = {}
  for _, k in ipairs(M.KINDS) do parts[#parts + 1] = "SELECT '" .. k.field .. "' AS kind, " .. k.key .. ' AS key, ' .. M.row_json(k) .. ' AS value FROM ' .. k.field end
  parts[#parts + 1] = "SELECT 'meta' AS kind, name AS key, json_object('value', value) AS value FROM meta WHERE name = 'fence'"
  M.CATALOG = table.concat(parts, '\nUNION ALL\n')
end
-- state_of answers the catalog of the CATALOG rows, and the JSON text of each row (raw[kind][key]).
function M.state_of(rows, decode)
  local state, raw = {intents = {}, forwards = {}, cleanups = {}, stops = {}}, {intents = {}, forwards = {}, cleanups = {}, stops = {}}
  for _, row in ipairs(rows) do
    local value = decode(row.value)
    if row.kind == 'meta' then state.fence = value.value
    else state[row.kind][row.key], raw[row.kind][row.key] = value, row.value end
  end
  return state, raw
end
-- values_of answers the column names and the SQL values of a record of kind k (the key first). It
-- fails on a field that the schema does not have, or on a value of the wrong type.
function M.values_of(k, key, record, encode, fail)
  if type(key) ~= 'string' then fail('internal', k.field .. ' has a key that is not a string') end
  if type(record) ~= 'table' then fail('internal', k.field .. '[' .. key .. '] is not a table') end
  for c in pairs(record) do
    if not k.known[c] then fail('internal', k.field .. '[' .. key .. '] has the field ' .. tostring(c) .. ', which the schema does not have') end
  end
  local names, values = {k.key}, {key}
  for i, c in ipairs(k.columns) do
    local v = record[c]
    if v ~= nil and k.json[c] then
      if type(v) ~= 'table' then fail('internal', k.field .. '[' .. key .. '].' .. c .. ' is not a table') end
      v = encode(v)
    elseif v ~= nil and type(v) ~= 'string' and type(v) ~= 'number' then
      fail('internal', k.field .. '[' .. key .. '].' .. c .. ' is not a string or a number')
    end
    names[i + 1], values[i + 1] = c, v
  end
  return names, values
end

local function same(a, b)
  if type(a) ~= 'table' or type(b) ~= 'table' then return a == b end
  for k, v in pairs(a) do if not same(v, b[k]) then return false end end
  for k in pairs(b) do if a[k] == nil then return false end end
  return true
end
local function copy(v)
  if type(v) ~= 'table' then return v end
  local r = {}
  for k, x in pairs(v) do r[k] = copy(x) end
  return r
end

function M.open(app)
  local db, fail, json = app.db, app.fail, rex.json
  local S = {}
  db.migrate {function() for _, sql in ipairs(M.SCHEMA) do db.exec(sql) end end}

  function S.catalog() return (M.state_of(db.query(M.CATALOG), json.decode)) end

  -- S.op answers the saved result of operation key: {found = false} or {found = true, fingerprint, result}.
  function S.op(key)
    local row = db.first('SELECT fingerprint, result FROM ops WHERE key = ?1', key)
    if not row then return {found = false} end
    return {found = true, fingerprint = row.fingerprint, result = json.decode(row.result)}
  end

  local function save(k, key, record)
    local names, values = M.values_of(k, key, record, json.encode, fail)
    local marks = {}
    for i = 1, #names do marks[i] = '?' .. i end
    db.exec('INSERT OR REPLACE INTO ' .. k.field .. ' (' .. table.concat(names, ', ') .. ') VALUES (' .. table.concat(marks, ', ') .. ')', unpack(values, 1, #names))
  end
  -- write saves the difference between catalog before and catalog after, and answers the count of
  -- changed rows. It checks the shape of after first: the four kinds are tables, the fence is nil or
  -- text, and no other field is there. So a field that the schema does not have fails, and nothing
  -- is written.
  local function write(before, after)
    for field, v in pairs(after) do
      if field == 'fence' then
        if type(v) ~= 'string' then fail('internal', 'The fence is not a string') end
      elseif not M.FIELD[field] then fail('internal', 'The catalog has the field ' .. tostring(field) .. ', which the schema does not have')
      elseif type(v) ~= 'table' then fail('internal', 'The catalog field ' .. field .. ' is not a table') end
    end
    for _, k in ipairs(M.KINDS) do
      if after[k.field] == nil then fail('internal', 'The catalog has no ' .. k.field) end
    end
    local n = 0
    for _, k in ipairs(M.KINDS) do
      local old, new = before[k.field], after[k.field]
      for key in pairs(old) do
        if new[key] == nil then db.exec('DELETE FROM ' .. k.field .. ' WHERE ' .. k.key .. ' = ?1', key); n = n + 1 end
      end
      for key, record in pairs(new) do
        if not same(old[key], record) then save(k, key, record); n = n + 1 end
      end
    end
    if after.fence ~= before.fence then
      if after.fence == nil then db.exec("DELETE FROM meta WHERE name = 'fence'")
      else db.exec("INSERT OR REPLACE INTO meta (name, value) VALUES ('fence', ?1)", after.fence) end
      n = n + 1
    end
    return n
  end

  -- S.update applies f to the current catalog and saves the changes, with the operation result op
  -- ({key, fingerprint, result}) if given, in one transaction. If op.key has a saved result with the
  -- same fingerprint, nothing changes and it answers {op_exists = <saved>}; with another fingerprint it
  -- fails with operation_conflict. An error in f changes nothing.
  function S.update(f, op)
    return db.transaction(function()
      if op then
        local saved = S.op(op.key)
        if saved.found and saved.fingerprint ~= op.fingerprint then fail('operation_conflict', 'This key has different content') end
        if saved.found then return {op_exists = saved} end
      end
      local state = S.catalog()
      local before = copy(state)
      f(state)
      local n = write(before, state)
      if op then
        db.exec('INSERT INTO ops (key, fingerprint, result) VALUES (?1, ?2, ?3)', op.key, op.fingerprint, json.encode(op.result))
        n = n + 1
      end
      if n > 0 then db.exec("UPDATE meta SET value = value + 1 WHERE name = 'writes'") end
      return {}
    end)
  end

  return S
end

return M
