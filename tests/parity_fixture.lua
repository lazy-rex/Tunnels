-- Parity fixture (LazyRex docs/testing.md, "Agent parity"): renders the Release Reservation form,
-- which opens only from the cleanup row of a legacy sending record in the Tunnels panel. The
-- fixture saves such a record, opens the form, and then releases the record through the form.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)
local profile = T.prefix .. T.port()
T.edit(function(v) v.cleanups = v.cleanups or {}; v.cleanups[profile] = {phase = 'sending', key = 'parity', saved_at = os.time() - 1} end)
local pane = T.shell(session('tunnels-parity'), 'work')
local v = T.open_panel(pane)
wait('the release action', function() local n = T.row(v, 'cleanup/' .. profile); return n and n.action and n.action.name == 'release' end, 10)
local op = v:action('cleanup/' .. profile, 'release', {})
if op.status ~= 'succeeded' or op.effects == 'failed' then error('the release form did not open: ' .. show(op), 0) end
local form = user:view(op.result.form, 'tunnels', pane.session)
form:render()
local done = form:action('release', 'release', {values = {accept = true}})
if done.status ~= 'succeeded' then error('the release failed: ' .. show(done), 0) end
