-- Forward on the view path, and what tunnels.list reports for it. Ported from tests/tunnels-lab.mjs
-- (fake opentunnel). agent-forward.lua tests the agent path (tunnels.forward) of the same handler;
-- the other flows run on both paths: tunnels.list (tool) and the panel (view). The real-opentunnel
-- run is excluded.

local tests_dir = debug.getinfo(1, 'S').source:match('^@?(.*)/[^/]*$')
dofile(tests_dir .. '/lib/guard.lua')(tests_dir)
local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)

local alice = agent('alice')
local S = session('tunnels-work')
local P = T.port()
local web = T.listen(S, P, 'web')
T.listening(P)
-- shared.shared.tblock: the tunnel block that the first test makes. A table field: in Rex Lua a closure's
-- write to a captured local can be lost after a caught error.
local shared = {}

test('the form lists the pane port first; Forward starts one detached block and opens the panel', function()
  local form = T.open_form(web)
  local select = node(form:render(), 'forward').fields[1]
  expect(select.options[1].value).to_be(S .. '|' .. web.block .. '|' .. P .. '|127.0.0.1')
  expect(select.options[1].label).to_match('^' .. P .. ' · nc · web · 127%.0%.0%.1')
  expect(select.options[#select.options].value).to_be('other')
  expect(select.value).to_be(select.options[1].value)
  local op = T.submit(form, select.options[1].value)
  expect(op.status).to_be('succeeded')
  local blocks = wait('one tunnel block', function() local b = T.tunnel_blocks(S); return #b == 1 and b end, 20)
  shared.tblock = blocks[1].block_id
  expect(blocks[1].placement).to_be('detached')
  local cat = T.catalog()
  expect((next(cat.intents or {}))).to_be(nil)
  local fw = cat.forwards[shared.tblock]
  expect(fw.session_id).to_be(S)
  expect(fw.source_block).to_be(web.block)
  expect(fw.port).to_be(P)
  expect(fw.target).to_be('127.0.0.1:' .. P)
  expect(fw.profile).to_be('lazyrexlab-' .. P)
  expect(fw.creator).to_equal({kind = 'user'})
  T.panel(S) -- the Forward result opened the panel in the form's session
end)

test('the panel and tunnels.list show Connected with the URL', function()
  local v = T.panel(S)
  local label = wait('Connected with a URL', function()
    local row = T.row(v, 'fw/' .. shared.tblock)
    return row and row.label:match('^Port ' .. P .. ' · Connected · https://') and row.label
  end, 40)
  local f = T.forward_of(P, alice)
  expect(f.id).to_be(shared.tblock)
  expect(f.state).to_be('Connected')
  expect(f.url).to_match('^https://lazyrexlab%-' .. P .. '%-%d+%.fake%.invalid$')
  expect(label).to_contain(f.url)
  expect(f.session_label).to_be('tunnels-work')
  expect(f.created_by).to_be('user')
  expect(f.logs_shown).to_be(false)
  expect(v:render().title).to_be('Tunnels (1 connected)')
end)

test('Show Logs places the block beside the source pane; Hide Logs detaches it; a repeated Show changes nothing', function()
  local v = T.panel(S)
  expect(T.row(v, 'fw/' .. shared.tblock).items[1].id).to_be('show')
  expect(v:action('fw/' .. shared.tblock, 'show', {item_id = 'show'}).status).to_be('succeeded')
  local b = wait('the block is placed', function() local x = T.blocks(S)[shared.tblock]; return x and x.placement == 'placed' and x end, 10)
  expect(b.window_id).to_be(web.window)
  expect(T.row(v, 'fw/' .. shared.tblock).items[1].id).to_be('hide')
  expect(T.forward_of(P, alice).logs_shown).to_be(true)
  -- A repeat of Show (a retry after a lost reply) does not move the block again.
  expect(v:action('fw/' .. shared.tblock, 'show', {item_id = 'show'}).status).to_be('succeeded')
  expect(T.blocks(S)[shared.tblock].placement).to_be('placed')
  expect(v:action('fw/' .. shared.tblock, 'hide', {item_id = 'hide'}).status).to_be('succeeded')
  wait('the block is detached', function() return T.blocks(S)[shared.tblock].placement == 'detached' end, 10)
  expect(T.row(v, 'fw/' .. shared.tblock).items[1].id).to_be('show')
  expect(#T.tunnel_blocks(S)).to_be(1)
end)

test('a plugin restart keeps the forward and starts no second tunnel', function()
  T.restart()
  local v = T.panel(S)
  wait('Connected after the restart', function() local r = T.row(v, 'fw/' .. shared.tblock); return r and r.label:find('Connected', 1, true) end, 20)
  expect(#T.tunnel_blocks(S)).to_be(1)
  local ids = {}
  for id in pairs(T.catalog().forwards) do ids[#ids + 1] = id end
  expect(ids).to_equal({shared.tblock})
end)

test('Stop from the panel empties the panel and the list', function()
  local v = T.panel(S)
  expect(v:action('fw/' .. shared.tblock, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  wait('no tunnel block', function() return #T.tunnel_blocks(S) == 0 end, 10)
  wait('the panel is empty', function() return T.row(v, 'empty') ~= nil end, 10)
  expect((next(T.list(alice).forwards or {}))).to_be(nil)
  T.no_cleanup_for(P)
end)

test('Other port…: the target is loopback and the source is the pane that ran the command', function()
  local p = T.port()
  T.forget(p)
  local b = T.forward_other(web, p)
  local fw = T.catalog().forwards[b]
  expect(fw.target).to_be('127.0.0.1:' .. p)
  expect(fw.source_block).to_be(web.block)
  expect(T.panel(S):action('fw/' .. b, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  T.no_cleanup_for(p)
end)

test('Forward input is checked', function()
  local form = T.open_form(web)
  for _, bad in ipairs({'0', '65536', 'x', '1.5', ''}) do
    local op = form:action('forward', 'forward', {values = {port = 'other', other = bad}})
    expect(op.status, bad).to_be('failed')
    expect(op.error.code, bad).to_be('invalid_input')
  end
  expect(#T.tunnel_blocks(S)).to_be(0)
end)

test('a second forward of a port is refused', function()
  local p = T.port()
  T.forget(p)
  local b = T.forward_other(web, p)
  local op = T.submit(T.open_form(web), p)
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('already forwarded')
  expect(#T.tunnel_blocks(S)).to_be(1)
  -- The refused form replaced the panel in its slot: open the panel again.
  expect(T.open_panel(web):action('fw/' .. b, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  T.no_cleanup_for(p)
end)

test('closing the session ends its tunnel; the panel and the list drop it', function()
  local S2 = session('tunnels-two')
  local p = T.port()
  local web2 = T.listen(S2, p, 'web2')
  T.listening(p)
  local form = T.open_form(web2)
  local first = node(form:render(), 'forward').fields[1].options[1]
  expect(first.label).to_match('^' .. p .. ' · nc · web2')
  expect(T.submit(form, first.value).status).to_be('succeeded')
  wait('the second tunnel block', function() return #T.tunnel_blocks(S2) == 1 end, 20)
  local f = wait('the list shows it', function() return T.forward_of(p, alice) end, 10)
  -- The panel in the first session lists the forward of the other session.
  local v = T.open_panel(web)
  wait('the first panel lists it', function() return T.row(v, 'fw/' .. f.id) ~= nil end, 20)
  close_session(S2)
  wait('the panel drops the closed session', function() return T.row(v, 'fw/' .. f.id) == nil end, 20)
  expect(T.forward_of(p, alice)).to_be(nil)
  expect((next(T.catalog().forwards or {}))).to_be(nil)
  T.no_cleanup_for(p)
end)

test('Show Logs is refused when the source pane is hidden', function()
  -- Last test: the palette refuses a hidden pane, so the source pane stays hidden afterwards.
  local p = T.port()
  T.forget(p)
  local b = T.forward_other(web, p)
  rex.call('session.detach_block', {session_id = S, block_id = web.block})
  local v = T.panel(S)
  local op = v:action('fw/' .. b, 'show', {item_id = 'show'})
  expect(op.status).to_be('failed')
  expect(op.error.message).to_match('source pane is closed or hidden')
  expect(T.blocks(S)[b].placement).to_be('detached')
  expect(v:action('fw/' .. b, 'stop', {item_id = 'stop'}).status).to_be('succeeded')
  T.no_cleanup_for(p)
end)
