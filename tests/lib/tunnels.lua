-- Shared helpers of the Tunnels test files. Usage, after the lab guard:
--   local T = dofile(tests_dir .. '/lib/tunnels.lua')(getfenv(1), tests_dir)
-- E is the test file's environment (agent, user, wait, store, write, ...).
return function(E, tests_dir)
  local T = {}
  T.plugin_dir = tests_dir:match('^(.*)/tests$')
  T.fixture = T.plugin_dir .. '/tests/fake-opentunnel.sh'
  T.fake = os.getenv('FAKE_OT_DIR')
  T.prefix = 'lazyrexlab-'
  math.randomseed(os.time())
  local next_port = 44000 + math.random(0, 600) * 20
  function T.port() next_port = next_port + 1; return next_port end

  local function sh(script) local r = rex.exec({'/bin/sh', '-c', script}, {timeout = 10}); return r and r.ok, r end
  local function q(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
  -- flag sets or clears a fake opentunnel switch (fail-up, slow-up, fail-serve, fail-down, slow-down).
  function T.flag(name, on) sh((on and 'mkdir -p ' .. q(T.fake) .. ' && touch ' or 'rm -f ') .. q(T.fake .. '/' .. name)) end
  -- service answers whether the fake launchd registration of port p exists.
  function T.service(p) return (sh('test -f ' .. q(T.fake .. '/' .. T.prefix .. p .. '.service'))) end
  -- forget removes the fake identity of port p, so the run script calls up again.
  function T.forget(p) sh('rm -f ' .. q(T.fake .. '/' .. T.prefix .. p .. '.id')) end

  -- count_lines counts the lines of the file at path that equal line. A missing file counts 0.
  -- Every other failure raises: a failed exec, a grep error (exit status 2 or more), or output that
  -- is not one number. exec is rex.exec unless a test gives a stand-in.
  function T.count_lines(path, line, exec)
    local script = 'if [ ! -e "$1" ]; then echo 0; exit 0; fi; grep -cx -- "$2" "$1"; s=$?; [ "$s" -le 1 ] && exit 0; exit "$s"'
    local r = (exec or rex.exec)({'/bin/sh', '-c', script, 'count', path, line}, {timeout = 10})
    local digits = r and r.ok and type(r.stdout) == 'string' and r.stdout:match('^(%d+)\n?$')
    local n = digits and tonumber(digits)
    if not n then
      error('count_lines: the read of ' .. path .. ' failed: ' .. (r and ('exit ' .. tostring(r.exit_code) .. ', stdout "' .. tostring(r.stdout) .. '", stderr "'
        .. tostring(r.stderr) .. '"' .. (r.error and (', ' .. tostring(r.error)) or '')) or 'no result'), 2)
    end
    return n
  end
  -- down_calls counts the `down` calls of port p's profile in the fake's call log.
  function T.down_calls(p) return T.count_lines(T.fake .. '/calls.log', T.prefix .. p .. ' down') end
  -- down_blocks answers the cleanup blocks (label lazyrex-tunnel-down:) in every session.
  function T.down_blocks()
    local list = {}
    for _, s in ipairs(rex.call('session.list', {}).sessions or {}) do
      pcall(rex.call, 'session.attach', {session_id = s.session_id, event_scope = 'session'})
      local r = rex.call('session.list_blocks', {session_id = s.session_id})
      for _, b in ipairs(r and r.blocks or {}) do
        if (b.label or ''):sub(1, 20) == 'lazyrex-tunnel-down:' then list[#list + 1] = b end
      end
    end
    return list
  end
  function T.catalog() return E.store('forwards').value or {} end
  -- edit changes the forwards record as another writer: it reads the value and its revision, calls
  -- f(value), and writes the value back with that revision (if_rev). A plugin commit in between
  -- makes the write fail with conflict; then edit reads again and calls f again on the fresh
  -- value, so f must only change the value it gets. Other errors raise. A local that f captured and
  -- changes can read stale in the caller after the caught conflict (LazyRex docs/rex-protocol.md,
  -- "Rex Lua runtime"); keep such state in a table field. between (tests of edit
  -- only) runs after the first read and before the first write. It answers the written value.
  function T.edit(f, between)
    for attempt = 1, 10 do
      local r = E.store('forwards')
      local value = r.value or {}
      f(value)
      if attempt == 1 and between then between() end
      local ok, err = pcall(E.write, {{key = 'forwards', value = value, if_rev = r.rev}})
      if ok then return value end
      if not (type(err) == 'table' and err.code == 'conflict') then error(err, 0) end
    end
    error('edit: the forwards record kept changing', 2)
  end
  function T.cleanups() local c = {}; for profile in pairs(T.catalog().cleanups or {}) do c[#c + 1] = profile end; table.sort(c); return c end
  function T.blocks(session)
    local by_id = {}
    for _, b in ipairs(rex.call('session.list_blocks', {session_id = session}).blocks or {}) do by_id[b.block_id] = b end
    return by_id
  end
  function T.tunnel_blocks(session)
    local list = {}
    for _, b in pairs(T.blocks(session)) do if (b.label or ''):sub(1, 15) == 'lazyrex-tunnel:' then list[#list + 1] = b end end
    return list
  end
  function T.list(a) return (a or E.agent('alice')):call('tunnels.list', {}) end
  function T.forward_of(p, a)
    for _, f in pairs(T.list(a).forwards or {}) do if f.port == p then return f end end
  end
  function T.no_cleanup_for(p, timeout)
    return E.wait('no cleanup for port ' .. p, function() return (T.catalog().cleanups or {})[T.prefix .. p] == nil end, timeout or 30)
  end

  -- listen opens a tab in session whose shell runs nc on 127.0.0.1:p as its child.
  function T.listen(session, p, label)
    local w = rex.call('session.new_window', {session_id = session, window_label = label or ('listen-' .. p),
      layout = {block = {flavor = 'com.superlogical.terminal.shell', options = {login = false,
        command = {'/bin/sh', '-c', '/usr/bin/nc -lk 127.0.0.1 ' .. p .. ' >/dev/null; :'}}}}})
    return {session = session, block = w.block_ids[1], window = w.window_id, port = p}
  end
  function T.listening(p)
    E.wait('a listener on ' .. p, function()
      local ok, r = sh('$([ -x /usr/sbin/lsof ] && echo /usr/sbin/lsof || echo /usr/bin/lsof) -nP -iTCP:' .. p .. ' -sTCP:LISTEN -Fp')
      return ok and (r.stdout or ''):find('p%d')
    end, 10)
  end
  -- shell opens a tab in session that runs sleep, a pane with no listener.
  function T.shell(session, label)
    local w = rex.call('session.new_window', {session_id = session, window_label = label,
      layout = {block = {flavor = 'com.superlogical.terminal.shell', options = {command = {'/bin/sleep', '600'}, login = false}}}})
    return {session = session, block = w.block_ids[1], window = w.window_id}
  end

  -- open_form runs the palette command Forward Port… in the pane and answers the form view.
  function T.open_form(pane)
    E.user:command('forward_port', {session = pane.session, block = pane.block})
    local form = E.user:view('/forms/forward', 'tunnels', pane.session)
    form:render()
    return form
  end
  -- submit submits the form: choice is an option value, or a port number for Other port….
  function T.submit(form, choice, key)
    local values = type(choice) == 'number' and {port = 'other', other = tostring(choice)} or {port = choice, other = ''}
    return form:action('forward', 'forward', {values = values}, key)
  end
  -- forward_other forwards p through Other port… from pane and answers the new tunnel block ID.
  function T.forward_other(pane, p)
    local before = {}
    for _, b in ipairs(T.tunnel_blocks(pane.session)) do before[b.block_id] = true end
    local op = T.submit(T.open_form(pane), p)
    if op.status ~= 'succeeded' then error('Forward of ' .. p .. ' failed: ' .. E.show(op), 2) end
    return E.wait('the tunnel block of ' .. p, function()
      for _, b in ipairs(T.tunnel_blocks(pane.session)) do if not before[b.block_id] then return b.block_id end end
    end, 15)
  end
  -- panel answers the Tunnels panel view in session (Forward opens it).
  function T.panel(session)
    local v = E.user:view('/panels/tunnels', 'tunnels', session)
    v:render()
    return v
  end
  -- open_panel runs the palette command Tunnels in the pane and answers the panel view.
  function T.open_panel(pane)
    E.user:command('tunnels', {session = pane.session, block = pane.block})
    return T.panel(pane.session)
  end
  -- row answers the panel row node of the panel row of a forward, or nil.
  function T.row(v, node_id)
    local ok, n = pcall(E.node, v:render(), node_id)
    return ok and n or nil
  end
  -- close_panels closes every open Tunnels panel view (its renderer pane).
  function T.close_panels()
    for _, view in pairs(E.views() or {}) do
      if view.route == '/panels/tunnels' and view.block_id ~= '' and view.session_id ~= '' then pcall(rex.call, 'block.close', {session_id = view.session_id, block_id = view.block_id}) end
    end
    E.wait('no Tunnels panel is open', function()
      for _, view in pairs(E.views() or {}) do if view.route == '/panels/tunnels' then return false end end
      return true
    end, 10)
  end
  function T.restart()
    E.H.hub('hub.admin.stop', {plugin = 'tunnels'})
    E.H.hub('hub.admin.start', {plugin = 'tunnels'})
    E.wait('the plugin answers again', function() return pcall(T.list) end, 20)
  end
  return T
end
