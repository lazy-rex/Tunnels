local ports = dofile(assert(rex.args.module))
rex.call('client.keymap', {actions = {{name = 'ports.scan', kind = 'client', title = 'Lab port scan'}}})
rex.call('client.set_label', {label = 'tunnels-ports-probe'})
rex.on('client_perform_requested', function(_, event)
  local ok, value = pcall(ports.scan, event.args.session_id)
  rex.call('client.reply', {call_id = event.call_id, result = ok and value or nil,
    error = not ok and {code = 'internal', message = tostring(value)} or nil})
end)
