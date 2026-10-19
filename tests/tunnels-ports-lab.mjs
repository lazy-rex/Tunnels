// Run against an isolated server started with spikes/lab/server.sh.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {spawn, execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {connectControl} from '../../LazyRex/lib/rex-client.mjs';
const self = fileURLToPath(import.meta.url);
if (process.argv[2] === 'listener') {
  const s = net.createServer(c => c.end());
  s.listen(0, '127.0.0.1', () => fs.writeFileSync(process.argv[3], JSON.stringify({pid: process.pid, port: s.address().port})));
} else if (process.argv[2] === 'parent') {
  const child = spawn(process.execPath, [self, 'listener', process.argv[3]], {stdio: 'inherit'});
  child.on('exit', code => process.exit(code || 0));
  process.on('SIGTERM', () => child.kill());
} else {
  const lab = process.env.TUNNELS_LAB || '/tmp/rexlab-tunnels-codex';
  assert(lab.startsWith('/tmp/rexlab-') || lab.startsWith('/private/tmp/rexlab-'), 'use an isolated lab');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tunnels-ports-'));
  const c = await connectControl(`${lab}/rex.sock`);
  const sessions = [];
  const external = net.createServer(socket => socket.end());
  await new Promise(resolve => external.listen(0, '127.0.0.1', resolve));
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  async function waitFor(f) {
    for (let i = 0; i < 100; i++) { const value = await f(); if (value) return value; await sleep(100); }
    throw Error('lab condition timed out');
  }
  try {
    const make = async name => {
      const s = (await c.call('session.create', {label: name})).session_id;
      sessions.push(s);
      await c.call('session.attach', {session_id: s, event_scope: 'session'});
      return s;
    };
    const a = await make('ports-a');
    const b = await make('ports-b');
    console.log(execFileSync('rex', ['-S', `unix://${lab}/rex.sock`, '--autostart=false', 'do', '-s', a,
      path.join(path.dirname(self), 'tunnels-ports-unit.lua'),
      `module=${path.resolve(path.dirname(self), '../../Tunnels/tunnels_ports.lua')}`], {encoding: 'utf8'}).trim());
    const blocks = [];
    for (const [i, session] of [a, b].entries()) {
      const output = path.join(dir, `${i}.json`);
      const created = await c.call('session.new_window', {session_id: session, window_label: `listener-${i}`,
        layout: {block: {flavor: 'com.superlogical.terminal.shell', options: {
          command: [process.execPath, self, 'parent', output], login: false}}}});
      const info = await waitFor(() => fs.existsSync(output) && JSON.parse(fs.readFileSync(output)));
      blocks.push({session, block: created.block_ids[0], window: created.window_id, ...info});
    }
    const module = path.resolve(path.dirname(self), '../../Tunnels/tunnels_ports.lua');
    await c.call('session.new_block', {session_id: a, flavor: 'com.superlogical.terminal.shell', options: {
      command: ['rex', '-S', `unix://${lab}/rex.sock`, '--autostart=false', 'do',
        path.join(path.dirname(self), 'tunnels-ports-probe.lua'), `module=${module}`], login: false}});
    const probe = await waitFor(async () => (await c.call('client.list')).clients.find(x => x.info?.label === 'tunnels-ports-probe'));
    const scan = async () => (await c.call('client.perform', {client_id: probe.client_id, action: 'ports.scan', args: {session_id: b}, timeout_ms: 10000})).result;
    let result = await scan();
    assert.deepEqual(result.warnings, {}); // Rex encodes empty Lua tables as objects.
    const rows = Object.values(result.ports);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].session_id, b, 'current session sorts first');
    for (const block of blocks) {
      const row = rows.find(x => x.pid === block.pid);
      assert.equal(row?.port, block.port, 'descendant listener appears');
      assert.equal(row?.block_id, block.block, 'listener belongs to its root pane');
      assert.equal(row?.window_id, block.window);
      assert.equal(row?.address, '127.0.0.1');
    }
    assert(!rows.some(x => x.port === external.address().port), 'outside processes stay outside the scan');
    // Infrastructure roots remain ancestry boundaries but never become port choices.
    for (const label of ['lazyrex-tunnel:probe', 'lazyrex-plugin:probe', 'lazyrex-view:probe',
      'lazyrex-form:probe', 'lazyrex-placeholder:probe', 'lazyrex-hub', 'lazyrex-dev-process']) {
      await c.call('session.set_block_label', {session_id: a, block_id: blocks[0].block, label});
      result = await scan();
      assert(!Object.values(result.ports).some(x => x.pid === blocks[0].pid), `exclude ${label}`);
    }
    await c.call('session.set_block_label', {session_id: a, block_id: blocks[0].block, label: 'source'});
    await c.call('session.detach_block', {session_id: a, block_id: blocks[0].block});
    result = await scan();
    const detached = Object.values(result.ports).find(x => x.pid === blocks[0].pid);
    assert.equal(detached.window_id, '');
    assert.equal(detached.tab, '');
    await c.call('block.close', {session_id: b, block_id: blocks[1].block});
    result = await scan();
    assert(!Object.values(result.ports).some(x => x.block_id === blocks[1].block), 'closed pane disappears');
    console.log('PASS: descendant ownership, current-session order, outside listener exclusion, infrastructure exclusion, detached pane, closed pane');
  } finally {
    for (const session of sessions) await c.call('session.destroy', {session_id: session}).catch(() => {});
    external.close();
    c.close();
    fs.rmSync(dir, {recursive: true, force: true});
  }
}
