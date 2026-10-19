// Lab: the Tunnels plugin end to end (plugins/tunnels.lua). LAB ONLY.
// Setup (tests/README.md, "Tunnels"): a lab server started with
//   LAZYREX_TUNNELS_PROFILE_PREFIX=lazyrexlab- LAB_CONFIG=$LAB/init.lua spikes/lab/server.sh $LAB
// ($LAB/init.lua is one line: pcall(require, "lazyrex_palette")), and dev.sh on a hub config with the
// plugins lazyrex and tunnels (events "all") and palette_lua $LAB/lazyrex_palette.lua.
// TUNNELS_REAL=1 uses the real opentunnel (the maintainer approved one real tunnel per run, 2026-10-17): it
// opens one public tunnel to a 127.0.0.1 test server that serves a fixed string, and at the end it
// deletes the lab profile. Without it, set LAZYREX_TUNNELS_OPENTUNNEL to tests/fake-opentunnel.sh in
// the lab server's environment.
// Checks: the palette command opens the form with the pane's port first; Forward starts one detached
// block in the source session and opens the Tunnels panel; the panel shows Connected and the URL;
// (real) the URL serves the test string; Show Logs puts the block beside the source pane; Hide Logs
// detaches it; a repeated Show changes nothing; Stop closes the block; closing the session ends a
// second forward, and the panel drops it; a plugin restart keeps the forward list.
import {connectControl} from '../../LazyRex/lib/rex-client.mjs';
import fs from 'node:fs';
import http from 'node:http';
import {execFileSync, spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
const LAB = process.env.TUNNELS_LAB || '/tmp/rexlab-tunnels-claude', SOCK = `unix://${LAB}/rex.sock`;
assert(LAB.startsWith('/tmp/rexlab-'), 'use an isolated lab');
const REAL = process.env.TUNNELS_REAL === '1';
// A real run opens one tunnel identity only: the session-close step uses the same port, so the same
// profile and hostname, after Stop.
const PORT = Number(process.env.TUNNELS_PORT || 47811), PORT2 = REAL ? PORT : PORT + 1;
const PREFIX = 'lazyrexlab-', BODY = 'lazyrex-tunnel-lab-ok';
const c = await connectControl(`${LAB}/rex.sock`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
let lastScreen = ''; // the screen that the last failed check read, printed on a timeout
const waitFor = async (what, f, ms = 15000) => { for (let t = 0; t < ms; t += 200) { const v = await f(); if (v) return v; await sleep(200); } assert.fail(`timed out: ${what}\n${lastScreen}`); };
const rex = (...a) => execFileSync('env', ['-u', 'REX_SESSION', '-u', 'REX_BLOCK', 'rex', '-S', SOCK, '--autostart=false', ...a], {encoding: 'utf8'});
const EV = `${LAB}/int/events.jsonl`;
const startAt = new Date().toISOString();
const events = name => fs.readFileSync(EV, 'utf8').split('\n').filter(l => l.includes(`"event":"${name}"`)).map(l => JSON.parse(l)).filter(e => e.at >= startAt);
const hubId = (await c.call('client.list')).clients.filter(x => x.info?.label === 'lazyrex-hub' && x.connection_state === 'connected').at(-1).client_id;
const hub = async (action, args = {}) => (await c.call('client.perform', {client_id: hubId, action, args, timeout_ms: 10000})).result;
const screen = (sess, block) => { try { return lastScreen = rex('capture', '-s', sess, '-b', block).replace(/\s+/g, ' '); } catch { return ''; } };
const press = (sess, block, ...keys) => rex('send-key', '-s', sess, '-b', block, ...keys);
const viewOf = async (sess, win) => (await c.call('session.view', {session_id: sess})).windows.find(w => w.window_id === win);
const formPane = async (sess, win) => (await viewOf(sess, win))?.layers?.flatMap(l => l.blocks).find(b => b.label?.startsWith('lazyrex-form:'));
const tunnelBlocks = async sess => (await c.call('session.list_blocks', {session_id: sess})).blocks.filter(b => b.label?.startsWith('lazyrex-tunnel:'));
// The plugin's store record, read directly from the hub database (only plugins may call hub.store).
const catalog = async () => JSON.parse(execFileSync('sqlite3', ['-readonly', `${LAB}/int/hub.db`, "SELECT value FROM records WHERE ns = 'tunnels' AND key = 'forwards'"], {encoding: 'utf8'}).trim() || '{}');
// The test server pane: one fixed string on 127.0.0.1 only.
const serverPane = (label, port) => ({block: {flavor: 'com.superlogical.terminal.shell', label, options: {login: false,
  command: [process.execPath, '-e', `require('http').createServer((q, s) => s.end(${JSON.stringify(BODY)})).listen(${port}, '127.0.0.1', () => console.log('listening ${port}'))`]}}});

const FAKE = process.env.FAKE_OT_DIR || '/tmp/fake-opentunnel-claude';
const flag = (name, on) => on ? fs.writeFileSync(`${FAKE}/${name}`, '') : fs.rmSync(`${FAKE}/${name}`, {force: true});
const service = port => fs.existsSync(`${FAKE}/${PREFIX}${port}.service`);
const hubDo = (action, args) => rex('-C', hubId, 'do', action, '--args', JSON.stringify(args));
const sessions = [];
const pickOther = async (sess, block) => {
  press(sess, block, 'enter');
  await waitFor('port list opens', () => screen(sess, block).includes('✓'));
  press(sess, block, 'end', 'enter');
  await waitFor('Other port chosen in the closed field', () => screen(sess, block).includes('Other port… ▾') && !screen(sess, block).includes('✓'));
};
// Pick the last option, Other port…, then type the port and submit.
const forwardOtherIn = async (sess, block, win, port) => {
  const before = new Set((await tunnelBlocks(sess)).map(b => b.block_id));
  await c.call('client.action', {action: 'lazyrex_tunnels_forward_port', origin: 'palette', session_id: sess, block_id: block});
  const f = await waitFor('form for other port', async () => { const p = await formPane(sess, win); return p && screen(sess, p.block_id).includes('Forward a port') && p; });
  await pickOther(sess, f.block_id);
  press(sess, f.block_id, 'tab');
  rex('send', '-s', sess, '-b', f.block_id, String(port));
  press(sess, f.block_id, 'tab', 'enter');
  return waitFor('new tunnel block', async () => (await tunnelBlocks(sess)).find(b => !before.has(b.block_id)));
};
const profiles = new Set();
const S = (await c.call('session.create', {label: 'tunnels-work', initial_windows: [{window_label: 'web', layout: serverPane('web', PORT)}]})).session_id;
sessions.push(S);
await c.call('session.attach', {session_id: S, event_scope: 'session'});
try {
  const web = (await c.call('session.view', {session_id: S})).windows.find(w => w.label === 'web');
  await waitFor('test server listening', () => screen(S, web.focused_block_id).includes(`listening ${PORT}`));

  // 1. The palette command opens the form; the pane's port is the first option.
  await c.call('client.action', {action: 'lazyrex_tunnels_forward_port', origin: 'palette', session_id: S, block_id: web.focused_block_id});
  const form = await waitFor('form pane', () => formPane(S, web.window_id));
  await waitFor('form lists the port', () => screen(S, form.block_id).includes(`${PORT} · node · web`));
  console.log('ok 1 form lists the pane port');

  // 2. Forward (the select has focus; Tab twice reaches the Forward button).
  press(S, form.block_id, 'tab', 'tab', 'enter');
  const [tblock] = await waitFor('one tunnel block', async () => { const b = await tunnelBlocks(S); return b.length === 1 && b; }, 20000);
  profiles.add(PREFIX + PORT);
  assert.equal(tblock.placement, 'detached', 'the tunnel block starts detached');
  const cat = await catalog();
  assert.deepEqual(Object.keys(cat.forwards), [tblock.block_id], 'the forward is keyed by its block');
  assert.equal(Object.keys(cat.intents ?? {}).length, 0, 'no intent remains');
  const fw = cat.forwards[tblock.block_id];
  assert.equal(fw.session_id, S); assert.equal(fw.source_block, web.focused_block_id); assert.equal(fw.port, PORT); assert.equal(fw.profile, PREFIX + PORT);
  console.log('ok 2 forward started one detached block');

  // 3. The panel replaces the form and shows Connected with the URL (a new real profile first waits for certificate verification).
  const panel = await waitFor('panel pane', async () => { const p = await formPane(S, web.window_id); return p && p.block_id !== form.block_id && p; });
  const url = await waitFor('panel shows Connected and URL', () => screen(S, panel.block_id).match(new RegExp(`Port ${PORT} · Connected · (https://[\\w.-]+)`))?.[1], REAL ? 300000 : 40000);
  console.log('ok 3 panel shows', url);
  if (REAL) {
    const body = await waitFor('the URL serves the test string', () => {
      const r = spawnSync('curl', ['-sS', '--max-time', '10', url], {encoding: 'utf8'});
      return r.stdout === BODY && r.stdout;
    }, 60000);
    console.log('ok 3b real tunnel serves', JSON.stringify(body));
  }

  // 4. Show Logs puts the block beside the source pane; Hide Logs detaches it. The panel opens with
  // focus on its first control (Show Logs); the item keeps its place as Hide Logs.
  const placement = async () => (await tunnelBlocks(S))[0]?.placement;
  const inWeb = async id => (await viewOf(S, web.window_id)).layers.flatMap(l => l.blocks).some(b => b.block_id === id);
  press(S, panel.block_id, 'enter');
  await waitFor('Show Logs places the block', async () => await placement() === 'placed');
  assert(await inWeb(tblock.block_id), 'the log is in the source pane window');
  await waitFor('the item is Hide Logs', () => screen(S, panel.block_id).includes('Hide Logs'));
  console.log('ok 4 Show Logs');
  press(S, panel.block_id, 'enter');
  await waitFor('Hide Logs detaches the block', async () => await placement() === 'detached');
  await waitFor('the item is Show Logs', () => screen(S, panel.block_id).includes('Show Logs'));
  assert.equal((await tunnelBlocks(S)).length, 1, 'Show and Hide keep one tunnel block');
  console.log('ok 5 Hide Logs');

  // 6. A plugin restart keeps the forward and its block; it starts no second tunnel.
  hubDo('hub.admin.stop', {plugin: 'tunnels'}); hubDo('hub.admin.start', {plugin: 'tunnels'});
  await waitFor('panel renders after restart', () => screen(S, panel.block_id).includes('Port ' + PORT + ' · Connected'), 20000);
  assert.equal((await tunnelBlocks(S)).length, 1, 'no second tunnel after a restart');
  assert.deepEqual(Object.keys((await catalog()).forwards), [tblock.block_id]);
  console.log('ok 6 restart keeps the forward');

  // 7. Stop (Tab to Stop) closes the block and removes the forward.
  press(S, panel.block_id, 'tab', 'enter');
  await waitFor('Stop closes the block', async () => (await tunnelBlocks(S)).length === 0);
  await waitFor('panel is empty', () => screen(S, panel.block_id).includes('No ports are forwarded'));
  assert.equal(Object.keys((await catalog()).forwards).length, 0);
  console.log('ok 7 Stop');
  if (REAL) {
    const r = spawnSync('curl', ['-sS', '--max-time', '10', url], {encoding: 'utf8'});
    assert.notEqual(r.stdout, BODY, 'the URL no longer serves after Stop');
    console.log('ok 7b URL stopped serving:', (r.stderr || r.stdout).trim().slice(0, 120));
  }

  // 8. Closing the session ends its tunnel: a forward in a second session, then destroy it.
  // 9. Fake only: "Other port…", failures and cleanup of an interrupted start.
  if (!REAL) {
    for (const name of ['fail-up', 'slow-up', 'fail-serve', 'fail-down', 'slow-down']) fs.rmSync(`${FAKE}/${name}`, {force: true});
    // New profiles, so that the run script calls up.
    for (let p = PORT + 5; p <= PORT + 8; p++) fs.rmSync(`${FAKE}/${PREFIX}${p}.id`, {force: true});
    const service = port => fs.existsSync(`${FAKE}/${PREFIX}${port}.service`);
    // Forward a port through the Other port option.
    const forwardOther = port => forwardOtherIn(S, web.focused_block_id, web.window_id, port);
    const stopAll = async () => {
      const p = await waitFor('panel', () => formPane(S, web.window_id));
      for (const b of await tunnelBlocks(S)) await c.call('block.close', {session_id: S, block_id: b.block_id});
      await waitFor('forwards removed', async () => Object.keys((await catalog()).forwards).length === 0, 20000);
      return p;
    };

    // 9a. Other port: the source pane is the pane that ran the palette command.
    const other = await forwardOther(PORT + 5);
    const ofw = (await catalog()).forwards[other.block_id];
    assert.equal(ofw.target, `127.0.0.1:${PORT + 5}`); assert.equal(ofw.source_block, web.focused_block_id);
    await stopAll();
    console.log('ok 9a Other port');

    // 9b. up fails after it registered the service: the run script runs down; the panel shows Failed.
    flag('fail-up', true);
    const failed = await forwardOther(PORT + 6);
    const pf = await waitFor('panel', () => formPane(S, web.window_id));
    await waitFor('panel shows Failed', () => new RegExp(`Port ${PORT + 6} · Failed \\(exit status 1\\)`).test(screen(S, pf.block_id)));
    assert(!service(PORT + 6), 'no service registration remains after a failed up');
    flag('fail-up', false);
    await stopAll();
    console.log('ok 9b failed up leaves no service');

    // 9c. The block is closed between up and down: the plugin runs down after the forward ends.
    flag('slow-up', true);
    const slow = await forwardOther(PORT + 7);
    await waitFor('up registered the service', () => service(PORT + 7));
    await c.call('block.close', {session_id: S, block_id: slow.block_id});
    await waitFor('the plugin removes the service', () => !service(PORT + 7), 20000);
    await waitFor('no cleanup pending', async () => Object.keys((await catalog()).cleanups ?? {}).length === 0);
    flag('slow-up', false);
    console.log('ok 9c interrupted up is cleaned up');

    // 9d. serve fails: the panel shows Failed with its exit code.
    flag('fail-serve', true);
    await forwardOther(PORT + 8);
    const ps = await waitFor('panel', () => formPane(S, web.window_id));
    await waitFor('panel shows serve failure', () => new RegExp(`Port ${PORT + 8} · Failed \\(exit status 3\\)`).test(screen(S, ps.block_id)));
    flag('fail-serve', false);
    await stopAll();
    console.log('ok 9d serve failure');
  }

  // A real run reuses the port: the first test server gives it up first. The panel keeps its window.
  if (REAL) await c.call('block.close', {session_id: S, block_id: web.focused_block_id});
  const S2 = (await c.call('session.create', {label: 'tunnels-two', initial_windows: [{window_label: 'web2', layout: serverPane('web2', PORT2)}]})).session_id;
  sessions.push(S2);
  await c.call('session.attach', {session_id: S2, event_scope: 'session'});
  const web2 = (await c.call('session.view', {session_id: S2})).windows[0];
  await waitFor('second server listening', () => screen(S2, web2.focused_block_id).includes(`listening ${PORT2}`));
  await c.call('client.action', {action: 'lazyrex_tunnels_forward_port', origin: 'palette', session_id: S2, block_id: web2.focused_block_id});
  const form2 = await waitFor('second form', () => formPane(S2, web2.window_id));
  await waitFor('second form lists the port', () => screen(S2, form2.block_id).includes(`${PORT2} · node · web2`));
  press(S2, form2.block_id, 'tab', 'tab', 'enter');
  profiles.add(PREFIX + PORT2);
  await waitFor('second tunnel block', async () => (await tunnelBlocks(S2)).length === 1);
  // Step 9 replaced the panel pane: use the panel that is open now.
  const panel8 = await waitFor('panel in the first session', () => formPane(S, web.window_id));
  await waitFor('first panel lists the second forward', () => screen(S, panel8.block_id).includes('Port ' + PORT2), 20000);
  await c.call('session.destroy', {session_id: S2});
  await waitFor('the panel drops the closed session', () => !screen(S, panel8.block_id).includes('Port ' + PORT2), 20000);
  assert.equal(Object.keys((await catalog()).forwards).length, 0, 'the forward record is gone');
  if (REAL) {
    await waitFor('the URL stops serving after the session closes', () => spawnSync('curl', ['-sS', '--max-time', '10', url], {encoding: 'utf8'}).stdout !== BODY, 30000);
  }
  console.log('ok 8 session close ends the tunnel');

  // 10. Fake only: cleanup does not depend on an open panel, and survives a failed down and a restart.
  if (!REAL) {
    for (let p = PORT + 9; p <= PORT + 10; p++) fs.rmSync(`${FAKE}/${PREFIX}${p}.id`, {force: true});
    const shellPane = label => ({block: {flavor: 'com.superlogical.terminal.shell', label, options: {command: ['/bin/sleep', '600'], login: false}}});
    const anyPanel = async () => { for (const s of sessions) { try { for (const w of (await c.call('session.view', {session_id: s})).windows) if (await formPane(s, w.window_id)) return true; } catch {} } return false; };
    const closePanel = async (sess, win) => { const p = await formPane(sess, win); if (p) { press(sess, p.block_id, 'esc'); await waitFor('panel closed', async () => !(await formPane(sess, win))); } };
    await closePanel(S, web.window_id);
    const cleanups = async () => Object.keys((await catalog()).cleanups ?? {});

    // 10a. The session with the only panel closes while up runs: the plugin still runs down.
    flag('slow-up', true);
    const S3 = (await c.call('session.create', {label: 'tunnels-three', initial_windows: [{window_label: 'three', layout: shellPane('three')}]})).session_id;
    sessions.push(S3);
    await c.call('session.attach', {session_id: S3, event_scope: 'session'});
    const w3 = (await c.call('session.view', {session_id: S3})).windows[0];
    await forwardOtherIn(S3, w3.focused_block_id, w3.window_id, PORT + 9);
    await waitFor('up registered the service', () => service(PORT + 9));
    await c.call('session.destroy', {session_id: S3});
    assert(!(await anyPanel()), 'no Tunnels panel is open');
    await waitFor('the plugin runs down without a panel', () => !service(PORT + 9), 30000);
    await waitFor('no cleanup pending', async () => (await cleanups()).length === 0);
    console.log('ok 10a no-panel session close is cleaned up');

    // 10b. down fails after the last forward ends; the plugin restarts; down then succeeds.
    const S4 = (await c.call('session.create', {label: 'tunnels-four', initial_windows: [{window_label: 'four', layout: shellPane('four')}]})).session_id;
    sessions.push(S4);
    await c.call('session.attach', {session_id: S4, event_scope: 'session'});
    const w4 = (await c.call('session.view', {session_id: S4})).windows[0];
    const b4 = await forwardOtherIn(S4, w4.focused_block_id, w4.window_id, PORT + 10);
    await waitFor('up registered the service', () => service(PORT + 10));
    await closePanel(S4, w4.window_id);
    flag('fail-down', true);
    await c.call('block.close', {session_id: S4, block_id: b4.block_id});
    await waitFor('cleanup is recorded', async () => (await cleanups()).includes(PREFIX + (PORT + 10)), 30000);
    await sleep(3000);
    assert(service(PORT + 10), 'down failed: the service remains');
    assert.deepEqual(await cleanups(), [PREFIX + (PORT + 10)], 'the cleanup stays pending');
    hubDo('hub.admin.stop', {plugin: 'tunnels'});
    flag('fail-down', false);
    hubDo('hub.admin.start', {plugin: 'tunnels'});
    await waitFor('the restarted plugin runs down', () => !service(PORT + 10), 30000);
    await waitFor('no cleanup pending', async () => (await cleanups()).length === 0);
    flag('slow-up', false);
    console.log('ok 10b failed down is retried across a restart');

    // 11. A running down owns its profile: Forward of the same port is refused until it ends, and a
    // plugin restart does not start a second down while the first one runs.
    const downBlocks = async () => { const lr = (await c.call('session.list')).sessions.find(x => x.label === 'LazyRex').session_id;
      await c.call('session.attach', {session_id: lr, event_scope: 'session'});
      return (await c.call('session.list_blocks', {session_id: lr})).blocks.filter(b => b.label?.startsWith('lazyrex-tunnel-down:')); };
    const P11 = PORT + 11;
    fs.rmSync(`${FAKE}/${PREFIX}${P11}.id`, {force: true});
    flag('slow-up', false);
    const b11 = await forwardOtherIn(S4, w4.focused_block_id, w4.window_id, P11);
    await waitFor('forward started', () => service(P11) === false && fs.existsSync(`${FAKE}/${PREFIX}${P11}.id`));
    flag('slow-down', true);
    await c.call('block.close', {session_id: S4, block_id: b11.block_id});
    await waitFor('one down block runs', async () => (await downBlocks()).length === 1, 20000);
    // 11a. Forward of the same port while down runs: refused, and no tunnel block starts.
    const before11 = (await tunnelBlocks(S4)).length;
    await c.call('client.action', {action: 'lazyrex_tunnels_forward_port', origin: 'palette', session_id: S4, block_id: w4.focused_block_id});
    const f11 = await waitFor('form', async () => { const p = await formPane(S4, w4.window_id); return p && screen(S4, p.block_id).includes('Forward a port') && p; });
    await pickOther(S4, f11.block_id);
    press(S4, f11.block_id, 'tab'); rex('send', '-s', S4, '-b', f11.block_id, String(P11)); press(S4, f11.block_id, 'tab', 'enter');
    await waitFor('Forward is refused', () => screen(S4, f11.block_id).includes('still stopping its previous tunnel'));
    assert.equal((await tunnelBlocks(S4)).length, before11, 'no tunnel block started');
    console.log('ok 11a same-port Forward refused while down runs');
    press(S4, f11.block_id, 'ctrl+q');
    // 11b. Restart the plugin while down runs: the record stays, no second down starts, then it ends.
    hubDo('hub.admin.stop', {plugin: 'tunnels'}); hubDo('hub.admin.start', {plugin: 'tunnels'});
    await sleep(3000);
    assert((await cleanups()).includes(PREFIX + P11), 'the cleanup record stays while down runs');
    assert.equal((await downBlocks()).length, 1, 'no second down block');
    await waitFor('down ends and the record is removed', async () => (await cleanups()).length === 0, 30000);
    await waitFor('the down block is closed', async () => (await downBlocks()).length === 0);
    flag('slow-down', false);
    // Now the port can be forwarded again.
    const again = await forwardOtherIn(S4, w4.focused_block_id, w4.window_id, P11);
    await c.call('block.close', {session_id: S4, block_id: again.block_id});
    await waitFor('no cleanup pending', async () => (await cleanups()).length === 0, 30000);
    console.log('ok 11b restart during down keeps one down; the port is free afterwards');
  }
} catch (e) {
  // On a failure, show every form and panel pane of the test sessions (coordinator's request).
  for (const sess of sessions) {
    try {
      for (const b of (await c.call('session.list_blocks', {session_id: sess})).blocks.filter(b => b.label?.startsWith('lazyrex-form:'))) {
        console.error(`--- ${b.label} ${b.block_id} ${b.placement}\n` + (() => { try { return rex('capture', '-s', sess, '-b', b.block_id); } catch { return '(no capture)'; } })());
      }
    } catch {}
  }
  throw e;
} finally {
  if (!process.env.KEEP) {
    for (const s of sessions) await c.call('session.destroy', {session_id: s}).catch(() => {});
    // Remove the lab profiles: the tunnel and its hostname, the route file, and the state directory.
    if (REAL) for (const p of profiles) {
      assert(p.startsWith(PREFIX));
      const r = spawnSync('/opt/homebrew/bin/opentunnel', ['--profile', p, 'delete', '--yes'], {encoding: 'utf8'});
      console.log('cleanup', p, (r.stdout + r.stderr).trim());
      const home = process.env.HOME;
      fs.rmSync(`${home}/.config/opentunnel/${p}.toml`, {force: true});
      fs.rmSync(`${home}/.local/state/opentunnel/${p}`, {recursive: true, force: true});
      assert(!fs.existsSync(`${home}/.local/share/opentunnel/${p}`), 'the profile identity is deleted');
      assert(!fs.existsSync(`${home}/Library/LaunchAgents/xyz.opentunnel.${p}.plist`), 'no launchd registration remains');
    }
  }
  c.close?.();
}
