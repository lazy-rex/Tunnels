<!-- Research by Codex, 2026-10-15. Read-only: nothing installed or run. -->

# OpenTunnel research for LazyRex

Research date: 2026-10-15, America/Los_Angeles (2026-10-16 UTC).
Scope: `anomalyco/opentunnel`, not similarly named projects.
No software was installed, built, or run. No tunnel was created.

**Verified-source** means confirmed in repository documentation or code. It does not mean independently tested.
**Inferred** means a design consequence of that evidence. **Unverified** means the reviewed evidence does not establish the claim.

Source snapshot: `a53e64c142ecfe18bbd902bada4345d67fb540c2`.
The latest published release was v0.5.1, published 2026-10-12, with `prerelease=false`.
The snapshot was 13 commits ahead of that tag. Those changes affect server code, tests, deployment, and server documentation.
The reviewed CLI and Rust client files were unchanged in that comparison.
Server defaults below are source defaults, not a measurement of the hosted deployment.
Sources: [release](https://github.com/anomalyco/opentunnel/releases/tag/v0.5.1), [comparison](https://github.com/anomalyco/opentunnel/compare/v0.5.1...a53e64c142ecfe18bbd902bada4345d67fb540c2).

## Main finding

**Verified-source:** OpenTunnel retains a tunnel identity and hostname in a persistent profile. Restarts do not inherently change the URL.
A fixed route such as `lazyrex` gives `https://lazyrex.<id>.opentunnel.xyz`.
The random `<id>` belongs to the tunnel; it is not regenerated on every connection.
**Inferred:** this can provide the stable origin that LazyRex needs for its PWA, if LazyRex preserves the profile identity and route.
This is not a promise of permanent hosted service or recoverability after credential loss. [CLI and files](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/packages/cli/README.md)

## 1. Architecture, hosting, license, and maturity

**Verified-source:** The client opens an outbound WebSocket bridge to the hosted service at `opentunnel.xyz`.
The relay reads the visitor's TLS ClientHello to select the tunnel and route. It then forwards encrypted TLS bytes through that bridge.
The local OpenTunnel client terminates visitor TLS and forwards the decrypted stream to the application.
The public server and local client are distinct processes. [Architecture](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/README.md)

**Verified-source:** The repository documents the hosted relay as a Rust service on Fly.io, with PlanetScale MySQL and Cloudflare DNS.
It replaced an earlier Cloudflare Worker/AWS design. The current server source is included.
The server accepts a configurable domain, database, certificate issuer, and DNS credentials; the CLI accepts `OPENTUNNEL_API` / `--api`.
**Inferred:** both hosted use and self-hosting are possible. Self-hosting requires operating a public relay, DNS, certificates, and storage.
It is more work than running the local tunnel client. [Server deployment](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/server.md), [CLI API selection](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/main.rs)

**Verified-source:** The repository uses the MIT license. The project was created on 2026-03-30 and was active at review time.
Published releases include v0.5.1; source includes protocol vectors, client/server integration tests, and reconnect tests.
**Inferred:** it is an early, actively changing project. Version 0.x and recent infrastructure replacement merit a bounded integration test.
**Unverified:** a service-level agreement, guaranteed URL retention, support commitments, and hosted bandwidth quotas were not established.
Sources: [license](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/LICENSE), [repository metadata](https://api.github.com/repos/anomalyco/opentunnel), [client tests](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-server/tests/clients.rs).

## 2. Stable public URLs: yes, with persistent identity

**Verified-source:** `opentunnel --profile lazyrex route add 127.0.0.1:3000 --name lazyrex` stores a named route in that profile.
The resulting hostname is `lazyrex.<random-tunnel-id>.opentunnel.xyz`.
`--name @` instead uses `<id>.opentunnel.xyz` directly.
Even the default random route is reused when the same target is added again, while its saved configuration remains available. [CLI commands](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/packages/cli/README.md)

**Verified-source:** `up` loads the existing identity and creates one only when none exists.
The server rejects a requested custom tunnel name. Thus `--name lazyrex` does **not** reserve `lazyrex.opentunnel.xyz`.
No supported custom-domain attachment was found in the reviewed API or CLI.
**Inferred:** a CNAME alone is insufficient: routing and certificates expect the configured tunnel suffix. [Identity reuse](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/main.rs), [name rejection](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-server/src/http.rs), [routing](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-server/src/relay.rs)

**Verified-source:** Persistent identity files include `tunnel.json`, `token`, `private-key.pem`, `certificate.pem`, and `chain.pem` under the profile data directory.
Route configuration is separate. `down` stops the service without deleting its identity; `delete --yes` removes the tunnel and loses its hostname.
**Inferred:** keep both data and route configuration across hub restarts, plugin upgrades, and application reinstalls.
Do not implement “disable remote access” with `delete`.
If credentials disappear, fail with an explicit recovery state rather than silently publishing a new origin. [CLI lifecycle](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/packages/cli/README.md), [identity removal](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/client.rs)

**Verified-source:** Certificates renew using the stored CSR. Automatic renewal depends on a connection within the preceding 90 days.
An attaching client triggers renewal when its certificate is near expiry or expired.
That is certificate behavior, not a documented 90-day hostname deletion rule.
**Unverified:** indefinite reservation and restoration after losing the token/private key are not guaranteed by the reviewed material. [Certificate lifecycle](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/protocol.md)

## 3. WebSockets and limits

**Verified-source:** After local TLS termination, the client copies bytes bidirectionally to the configured TCP target without parsing HTTP.
**Inferred:** normal HTTP/1.1 WebSocket upgrade and subsequent binary/text frames can pass through it as `wss://` traffic.
This conclusion comes from stream forwarding, not from confusing the tunnel's own bridge WebSocket with an application WebSocket.
I did not run a browser WebSocket test. [Client forwarding](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/tunnel.rs)

**Verified-source, source defaults:**

| Limit | Meaning for LazyRex |
|---|---|
| 256 connections in the Rust client | Shared by the routes on that client bridge; excess connections are rejected |
| 32 KiB bridge data payload | Stream chunk size, not a 32 KiB application WebSocket-message limit |
| 15-minute visitor inactivity timeout | A connection with no bytes in either direction is reset |
| 60-second half-close inactivity timeout | Applies after one direction ends |
| 30-second stalled-channel handling | A stalled consumer can cause resets; bridge writes also have a timeout |
| Bridge heartbeat 15 seconds; receive-idle timeout 45 seconds | Keeps the bridge healthy; it does not make an idle visitor stream active |
| Reconnect backoff 250 ms to 30 seconds, with jitter | A lost bridge reconnects; existing application connections still need recovery |

Sources: [Rust client](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/tunnel.rs), [protocol constants](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/protocol/bridge.rs), [server timeouts](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-server/src/config.rs), [relay behavior](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/server.md), [bridge handling](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-server/src/bridge.rs).

**Verified-source:** The protocol lacks per-connection flow control; a slow reader can delay other connections sharing a bridge.
**Inferred:** the gateway needs application-level heartbeat and reconnect/resynchronization behavior for browser connections.
Raw TCP tunneling does not forward UDP, so this does not itself relay pion WebRTC media/data-channel UDP traffic.
A WebSocket signaling connection can use the tunnel; WebRTC connectivity remains a separate concern. [Backpressure](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/protocol.md)

**Unverified:** actual hosted traffic quotas, maximum useful throughput, and effective connection limits in the running fleet.
The repository's load tests are not a service guarantee. No assertion of “unlimited WebSockets” is justified.

## 4. TLS termination and relay visibility

**Verified-source:** Visitor TLS terminates in the local OpenTunnel client, using a locally generated private key.
The ordinary relay path carries ciphertext and does not receive that private key.
The API/bridge connection has separate TLS, terminated by the hosted infrastructure.
The local application connection carries decrypted bytes; with the normal route configuration, the Go gateway receives HTTP/WS over loopback.
Do not point this plaintext output directly at a listener that expects another TLS handshake. [Protocol](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/protocol.md), [local forwarding](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/tunnel.rs)

**Verified-source:** The relay sees connection metadata, including the peer address and requested SNI. It necessarily sees encrypted traffic timing and size.
**Inferred:** “blind” means the normal relay implementation cannot read visitor plaintext; it is not a promise of anonymity or protection from an actively malicious domain operator.
The hosted operator controls DNS and certificate issuance infrastructure. Without independently pinned application identity, that operator remains in the browser's trust path.
No independent pinning mechanism was established in this review. [Server routing and certificate configuration](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/server.md)

## 5. Tunnel authentication versus gateway authentication

**Verified-source:** Tunnel creation is unauthenticated. Management endpoints use the issued bearer token; bridge attachment authenticates with that token in-band.
The token authorizes tunnel control. It does not authenticate each person visiting the public URL.
The local TLS acceptor uses `with_no_client_auth()`, so it does not require visitor client certificates. [API contract](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/protocol.md), [TLS acceptor](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel/src/tunnel.rs)

**Verified-source:** Anyone with the URL can reach the route. A random route name is not authentication.
The local target sees a loopback connection, the visitor's unchanged `Host`, and any visitor-supplied forwarding headers.
OpenTunnel does not sanitize those headers or make them trusted. [Trust boundary](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/trust-boundary.md)

**Inferred for LazyRex:** the gateway must enforce pairing/login and authorization on HTTP and WebSocket access.
It must validate allowed Host/Origin values and protect state-changing requests.
It must not grant local privileges just because the peer is loopback.
Keep local-only administrative endpoints on a separate listener that the plugin never exposes.
If real visitor addresses are required, explicitly configure PROXY protocol on both sides; do not trust arbitrary `X-Forwarded-For`.
Do not expose the raw Rex API as the route target. [Trust boundary](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/docs/trust-boundary.md)

## 6. Rex Lua plugin integration

**Verified-source:** The CLI provides `route add/remove/list`, `status`, `up`, `down`, `serve`, and `delete`.
`up` and `route add` normally register a launchd/systemd service. The foreground process is `opentunnel --profile lazyrex serve`.
There is also a local Unix control socket with JSON-line `status`, `reload`, and `stop` requests.
The CLI status command prints human-readable output; no `--json` flag appears in the reviewed command definition. [CLI](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/packages/cli/README.md), [control protocol](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/control.rs), [command definition](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/main.rs)

**Proposed simplest integration:** A Rex Lua plugin calls short CLI commands through the existing process interface and lets OpenTunnel supervise its own daemon.
Use a dedicated profile. Expose “Enable,” “Disable,” “Copy public URL,” and connection status.
Keep credentials out of plugin events and terminal logs. This requires no new HTTP/TLS implementation in Lua.
The local control socket is useful for structured status, but Rex Lua needs a socket helper or Go support to access it.
The public HTTP API alone is insufficient: a client must also implement TLS and the streaming bridge.

**Alternative, inferred:** Rex can own a foreground `serve` process in a dedicated pane, so its log and exit are visible.
But select one supervisor: do not combine a launchd service with a competing Rex process for the same profile.
A profile lock rejects a second service. Fresh `serve` does not create a new identity by itself; it can resume a pending one.
Provision with the supported CLI first, stop its service with `down`, then start `serve` in Rex.
Later `route add` can replace a foreground process with an OS service on macOS. To preserve Rex ownership, edit the declarative route file instead.
The daemon checks it every two seconds. [Foreground behavior](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/daemon.rs), [OS service ownership](https://github.com/anomalyco/opentunnel/blob/a53e64c142ecfe18bbd902bada4345d67fb540c2/crates/opentunnel-cli/src/service.rs)

**Inferred recommendation:** Start with the native daemon under a Lua plugin's control. Only choose Rex-owned foreground supervision if pane ownership is a firm requirement.
Either way, preserve the profile, use a fixed route, expose only the authenticated gateway, and report URL changes explicitly.

Before acceptance, test restart URL stability, WebSocket upgrade/binary traffic, idle recovery, gateway authentication, and service shutdown on the selected release.
These are proposed future checks. None was run during this read-only research.

## Observed with the Tunnels plugin (Claude, 2026-10-17, opentunnel 0.5.2 from Homebrew)

The maintainer approved one real lab tunnel per test run to a 127.0.0.1 test server, and profiles `lazyrex-<port>` with the up/down step.

**Verified-source (v0.5.2):** `serve` does not create an identity. Only `up` and `route add` create one, and both register the launchd service `xyz.opentunnel.<profile>`. `down` removes the registration. The launchd plist sets only `OPENTUNNEL_DAEMON`, so XDG directories cannot isolate a lab profile.

**Observed (lab, `tests/tunnels-lab.mjs` with `TUNNELS_REAL=1`; that test is removed, see the git history):**

- A new profile prints "Waiting for certificate verification (this can take a few minutes)". It took about one minute in three runs.
- `up` then `down` left no plist in `~/Library/LaunchAgents`. The route file `~/.config/opentunnel/<profile>.toml` with `"@" = "127.0.0.1:<port>"` and a foreground `serve` connected: `serve` logs `event={"type":"connecting",...}` and then `event={"type":"connected",...}`.
- The URL `https://<id>.opentunnel.xyz` returned the test server's fixed string.
- Closing the block (Stop) or destroying its session ended `serve`. The URL then failed with `SSL_ERROR_SYSCALL`.
- `delete --yes` removed `~/.local/share/opentunnel/<profile>`. The test also removes the profile's route file and state directory itself; it did not check whether `delete` removes them. After the cleanup, empty `~/.config/opentunnel`, `~/.local/share/opentunnel` and `~/.local/state/opentunnel` directories remained (untested which program leaves each one).
- `opentunnel` is at `/opt/homebrew/bin`. A Rex pane does not get a login PATH, so the plugin looks there itself.
