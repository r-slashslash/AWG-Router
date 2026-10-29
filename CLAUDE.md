# AWG Router — notes for development

Web panel for AmneziaWG (AWG up to 3.1): users, full tunnel settings and cascade routing
(clients exit through other AWG servers; chosen networks go direct; per-client overrides).
Public repo: https://github.com/r-slashslash/AWG-Router (branch `main`, MIT).

## Ground rules
- **Python standard library only** (PyPI may be unreachable). Own tiny HTTP framework in `app/web.py`.
- **Every user-facing string goes through i18n in 4 languages: ru, en, zh, fa** (fa is RTL).
  Server returns `Msg("key", **params)` → JSON `{"$t": key, "p": params}`; the browser translates
  with `t()` / `th()` / `tm()` from `app/static/i18n.js`. Add each new key to all four dictionaries.
  Keep `{placeholders}` identical across languages; wrap mixed-direction text in `<bdi>`.
- Code comments and docstrings are in Russian; README exists in en / ru / zh / fa — keep all four in sync.
- The installer (`install.sh`) speaks English only.
- Commits end with `Co-Authored-By: Claude …` only (no session links). Push to `main`;
  users update with `awg-router update`, which downloads the `main` tarball from GitHub.

## Layout
| Path | What |
|---|---|
| `app/main.py` | API endpoints, auth (signed cookie, 4 h session, 8 fails → 10 min block), startup, `data/status.json` |
| `app/web.py` | HTTP server: routing, JSON, static, TLS + plain-HTTP→HTTPS redirect, 4 MB body limit, body draining |
| `app/engine.py` | Reconcile loop: discover target, start exit tunnels `awgrN`, build/apply nftables, ip rules, health |
| `app/nftgen.py` | nftables ruleset generator (table `ip awgr`, chains `c_prerouting`/`c_forward`/`c_postrouting`) |
| `app/system.py` | Targets: `ContainerTarget` (nsenter into Amnezia container), `HostTarget` (pid 1), `DemoTarget`; docker API via socket; host runtime install |
| `app/users.py` | `ServerManager`: clients CRUD, client configs/vpn:// links, server params, host init |
| `app/awgserver.py` | Server conf model (Amnezia layout), parameter generation/validation, client conf, vpn:// encoder |
| `app/awgconf.py` | Parsing exit configs (`.conf`, JSON, `vpn://`) |
| `app/lists.py` | Country / ASN / URL / manual network lists (ipverse → ipdeny / RIPEstat fallback) |
| `app/tlsmgr.py` | Let's Encrypt via `lego` (profile `shortlived`, 6-day IP certs, renew ~3 days), self-signed fallback, hot reload |
| `app/store.py` | `data/state.json` (routing, upstreams, lists, client policies, private keys, settings) |
| `app/initserver.py` | CLI: create an Amnezia-layout server config (used by installer for a new container) |
| `app/uninstall.py` | Removes nft table / ip rules from the target (used by `awg-router uninstall`) |
| `app/static/` | SPA: `index.html`, `app.js` (tabs: overview, clients, exits, routing, lists, server, system), `app.css`, `i18n.js`, `qrcode.js` (MIT, Kazuhiko Arase) |
| `awg-server/` | Dockerfile + start.sh for an Amnezia-compatible `amnezia-awg2` container the installer can create |
| `Dockerfile` | Builds amneziawg-go + static awg/awg-quick (Go), copies lego; Python 3.13 alpine runtime |
| `install.sh` | Installer/updater; works via `curl … | bash` (bootstraps code into `/opt/awg-router`) |
| `tests/` | `test_core.py` (unittest), `netns_e2e.py` (routing in netns, needs root + pyroute2), `awg_real_e2e.py` (real AWG tunnels) |

## How it works (essentials)
- Panel container: `network_mode: host`, `pid: host`, `privileged`, docker.sock mounted; data in `./data`.
- Container mode: AmneziaVPN layout in `/opt/amnezia/awg/` — `awg0.conf` (I1–I5 stored as `# I1 = …`
  comments, `" = "` separators), `wireguard_psk.key` (one PSK shared by all clients),
  `wireguard_server_public_key.key`, `clientsTable` (JSON names). Peers applied with `awg syncconf`;
  server-side params (port, S1–S4, H1–H4, HeaderProtectionKey) need an interface restart.
- Host mode: `/etc/amnezia/amneziawg/awg0.conf`, systemd `awg-quick@awg0`, NAT in PostUp (ends with `; true`).
- Disabled client = commented peer block marked `#awgr:disabled` (keeps its IP reserved).
- Routing: prerouting marks packets → fwmark `0x2000+N` → `ip rule` priority `20000+N` → table `2000+N`
  → `default dev awgrN`; `unreachable` fallback route; SNAT to the exit's tunnel address;
  link-local `169.254.200.N` on `awgrN`; MSS clamp; `rp_filter=2`.
- `Target.key` includes container PID + start time → container restart triggers full re-apply.

## Gotchas already hit
- nft chain names `fwd`/`post`/`pre` are reserved words → use `c_*` names.
- Browsers block some ports (ERR_UNSAFE_PORT: 6697, 6665–6669, 5060, 2049, 4045, …) — installer's
  `UNSAFE_PORTS` list; never pick or keep those.
- Unread request bodies must be drained (keep-alive) — see `_drain_body` in `web.py`.
- Real AWG re-enable of a peer may need ~15 s (WireGuard session timers) — e2e retries.
- `install.sh` reads answers from `/dev/tty` (works under `curl | bash`); `ask` falls back to defaults without a TTY.
- Installer never deletes an existing `amnezia-awg2` container: it renames it `…-old-<date>`.

## Testing
```bash
python3 -m unittest discover tests
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo PANEL_PORT=8099 PUBLIC_HOST=203.0.113.5 python3 -m app.main
```
Demo mode (`DRY_RUN=1`) fakes the AWG server; useful with Playwright for UI checks in all four
languages, desktop and 375 px mobile (no horizontal overflow; RTL for fa).

## Status
Verified on a real server (Ubuntu 22.04, AmneziaVPN container): image builds, Let's Encrypt
issuance through the installer, the panel itself, update from GitHub.
