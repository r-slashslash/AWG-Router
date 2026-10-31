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
- **Bump `VERSION` in `app/version.py`** with every user-visible change: panels compare it with
  `main` on GitHub (every 6 h) to show "update available". A fix after a release is a new version,
  never the same number again; add it to `CHANGELOG.md`; tag `vX.Y.Z` and never move a tag.
- No requests to third-party hosts from the browser: fonts and scripts are served by the panel
  (`app/static/fonts`, OFL). Google and CDNs are blocked in CN/IR and leak who opens the panel.

## Layout
| Path | What |
|---|---|
| `app/main.py` | API endpoints, auth (signed cookie, 4 h session, 8 fails → 10 min block, optional TOTP step: `need_code`; a password changed in the panel lives as PBKDF2 in `data/panel_password.json` and wins over `.env`), backup/restore, startup, `data/status.json` |
| `app/totp.py` | Optional 2FA (RFC 6238): secret in `data/totp.json` (re-read by mtime; `awg-router 2fa-off` deletes it), replay-protected codes; enabling/disabling changes the session tag → other sessions end |
| `app/traffic.py` | Per-client traffic totals and months (`data/traffic.json`, `{"_v": 2, "clients": …, "outs": …, "acct": …}`), deltas between polls survive counter resets; the first sight of a peer is only a baseline. `outs` — totals per exit (`direct` or upstream id, used by exit quotas); `by_out` in a client — month split by exit; `acct` — last values of the nft counters |
| `app/limits.py` | Client end date / traffic quota (`state.limits`): auto-off (`auto_off`: `exp` / `quota:<month>`), monthly auto-on; called after each poll |
| `app/updates.py` / `app/version.py` | Panel version and the update check |
| `app/cps.py` | Signature packets I1–I5: strict tag check (`b r rc rd t` only — `<c>` is kernel-only, `<d>/<ds>/<dz>` go-only), byte size (≤ 1400), RFC-based presets (STUN, QUIC Initial 1200 B, DNS+EDNS 128 B, SIP, AmneziaVPN default, none) with random fields; per-client override in `state.cps[pk]` = `{preset}` or `{preset: custom, values}`, applied in `users.client_config` (conf and vpn://) |
| `app/selfupdate.py` | Update from the panel: `install.sh --update` on the host via `nsenter -t 1` + `systemd-run --unit awg-router-update` (outside the panel container's cgroup, survives its recreation); output in `data/update.log` ending with `exit=N`, state in `data/update.json`; host install dir from the Compose label `com.docker.compose.project.working_dir` (or the `/data` mount source) |
| `app/static/share.html`, `share.js` | Public personal page of a client: `/s/<token>` + `/s/api/<token>` + `/s/assets/<whitelisted file>` — **outside the secret path, no login** (token in `state.shares`; unknown tokens → 404) |
| `app/notify.py` | Optional Telegram notifications (`settings.telegram`, token never sent to the browser): engine events, sign-ins, TLS renewal failure; queue + 5-min dedupe. **Only place with server-side texts** (`TEXTS`, 4 languages) because messages go to Telegram, not the browser |
| `app/web.py` | HTTP server: routing, JSON, static (ETag/304), TLS + plain-HTTP→HTTPS redirect, 4 MB body limit, strict `Content-Length`, body draining, ≤ 128 connections (≤ 24 per IP), 60 s idle timeout |
| `app/engine.py` | Reconcile loop: discover target, start exit tunnels `awgrN`, build/apply nftables, ip rules, health |
| `app/nftgen.py` | nftables ruleset generator (table `ip awgr`, chains `c_prerouting`/`c_forward`/`c_postrouting`); `acct_ruleset` — separate counting table `ip awgr_acct` (dynamic sets `up`/`down` keyed `client ip . ifname`, forward hook at priority filter+10) |
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
| `tests/` | `test_core.py`, `test_api.py` (unittest; `test_api` imports `main` in demo mode), `netns_e2e.py` (routing in netns, needs root + pyroute2), `awg_real_e2e.py` (real AWG tunnels) |

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
- Counting a peer's counter at first sight adds all traffic since the interface started (1.2.0 bug) —
  `traffic.py` treats the first sight as a baseline only.
- Auto-refresh (every 5 s) re-renders the tab: skip it while the user is typing in a field in `#main`.
- Anything outside the secret path is visible to scanners: keep public routes minimal, `Server: httpd`.
  Files under `/s/assets/` are a whitelist (`app.public_files` in `main.py`) — add new ones there.
- `/api/state` is polled every 5 s: keep it small. Manual list text (up to 2 MB) is left out
  (`_list_view`) and fetched by the editor from `GET /api/lists/<id>`.
- Restore (`clean_backup_state`, `clean_server_files`) re-validates every field like panel input:
  ids end up in nft set names, interface names and file names. Hooks (`PostUp` …) from a backup
  are replaced (`awgserver.safe_hooks`) — awg-quick runs them as root.
- Exit configs: `FwMark`/`ListenPort` are dropped (`awgconf.LOCAL_ONLY_KEYS`).
- The counting table `awgr_acct` must **never** be rebuilt with the main `awgr` table (counters
  would reset): `engine._account` creates it only when it is missing or its rule comment marker
  (`nftgen.acct_marker`, bump `ACCT_VER` when the table changes) differs. It only counts — no
  marks, no verdicts — so a failure turns counting off (`acct_state = "off"`, retry in 1 h or on a
  new target) without touching routing. Counter is in the rule (`update @up { … counter }`), not in
  the set declaration: set-level expressions need kernel ≥ 5.11.
- Traffic file format stays `_v: 2` on purpose: new keys are ignored by older panels, so a
  downgrade does not wipe client totals.
- Exit quota: `quota_action` is `notify` or a target (`direct` / `block` / `up:<id>`, not itself),
  independent of `fallback`; `engine.quota_target` (also maps `fallback` from early 1.3.0 builds) and
  `over_quota` make `resolve()` send a healthy over-quota exit to that target (a dead exit still goes
  to `fallback`). Targets count as references (`ref.quota`) — such an exit can't be deleted. Event
  marks `quota_hit` / `quota_warned` (month) live in the upstream in `state.json`.
- Installer and Docker: images are built with `docker build` (`build_image`), not `docker compose build` —
  Compose 2.40.2+ refuses to build with buildx < 0.17 (Debian 13 ships 0.13.1); `compose up --no-build`
  only starts. Compose and buildx are updated to the latest GitHub release on every run (`plugin_latest`,
  into `/usr/local/lib/docker/cli-plugins`, sha256-checked); apt packages are only the fallback (Debian
  11/12 have only Compose v1). Docker is installed
  after the questions; an installed but stopped daemon is started first (needed to find Amnezia).
- Telegram backups (`settings.telegram.backup` off/daily/weekly, `backup_pw`, `backup_last`, `backup_error`):
  `main.backup_tick` every 15 min, a failure retries after 1 h. Encryption is `openssl enc -aes-256-cbc
  -pbkdf2 -iter 200000` (no AES in the stdlib); `POST /api/backup/decrypt` turns such a file back into
  JSON for the normal restore. `backup_pw` is never sent to the browser (`notify.public_view`).
- Client early warnings in `limits.enforce`: `exp_warned` (the end date warned about) and
  `quota_warned` (month or `total`), 3 days / 90 %; the browser's "Ending soon" filter uses the same rule.
- Web app manifest: `static/manifest.webmanifest` with `start_url`/`scope` `../` (relative to the
  manifest, so it stays under the secret path); `web.py` registers the `.webmanifest` MIME type.
  No service worker on purpose: nothing to cache, no extra code with the panel's cookies.
- I1–I5 are client-side: the server drops them, so a per-client override needs no server change —
  only a new client config. A preset is stored by name, so fixing a preset reaches clients with
  their next config. Per-client data lives in `state.cps` (not `state.clients`, which `put_client`
  rebuilds); deleting a client drops it.
- Very old installs may have an `awg-router` helper whose `update` doesn't pass `--update` (it rebuilds
  old code). Fix: re-run the installer via `curl … | bash`, which rewrites the helper.

## Testing
```bash
python3 -m unittest discover tests
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo PANEL_PORT=8099 PUBLIC_HOST=203.0.113.5 python3 -m app.main
```
Demo mode (`DRY_RUN=1`) fakes the AWG server; useful with Playwright for UI checks in all four
languages, desktop and 375 px mobile (no horizontal overflow; RTL for fa).
README screenshots (`docs/screenshots`) come from demo mode: English, light theme, 1280×860 at
scale 1.25 (1600×1075) and phone 390×844 at scale 3; hide the demo banner and "(demo)", quantize
to 256 colours.

## Status
Verified on a real server (Ubuntu 22.04, AmneziaVPN container): image builds, Let's Encrypt
issuance through the installer, the panel itself, update from GitHub.
