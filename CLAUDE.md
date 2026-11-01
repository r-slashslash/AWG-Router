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
- Commits end with `Co-Authored-By: Claude …` only (no session links). Push to `main`, then tag.
  Users get code only from **releases**: `install.sh` (also `awg-router update` and the panel's
  update button) downloads `releases/latest/download/awg-router.tar.gz`, falling back to the `main`
  tarball only if that fails; GitHub counts the asset's downloads (≈ installs + updates).
- **Bump `VERSION` in `app/version.py`** with every user-visible change: panels compare it with
  the latest release tag (every 6 h; `version.py` on the branch only if there is no release) to show
  "update available". A fix after a release is a new version, never the same number again; add it
  to `CHANGELOG.md`; tag `vX.Y.Z` (must equal `VERSION`) and never move a tag.
- **Release = tag push.** `.github/workflows/release.yml` builds `awg-router.tar.gz` (`git archive
  --prefix=awg-router/`) + `.sha256`, creates the release with notes from the CHANGELOG section (or
  attaches to a release that already exists). Claude Code cloud sessions cannot push tags or create
  releases (the proxy refuses): push `main`, then ask the owner to publish the release in the GitHub
  UI (Releases → Draft a new release → new tag `vX.Y.Z` on `main` → Publish); the workflow then
  attaches the archive. Until then panels see no update and the installer falls back to `main`, so an
  unreleased push breaks nothing. Check the asset is there:
  `gh api repos/r-slashslash/AWG-Router/releases/latest --jq '.assets[].name'`. If Actions did not
  run, build the same archive locally and `gh release upload vX.Y.Z awg-router.tar.gz* --clobber`.
  Downloads: `gh api repos/r-slashslash/AWG-Router/releases --jq '.[]|[.tag_name,(.assets[]|select(.name=="awg-router.tar.gz").download_count)]'`.
- No requests to third-party hosts from the browser: fonts and scripts are served by the panel
  (`app/static/fonts`, OFL). Google and CDNs are blocked in CN/IR and leak who opens the panel.

## Layout
| Path | What |
|---|---|
| `app/main.py` | API endpoints, auth (signed cookie, 4 h session, 8 fails → 10 min block, optional TOTP step: `need_code`; a password changed in the panel lives as PBKDF2 in `data/panel_password.json` and wins over `.env`), backup/restore, startup, `data/status.json` |
| `app/totp.py` | Optional 2FA (RFC 6238): secret in `data/totp.json` (re-read by mtime; `awg-router 2fa-off` deletes it), replay-protected codes; enabling/disabling changes the session tag → other sessions end |
| `app/traffic.py` | Per-client traffic totals and months (`data/traffic.json`, `{"_v": 2, "clients": …, "outs": …, "acct": …}`), deltas between polls survive counter resets; the first sight of a peer is only a baseline. `outs` — totals per exit (`direct` or upstream id, used by exit quotas); `by_out` in a client — month split by exit; `acct` — last values of the nft counters |
| `app/limits.py` | Client end date / traffic quota (`state.limits`): auto-off (`auto_off`: `exp` / `quota:<month>`), monthly auto-on; called after each poll |
| `app/updates.py` / `app/version.py` | Panel version and the update check (`HEAD /releases/latest` → redirect to `/releases/tag/vX.Y.Z`; `AWGR_BRANCH` ≠ main → `version.py` of that branch) |
| `app/cps.py` | Signature packets I1–I5: strict tag check (`b r rc rd t` only — `<c>` is kernel-only, `<d>/<ds>/<dz>` go-only), byte size (≤ 1400), RFC-based presets (STUN, QUIC Initial 1200 B, DNS+EDNS 128 B, SIP, AmneziaVPN default, none) with random fields; per-client override in `state.cps[pk]` = `{preset}` or `{preset: custom, values}`, applied in `users.client_config` (conf and vpn://) |
| `app/selfupdate.py` | Update from the panel: `install.sh --update` on the host via `nsenter -t 1` + `systemd-run --unit awg-router-update` (outside the panel container's cgroup, survives its recreation); output in `data/update.log` ending with `exit=N`, state in `data/update.json`; host install dir from the Compose label `com.docker.compose.project.working_dir` (or the `/data` mount source) |
| `app/static/share.html`, `share.js` | Public personal page of a client: `/s/<token>` + `/s/api/<token>` + `/s/assets/<whitelisted file>` — **outside the secret path, no login** (token in `state.shares`; unknown tokens → 404) |
| `app/notify.py` | Optional Telegram notifications (`settings.telegram`, token never sent to the browser): engine events, sign-ins, TLS renewal failure; queue + 5-min dedupe. Server-side texts (`TEXTS`, 4 languages) live here and in `tgbot.py` only, because those messages go to Telegram, not the browser |
| `app/tgbot.py` | Control from Telegram (`settings.telegram.control`): getUpdates long polling on the same path as notifications (direct / through an exit), commands and inline buttons, buttons under notifications (`notify_buttons`, engine events carry `pk` / `uid`). Obeys only `chat_id`; offset saved in `data/tgbot.json` **before** handling (a restart never repeats a command); messages older than 10 min are skipped. Calls panel actions through `main.bot_ops` (same functions as the API: `apply_limits`, `set_client_enabled`, `ensure_share`, `trace_target`, `set_default_outbound`, `delete_user`); the only destructive action is deleting a client, always behind a Yes/Cancel step (`dl:` → `dlgo:`). Actions go to the event log as `tg.act_*` |
| `app/qr.py` | QR code → PNG in pure Python (byte mode, ECC M then L, like `static/qrcode.js`): config QR for Telegram. Verified module-for-module against `qrcode.js` for versions 1–40 |
| `app/tgreq.py` | Telegram request through an exit: run as `nsenter -t PID -n -- python3 tgreq.py <fwmark>` (like `probe.py`); request on stdin, JSON answer on stdout; A record looked up through the tunnel (UDP DNS to 1.1.1.1 / 8.8.8.8) because local DNS spoofs blocked names |
| `app/web.py` | HTTP server: routing, JSON, static (ETag/304), TLS + plain-HTTP→HTTPS redirect, 4 MB body limit, strict `Content-Length`, body draining, ≤ 128 connections (≤ 24 per IP), 60 s idle timeout |
| `app/engine.py` | Reconcile loop: discover target, start exit tunnels `awgrN`, build/apply nftables, ip rules, health |
| `app/nftgen.py` | nftables ruleset generator (table `ip awgr`, chains `c_prerouting`/`c_forward`/`c_postrouting`); `acct_ruleset` — separate counting table `ip awgr_acct` (dynamic sets `up`/`down` keyed `client ip . ifname`, forward hook at priority filter+10) |
| `app/system.py` | Targets: `ContainerTarget` (nsenter into Amnezia container), `HostTarget` (pid 1), `DemoTarget`; docker API via socket; host runtime install |
| `app/users.py` | `ServerManager`: clients CRUD, client configs/vpn:// links, server params, host init |
| `app/awgserver.py` | Server conf model (Amnezia layout), parameter generation/validation, client conf, vpn:// encoder |
| `app/awgconf.py` | Parsing exit configs (`.conf`, JSON, `vpn://`) |
| `app/lists.py` | Country / ASN / URL / manual network lists (ipverse → ipdeny / RIPEstat fallback); kind `domains` → `domains.py` |
| `app/domains.py` | Domain lists: parsing (plain, `*.`, dnsmasq `server=/…/`, hosts, Adblock `\|\|x^`, v2ray `domain:`/`full:`, Clash `DOMAIN-SUFFIX,`), IDN → punycode, subdomains of listed domains dropped (`compact`); file `data/lists/<id>.domains`; suffix match |
| `app/sniproxy.py` | Domain rules for SOCKS5 exits, **stdlib only, no panel imports**: transparent TCP 80/443 proxy in the AWG server's network (`SO_ORIGINAL_DST`), SNI / Host → SOCKS5 CONNECT by name, otherwise the original address with the client's policy mark; SIGHUP → reload; stats in `/run/awgr/sni-stats.json` |
| `app/socks.py` | SOCKS5 exits: `hev_config` (YAML for hev-socks5-tunnel), health `check()` (login + CONNECT 1.1.1.1:443 / 8.8.8.8:443 from the panel, every 60 s in a thread) |
| `app/tlsmgr.py` | Let's Encrypt via `lego` (profile `shortlived`, 6-day IP certs, renew ~3 days), self-signed fallback, hot reload |
| `app/store.py` | `data/state.json` (routing, upstreams, lists, client policies, private keys, settings) |
| `app/hostnet.py` | Host addresses without outside requests (panel runs in the host network): public IPv6 from `/proc/net/if_inet6`, IPv6 UDP listener on the AWG port from `/proc/net/udp6` |
| `app/initserver.py` | CLI: create an Amnezia-layout server config (used by installer for a new container) |
| `app/uninstall.py` | Removes nft table / ip rules from the target (used by `awg-router uninstall`) |
| `app/static/` | SPA: `index.html`, `app.js` (tabs: overview, clients, exits, routing — rules + lists + route check since 1.12.1, `#lists` maps to it — server, system), `app.css`, `i18n.js`, `qrcode.js` (MIT, Kazuhiko Arase) |
| `awg-server/` | Dockerfile + start.sh for an Amnezia-compatible `amnezia-awg2` container the installer can create |
| `Dockerfile` | Builds amneziawg-go + static awg/awg-quick (Go), static hev-socks5-tunnel (`HEV_REF`, MIT), copies lego; Python 3.13 alpine runtime |
| `install.sh` | Installer/updater; works via `curl … | bash` (bootstraps code into `/opt/awg-router` from the latest release archive) |
| `.github/workflows/release.yml` | On a `vX.Y.Z` tag: release with `awg-router.tar.gz` (the archive the installer downloads) |
| `tests/` | `test_core.py`, `test_api.py` (unittest; `test_api` imports `main` in demo mode), `netns_e2e.py` (routing in netns, needs root + pyroute2), `awg_real_e2e.py` (real AWG tunnels), `domains_socks_e2e.py` (SOCKS5 exit + domain rules with real nft, sniproxy.py, hev-socks5-tunnel; helper servers in `e2e_servers.py`) |

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
- Client configs use `settings.client_host` (an IP picked on the Server tab, empty = `public_host`), never
  `public_host` directly: `public_host` is also the panel URL and the Let's Encrypt name, and the panel
  listens on IPv4 only. Restore keeps this server's `client_host`, as it does `public_host`. The tunnel
  itself is IPv4 only (clients get `::/0` → IPv6 goes into the tunnel and is dropped, no leak).
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
- Backup download (1.11.0): an optional password → `POST /api/backup/encrypted` (8–128 chars, same `notify.encrypt`
  as Telegram backups) → `<name>.json.enc`; **Restore from file** detects `Salted__` and asks for the password.
- Install on a phone (1.11.0): System → Access → `#app-phone` → `installApp()`: on a computer a QR of `panel.url`
  plus Android/iOS steps, on a phone the Chrome install prompt (`beforeinstallprompt`) when available, else steps.
- Web app manifest: `static/manifest.webmanifest` with `start_url`/`scope` `../` (relative to the
  manifest, so it stays under the secret path); `web.py` registers the `.webmanifest` MIME type.
  No service worker on purpose: nothing to cache, no extra code with the panel's cookies.
- I1–I5 are client-side: the server drops them, so a per-client override needs no server change —
  only a new client config. A preset is stored by name, so fixing a preset reaches clients with
  their next config. Per-client data lives in `state.cps` (not `state.clients`, which `put_client`
  rebuilds); deleting a client drops it.
- Telegram path (`settings.telegram.via`: `direct` | `up:<id>`, never `block`): `notify.router` (set in
  `main.py`) → `engine.own_route` → `None` (urllib from the panel) or `(pid, fwmark)` → `tgreq.py`
  in the AWG server's network. Follows `resolve()` (dead exit → its fallback); the exit counts as a
  reference (`ref.telegram`). `NotifyError.msg` carries a `Msg` for errors of our own, so
  `notify_error` / `backup_error` may be `{"$t": …}` — render them with `tm()`.
- Exit window routing (1.12.0): `POST`/`PUT /api/upstreams` take optional `routing` =
  `{domains, domain_lists, net_lists, default}` → `main.apply_exit_routing`: the sites text is the exit's own
  domain list (`u["own_list"]`, named like the exit, renamed with it, dropped when emptied or with the exit if
  unreferenced); all global rules with outbound `up:<id>` are replaced by ≤ 2 rules (domains, networks) at the
  position of the first old one (else top), then `v_rules`. The browser sends `routing` only when that part of
  the form was touched (or for a new SOCKS5 exit with something chosen). Exit type can't change on edit.
  Deleting an exit drops rules with domain lists whose replacement isn't SOCKS5.
- Deleting an exit: `DELETE /api/upstreams/<id>` with `{"replace": out}` runs
  `Store.replace_outbound(st, target, new, spare=its fallback)` over every place `outbound_refs`
  knows (plus client rules in "inherit" mode); without `replace` an exit in use is refused as
  before. A new place that can point to an exit must be added to **both** functions.
- Telegram bot (1.9.0): callback data ≤ 64 bytes (`off:<pk>` is 48). Menu, list and card messages the bot
  sent itself are edited in place (`_panel_msgs`); a button under a notification opens a new message.
  A pending question (`/add` or `/route` without an argument) waits 15 min for a reply; the question is deleted after it. An update started
  from the bot is remembered in `tgbot.json` and announced (done / failed) by the new panel.
  **One control message (1.12.0):** `/start` → `show_menu` = inline buttons (status|clients, exits|add,
  panel|backup; Panel is a URL button to `panel_url()`, or the `pn` screen if Telegram refuses the URL / SSH
  mode). Every screen is edited into that message (`_show`) and has **‹ Menu** (`m`); the card also ‹ Clients.
  `_send(panel=True)` deletes older menu messages, so there is one; their ids live in `tgbot.json["panel"]`
  (survive restarts). After files (QR/config, backup) the menu is re-sent below (`_move` / `show_*(msg=None)`).
  Share link and exit probe go into the screen text (`note`). The old reply keyboard (1.10–1.11, `_st["kbd"]`)
  is removed on the next command by sending a `remove_keyboard` message and deleting it; its button texts are
  still understood (`menu_action`, `MENU` + `OLD_MENU`). `/route` stays as a command. Link previews stay off
  (`notify.send`), or Telegram itself would open the secret path;
  `_drop_commands` removes the keyboard when control is turned off. A command from another chat is not run;
  in a private chat the bot answers "No access" with that chat's id (once per 10 min per chat). A webhook on
  the token (409 on getUpdates) is removed once by `_drop_webhook`.
  Control does **not** depend on `enabled` (notifications): the loop needs `token`, `chat_id` and `control`
  only, and the panel shows `tg_bot` whenever `control` is on (before 1.10.5, with notifications off
  the bot was silently off).
- Bot message age (1.10.5) is measured by Telegram's clock: `notify.note_date` reads the `Date` header of
  every Telegram answer (direct, and `tgreq.py` returns it as `date`) into `notify.clock_skew`. Never compare
  Telegram `date` fields with the server clock directly — VPS clocks drift, and the bot then ignored every
  command.
- First connection (1.10.0): `users.add_client` puts the client into `state.await_first` (pk → created);
  `limits.first_seen` (after each poll) fires `ev.client_first` on its first handshake and drops entries
  for deleted clients or after 90 days. Restore does not carry `await_first` (built from `DEFAULT_STATE`).
- Domain rules (1.12.0) — **only to SOCKS5 exits** (`v_rules`: `err.domains_need_socks`, no mixing with address
  lists: `err.rule_mixed_domains`). No DNS changes: `sniproxy.py` (stdlib only, no panel imports; run as
  `nsenter -t PID -n -- python3 sniproxy.py /run/awgr/sni.json`, 0600 — proxy passwords) listens on the server's
  tunnel address `:10443`. Policies are split by `engine._policies`: address rules → nft as before, rules with
  domain lists → `policy["domain"]`. `nftgen.layout()` (shared by nft and the sniproxy config, names must match)
  dedups policies including domain rules; `sniff_marks()` gives each policy with domain rules a mark
  `SNIFF_OUT_BASE + i`. In such a policy chain, first: `udp dport 443 goto o_block` (QUIC — no readable name) and
  `tcp dport {80,443} meta mark set SNIFF_MARK accept`; `c_sniff` (nat prerouting) redirects that mark (needs
  `meta l4proto tcp`). sniproxy reads SNI (ClientHello, may span TLS records) or HTTP Host (waits ≤ 3 s for client
  data), matches the client's policy domain rules: hit → SOCKS5 CONNECT **by name** (or the exit's fallback:
  `{"mark"}` / `{"block"}` from `engine._sni_target`); miss → connect to SO_ORIGINAL_DST with the policy's mark,
  and `c_output` (`type route hook output`) jumps to `q_<policy>` = the same address rules with `oq_*` outs
  (mark change → re-route). No sniproxy (not started, died, hung — stats older than 120 s) → ruleset without
  sniffing (address rules only); panel stop with `on_stop=keep` re-applies the ruleset without it. Redirected
  connections are *input* traffic: `_input_rule` inserts `iptables -I INPUT -i <wg> -p tcp --dport 10443 -j ACCEPT`
  (ufw); an nftables-only host firewall must allow it by hand. `trace(pk, ip, name)` checks domain rules first.
- SOCKS5 exits (1.12.0): upstream `config` = normalized `socks5://user:pass@host:port` (`awgconf.parse_socks`,
  `UpstreamConf.kind == "socks5"`, `socks` dict; password only via `GET /api/upstreams/<id>/config`). Started as
  `nsenter -t PID -n -- hev-socks5-tunnel /run/awgr/awgrN.yml` (TUN `awgrN`, ipv4 169.254.200.N, mtu 8500,
  `udp: 'udp'`), YAML deleted once the link exists; proxy host resolved by the panel (hev needs an IP). No SNAT
  for it (`snat` empty). hev's own sockets are unmarked → main table → no loop. **hev opens AF_INET6 sockets**
  (v4-mapped): needs kernel IPv6 (fine with `disable_ipv6=1`, fails with `ipv6.disable=1` → `sys.socks_no_ipv6`).
  The e2e test in a kernel without IPv6 needs an LD_PRELOAD shim mapping those sockets to AF_INET. Health:
  `_socks_health` (hev alive + check ≤ 200 s old and ok); TUN rx = from proxy (download), tx = to proxy.
- Very old installs may have an `awg-router` helper whose `update` doesn't pass `--update` (it rebuilds
  old code). Fix: re-run the installer via `curl … | bash`, which rewrites the helper.

## Testing
```bash
python3 -m unittest discover tests
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
sudo PATH=<hev-socks5-tunnel>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
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
