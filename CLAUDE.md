# AWG Router — notes for development

Web panel for AmneziaWG (up to AWG 3.1): clients, all tunnel settings and cascade routing (clients
exit through other AWG servers or SOCKS5 proxies; chosen networks go direct; per-client overrides).
Public repo https://github.com/r-slashslash/AWG-Router, branch `main`, MIT.

## Rules
- **Python standard library only** (PyPI may be unreachable). Own HTTP framework in `app/web.py`.
- **Every user-facing string in 4 languages: ru, en, zh, fa** (fa is RTL). The server returns
  `Msg("key", **params)` → JSON `{"$t": key, "p": params}`; the browser translates with `t()` / `th()` /
  `tm()` from `app/static/i18n.js`. Add each key to all four dictionaries, keep `{placeholders}` identical,
  wrap mixed-direction text in `<bdi>` (`t()` already isolates its params). Texts sent to Telegram live in
  `notify.TEXTS` / `tgbot.py`, not in `i18n.js`.
- Code comments and docstrings in Russian. README in en / ru / zh / fa — change all four together.
  `install.sh` speaks English only.
- Commit messages end with `Co-Authored-By: Claude …` only — no session links (they lead to a private chat).
- Every user-visible change bumps `VERSION` in `app/version.py` and gets a `CHANGELOG.md` section.
  A fix after a release is a new version, never the same number again.
- The browser never calls third-party hosts: fonts and scripts are served by the panel (`app/static/fonts`,
  OFL). Google and CDNs are blocked in CN/IR and reveal who opens the panel.

## Release
1. Bump `VERSION`, add the CHANGELOG section, push `main`.
2. The owner publishes the release in the GitHub UI (cloud sessions can't push tags or create releases):
   Releases → Draft a new release → new tag `v` + VERSION (`v1.12.2`) on `main` → Publish. Never move or
   reuse a tag.
3. `.github/workflows/release.yml` builds `awg-router.tar.gz` (`git archive --prefix=awg-router/`) and its
   `.sha256` and attaches them. It fails when the tag ≠ `VERSION`.
4. Check: `gh api repos/r-slashslash/AWG-Router/releases/latest --jq '.assets[].name'`. If Actions didn't run,
   build the same archive locally and `gh release upload vX.Y.Z awg-router.tar.gz* --clobber`.

Users get code only from releases: `install.sh` (also `awg-router update` and the panel's update button)
downloads `releases/latest/download/awg-router.tar.gz` and checks its `.sha256`; the `main` tarball is used
only on HTTP 404. A network error or a bad checksum stops the install. Panels compare `VERSION` with the
latest release tag every 6 h. Downloads (≈ installs + updates):
`gh api repos/r-slashslash/AWG-Router/releases --jq '.[]|[.tag_name,(.assets[]|select(.name=="awg-router.tar.gz").download_count)]'`

## Layout
| Path | What |
|---|---|
| `app/main.py` | API, sign-in (signed cookie, 4 h; 8 fails → 10 min block per IP; optional TOTP step `need_code`; a password set in the panel is PBKDF2 in `data/panel_password.json` and wins over `.env`), backup/restore, startup, `data/status.json` |
| `app/web.py` | HTTP server: routes, JSON, static (ETag), TLS + HTTP→HTTPS redirect, 4 MB body, strict `Content-Length`, ≤ 128 connections (≤ 24 per IP), 60 s idle timeout |
| `app/engine.py` | Reconcile loop (every 10 s and on change): find the AWG server, start exits `awgrN`, apply nftables and ip rules, exit health, sniproxy |
| `app/nftgen.py` | nftables generator: table `ip awgr`; counting table `ip awgr_acct` |
| `app/system.py` | Targets: `ContainerTarget` (nsenter into the Amnezia container), `HostTarget` (pid 1), `DemoTarget`; Docker API via socket |
| `app/users.py` | `ServerManager`: clients, client configs and vpn:// links, server settings, host init |
| `app/awgserver.py` | Server conf model (Amnezia layout), parameter generation/validation, client conf, vpn:// encoder, NAT hooks |
| `app/awgconf.py` | Exit configs: `.conf`, JSON, `vpn://`, `socks5://` |
| `app/store.py` | `data/state.json`: routing, exits, lists, client policies, client private keys, settings |
| `app/traffic.py` | `data/traffic.json` `{"_v": 2, "clients", "outs", "acct", "sni"}`: client totals and months, totals per exit, last nft and sniproxy counters |
| `app/limits.py` | Client end date and traffic quota: auto-off / monthly auto-on, early warnings, first connection event |
| `app/lists.py` / `app/domains.py` | Network lists (country, ASN, URL, manual; ipverse → ipdeny / RIPEstat) / domain lists (many formats, IDN → punycode, suffix match) |
| `app/sniproxy.py` | Domain rules: transparent TCP 80/443 proxy in the AWG server's network. **Stdlib only, no panel imports** |
| `app/socks.py` | SOCKS5 exits: hev-socks5-tunnel config, proxy health check |
| `app/cps.py` | Signature packets I1–I5: tag check, sizes, presets, per-client override |
| `app/notify.py` / `app/tgbot.py` / `app/tgreq.py` | Telegram notifications / bot control / a request through an exit's tunnel |
| `app/tlsmgr.py` | Let's Encrypt via `lego` (`shortlived` profile, 6-day IP certificates), self-signed fallback |
| `app/totp.py`, `app/qr.py`, `app/hostnet.py`, `app/updates.py`, `app/selfupdate.py` | 2FA; QR → PNG; host addresses from `/proc`; update check; update from the panel (`install.sh --update` on the host via `nsenter -t 1` + `systemd-run`) |
| `app/initserver.py`, `app/uninstall.py` | CLI for the installer: new server config / remove our nft table and ip rules |
| `app/static/` | SPA (`app.js`: overview, clients, exits, routing, server, system), `i18n.js`, `share.html` / `share.js` (client's public page `/s/<token>`, no login) |
| `awg-server/` | Amnezia-compatible `amnezia-awg2` container the installer can create |
| `install.sh`, `Dockerfile`, `.github/workflows/release.yml` | Installer/updater; image (amneziawg-go, awg tools, hev-socks5-tunnel, lego, Python 3.13 alpine); release archive |

## How it works
- Panel container: `network_mode: host`, `pid: host`, `privileged`, docker.sock mounted, data in `./data`.
- Container mode: AmneziaVPN layout in `/opt/amnezia/awg/`: `awg0.conf` (I1–I5 as `# I1 = …` comments,
  `" = "` separators), `wireguard_psk.key` (one PSK for all clients), `wireguard_server_public_key.key`,
  `clientsTable` (names). Peers applied with `awg syncconf`; port, S1–S4, H1–H4, HeaderProtectionKey need
  an interface restart. Host mode: `/etc/amnezia/amneziawg/awg0.conf`, `awg-quick@awg0`, NAT in PostUp.
- A disabled client is a commented peer block marked `#awgr:disabled` (keeps its IP).
- Routing: prerouting marks packets → fwmark `0x2000+N` → `ip rule` priority `20000+N` → table `2000+N` →
  `default dev awgrN`, plus an `unreachable` fallback route; SNAT to the exit's tunnel address; link-local
  `169.254.200.N` on `awgrN`; MSS clamp; `rp_filter=2`.
- `Target.key` includes the container PID and start time → a container restart re-applies everything.

## Features in detail
- **Exits.** `resolve()`: a dead exit → its `fallback`; a healthy exit over its monthly quota → its
  `quota_action` (`notify` | `direct` | `block` | `up:<id>`, never itself); depth limit → `block`. Every place
  that can point to an exit must be in **both** `Store.outbound_refs` and `Store.replace_outbound`
  (`DELETE /api/upstreams/<id>` with `{"replace": out}` uses them). An exit's type and a list's kind can't
  change on edit. A failed start waits `UP_PAUSES` (10 s … 5 min) with one event per new error; reset on a
  config or target change and by `POST /api/reapply`.
- **Exit window routing** (`routing` in `POST`/`PUT /api/upstreams` → `apply_exit_routing`): the sites text
  is the exit's own domain list `u["own_list"]` (named like the exit, kept by restore). `merge_exit_rules`
  changes only enabled global rules to that exit; disabled rules, comments and order stay.
- **Domain rules** — only to SOCKS5 exits, never mixed with address lists in one rule. Clients with such
  rules: TCP 80/443 is redirected to `sniproxy.py` on the server's tunnel address `:10443`, UDP 443 (QUIC) is
  blocked. sniproxy reads SNI / Host: a match → SOCKS5 CONNECT by name; no match → the original address with
  the policy mark, re-routed by `c_output` → `q_<policy>`. `nftgen.layout()` is shared by nft and the
  sniproxy config (names must match). No sniproxy (not started, dead, stats older than 120 s) → address
  rules only. Its connections are input/output, not forward: it counts its own bytes per `client|exit`
  (`sni-stats.json`, read by `engine._sni_account`), gets its own MSS clamp (`c_mss_out`), TCP keepalive and
  a 15 min idle timeout. `_input_rule` opens port 10443 in iptables/ufw; an nftables-only host firewall
  needs it by hand.
- **SOCKS5 exits**: `socks5://user:pass@host:port`, run as `hev-socks5-tunnel` in the server's network
  (TUN `awgrN`, no SNAT); the panel resolves the proxy host. hev needs kernel IPv6 (fails with
  `ipv6.disable=1`). Health = hev alive + proxy check (login + CONNECT) not older than 200 s.
- **Traffic.** Client totals from peer counters (first sight = baseline only; deltas survive resets).
  Per-exit split from `awgr_acct` + sniproxy. Months are UTC.
- **Telegram.** Notifications queue with a 5 min dedupe. Path `settings.telegram.via` = `direct` | `up:<id>`
  (through the exit's tunnel via `tgreq.py`). The bot obeys only `chat_id`, saves the offset before handling,
  skips messages older than 10 min measured by Telegram's clock (`notify.clock_skew`: VPS clocks drift), runs
  in one edited menu message. Its only destructive action, deleting a client, needs a Yes/Cancel step. Bot
  control doesn't depend on notifications being on. Callback data ≤ 64 bytes.
- **Backups**: one JSON (`make_backup`); optional password → `openssl enc -aes-256-cbc -pbkdf2 -iter 200000`;
  scheduled sends to Telegram. Restore re-validates every field like panel input and replaces PostUp/PostDown
  hooks (`safe_hooks`); it keeps this server's `public_host` and `client_host`.

## Gotchas
- nft chain names `fwd` / `post` / `pre` are reserved → use `c_*`.
- Browsers refuse some ports (ERR_UNSAFE_PORT: 6697, 6665–6669, 5060, 2049, 4045…) — installer's
  `UNSAFE_PORTS`.
- Unread request bodies must be drained on keep-alive (`_drain_body`).
- Re-enabling a peer on real AWG may take ~15 s (WireGuard timers).
- `install.sh` reads answers from `/dev/tty` (works under `curl | bash`); without a TTY it takes defaults. It
  never deletes an existing `amnezia-awg2` container, it renames it `…-old-<date>`. Images are built with
  `docker build`, not `docker compose build` (Compose 2.40.2+ refuses buildx < 0.17).
- The UI refreshes every 5 s: skip re-rendering while the user types in `#main`. Keep `/api/state` small
  (manual list text is fetched separately via `GET /api/lists/<id>`).
- Everything outside the secret path is visible to scanners: minimal public routes, `Server: httpd`,
  `/s/assets/` files are a whitelist (`app.public_files`).
- Client configs use `client_host`, never `public_host` (that is also the panel URL and the certificate name).
  The tunnel is IPv4 only; clients get `::/0`, so IPv6 is dropped inside the tunnel, no leak.
- Never rebuild `awgr_acct` together with `awgr` (counters would reset): it is created only when missing or
  its marker (`nftgen.acct_marker`, bump `ACCT_VER`) changed. Counters live in the rule, not in the set
  (set-level expressions need kernel ≥ 5.11).
- Keep `traffic.json` at `_v: 2`: older panels ignore new keys, so a downgrade keeps client totals.
- Host mode: changing the subnet moves NAT in PostUp/PostDown (`retarget_nat`) and deletes the old
  MASQUERADE. The AmneziaVPN container has its subnet written into `start.sh` → the subnet is locked there.
- I1–I5 are client-side: a per-client override changes only the client config. Per-client data lives in
  `state.cps`, not `state.clients` (rebuilt by `put_client`).
- Very old installs may have an `awg-router` helper whose `update` lacks `--update`: re-run the installer
  via `curl … | bash`.

## Decided, not bugs
- Telegram control trusts the chat, not the person: in a group every member controls the panel (README,
  Security).
- Backups hold all private keys and are unencrypted unless a password is set (README, Security).
- QUIC is blocked for all sites of clients with domain rules; ECH sites can't be matched by name (UI hint).

## Testing
```bash
python3 -m unittest discover tests
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
sudo PATH=<hev-socks5-tunnel>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo PANEL_PORT=8099 PUBLIC_HOST=203.0.113.5 python3 -m app.main
```
Demo mode fakes the AWG server; check the UI with Playwright in all four languages, desktop and 375 px
(no horizontal scroll, RTL for fa). README screenshots (`docs/screenshots`) come from demo mode: English,
light theme, 1280×860 at scale 1.25 and phone 390×844 at scale 3, demo banner and "(demo)" hidden,
256 colours.

## Status
Verified on a real server (Ubuntu 22.04, AmneziaVPN container): image build, Let's Encrypt through the
installer, the panel, update from GitHub. SOCKS5 exits and domain rules are covered by e2e tests in network
namespaces but not yet checked on a real server.
