# AWG Router — notes for development

Web panel for AmneziaWG (up to AWG 3.1): clients, all tunnel settings and cascade routing (clients exit
through other AWG servers or SOCKS5 proxies, chosen networks go direct, a client can have its own rules).
Repo https://github.com/r-slashslash/AWG-Router, branch `main`, MIT.

These notes say what to do and why. How things work is in the code and its docstrings; numbers live in
constants (named here, not their values). Rules that can be checked are checked by `tests/test_rules.py` —
if it fails, a rule is broken.

## Rules
- **Python standard library only** (PyPI may be unreachable). Own HTTP framework in `app/web.py`.
- **Every user-facing string in 4 languages: ru, en, zh, fa** (fa is RTL). The server returns
  `Msg("key", **params)` → `{"$t": key, "p": params}`; the browser translates with `t()` / `th()` / `tm()`
  from `app/static/i18n.js`. `{placeholders}` identical in every language; mixed-direction text in `<bdi>`
  (`t()` isolates its params itself). Telegram texts live in `notify.TEXTS` and `tgbot.py`, not in
  `i18n.js`. *Test:* `I18nTest`.
- Code comments and docstrings in Russian. README in en / ru / zh / fa change together. `install.sh` speaks
  English only.
- A commit message ends with `Co-Authored-By: Claude …` and nothing else (a session link leads to a private
  chat and is useless in a public repo).
- Every user-visible change gets a new `VERSION` in `app/version.py` and a `CHANGELOG.md` section. A fix
  after a release is a new version; a number is never reused.
- The browser never calls third-party hosts: fonts and scripts are served by the panel
  (`app/static/fonts`, OFL). Google and CDNs are blocked in CN/IR and reveal who opens the panel.

## Release
1. Bump `VERSION`, write the `CHANGELOG.md` section (`## X.Y.Z — date`, English) and the release text
   `release-notes/vX.Y.Z.md` in en / ru / zh / fa (same layout as the previous file: English on top, then
   `<details>` for ru, zh, fa with `<a id="…">`, update instructions in each). Push `main`.
2. `.github/workflows/release.yml` runs the tests, builds `awg-router.tar.gz` + `.sha256` and creates a
   **draft** release `vX.Y.Z` with that text. Later commits with the same version refresh the draft. A
   version not newer than the latest release, or a missing notes file, fails the workflow.
3. The owner opens Releases and presses **Publish**. The tag is created on publishing; nobody types it.
   Claude Code cloud sessions can't publish.
4. Check: `gh api repos/r-slashslash/AWG-Router/releases/latest --jq '.assets[].name'`.

Users get code only from releases: `install.sh` (also `awg-router update` and the panel's button) downloads
`releases/latest/download/awg-router.tar.gz` and checks its `.sha256`; the `main` tarball is used only when
there is no release (HTTP 404). Panels compare `VERSION` with the latest release every `updates.INTERVAL`.
Downloads (≈ installs + updates):
`gh api repos/r-slashslash/AWG-Router/releases --jq '.[]|[.tag_name,(.assets[]|select(.name=="awg-router.tar.gz").download_count)]'`

## Checklists
**A new field in `state.json`**
- default value in `store.DEFAULT_STATE` (or read with `.get` and a default);
- input validation in the API handler in `main.py`;
- carried over by restore in `clean_backup_state` (unknown fields are dropped!). *Test:*
  `RestoreKeepsFieldsTest`; a field that must not be carried over goes into its `DROPPED` with a reason;
- what the browser sees in `get_state`; `/api/state` is polled every few seconds, keep it small (big data
  through a separate request, like a list's text via `GET /api/lists/<id>`).

**A new place that can point to an exit** (`up:<id>`)
- in both `Store.outbound_refs` and `Store.replace_outbound`; *test:* `ExitReferencesTest` (add the new
  place there and update the expected number of references).

**A new UI text or server error**
- the key in all 4 dictionaries of `i18n.js` with the same placeholders; *test:* `I18nTest`.

**A new file for a client's personal page** (`/s/…`, no login)
- in the `app.public_files` whitelist in `main.py`; *test:* `FormatsTest`.

**A routing (nft) change**
- `nftgen.layout()` is shared by nftables and the `sniproxy.py` config — policy names must match;
- never rebuild the counting table `awgr_acct` together with `awgr` (counters would reset): bump
  `nftgen.ACCT_VER` when it changes;
- check the ruleset with `nft -c -f` and the netns e2e tests (see Tests).

**A `traffic.json` format change**
- `traffic.FORMAT` stays 2: older panels read only that and ignore new keys, so a downgrade keeps the
  totals. *Test:* `FormatsTest`.

## How it works
- Panel container: `network_mode: host`, `pid: host`, `privileged`, docker.sock, data in `./data`. The AWG
  server is a `system.Target`: the AmneziaVPN container (`ContainerTarget`, nsenter into its network), a
  server on the host (`HostTarget`) or demo (`DemoTarget`).
- Container: AmneziaVPN layout in `/opt/amnezia/awg/` — `awg0.conf` (I1–I5 as `# I1 = …` comments,
  `" = "` separators), shared PSK `wireguard_psk.key`, `clientsTable` with names. Peers via `awg syncconf`;
  port, S1–S4, H1–H4, HeaderProtectionKey only with an interface restart. Host:
  `/etc/amnezia/amneziawg/awg0.conf`, `awg-quick@awg0`, NAT in PostUp.
- A disabled client is a commented peer block marked `#awgr:disabled` (its IP stays taken).
- Routing: prerouting sets mark `MARK_BASE + N` → `ip rule` `RULE_PRIO_BASE + N` → table `TABLE_BASE + N` →
  `default dev awgrN`, with an `unreachable` fallback route (no tunnel, no leak); SNAT to the exit's tunnel
  address; MSS clamp; `rp_filter=2` (constants in `config.py`).
- An exit: working → its number; down → `fallback`; over its monthly quota → `quota_action`
  (`engine.resolve`). A failed exit start waits `engine.UP_PAUSES`.
- Domain rules go only to SOCKS5 exits. nftables redirects TCP 80/443 of such clients to `sniproxy.py`
  (port `config.SNI_PROXY_PORT`) and blocks QUIC. sniproxy reads the site name (SNI / Host): a match → CONNECT
  to the proxy by name, otherwise → the original address with the policy mark. Its connections are not
  forwarded: traffic counting, MSS clamp and the input firewall rule are handled separately for them.
- Client configs get `client_host`, never `public_host` (that is also the panel URL and the certificate
  name). The tunnel is IPv4 only: clients get `::/0`, IPv6 is dropped inside the tunnel, no leak.
- `Target.key` includes the container PID and start time: a container restart re-applies everything.

## Gotchas
- nft chain names `fwd` / `post` / `pre` are reserved → `c_*`.
- Browsers refuse some ports (ERR_UNSAFE_PORT) — the installer's `UNSAFE_PORTS`.
- Unread request bodies must be drained on keep-alive: `_drain_body` in `web.py`.
- Re-enabling a peer on real AWG may take up to ~15 s (WireGuard timers).
- `install.sh` reads answers from `/dev/tty` (works under `curl | bash`); without a terminal it takes the
  defaults. It never deletes an existing `amnezia-awg2` container, it renames it. The image is built with
  `docker build`, not `docker compose build` (new Compose refuses old buildx).
- The UI re-renders on a timer: don't re-render while the user types in `#main`.
- Everything outside the secret path is visible to scanners: minimal public routes, `Server: httpd`.
- Restore validates every field like panel input and replaces PostUp/PostDown hooks (`safe_hooks`):
  awg-quick runs them as root.
- Measure the bot's message age by Telegram's clock (`notify.clock_skew`): VPS clocks drift.
- hev-socks5-tunnel opens AF_INET6 sockets: the kernel needs IPv6 support (fails with `ipv6.disable=1`).
- I1–I5 are client-side: a client's own masking changes only its config. Client data lives in
  `state.cps`, not `state.clients` (rebuilt by `put_client`).

## Decided, not bugs
- Telegram control trusts the chat, not the person: in a group every member controls the panel (README,
  Security).
- A backup holds all private keys; without a password it is not encrypted (README, Security).
- QUIC is blocked for all sites of clients with domain rules; ECH sites can't be matched by name (UI hint).
- Months for quotas and totals are UTC.

## Tests
```bash
python3 -m unittest discover tests            # all without root; tests/test_rules.py — the rules above
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
sudo PATH=<hev-socks5-tunnel>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo PANEL_PORT=8099 PUBLIC_HOST=203.0.113.5 python3 -m app.main
```
Demo mode fakes the AWG server: check the UI with Playwright in 4 languages, desktop and 375 px wide (no
horizontal scroll, RTL for fa). README screenshots (`docs/screenshots`) come from demo mode: English, light
theme, 1280×860 at scale 1.25 and phone 390×844 at scale 3, demo banner and "(demo)" hidden, 256 colours.

## Status
Verified on a real server (Ubuntu 22.04, AmneziaVPN container): image build, Let's Encrypt through the
installer, the panel, update from GitHub. SOCKS5 exits and domain rules are covered by e2e tests in network
namespaces, not yet on a real server.
