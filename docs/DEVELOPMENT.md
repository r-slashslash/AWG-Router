# Development

The rules for changing AWG Router, the invariants that must not break, and how to check a change.
For a map of the parts start with [ARCHITECTURE.md](ARCHITECTURE.md). How something works in detail is
in the code and its docstrings (written in Russian); numbers live in constants, mostly in `app/config.py`.
Rules that can be checked are checked by `tests/test_rules.py`: if it fails, a rule below was broken.

## Rules

- **Standard library only.** No Python dependencies (PyPI may be unreachable where the panel runs). The HTTP
  layer is `app/web.py`.
- **Every text a user sees exists in four languages: ru, en, zh, fa** (fa is right to left). The server returns
  `Msg("key", **params)` → `{"$t": key, "p": params}`; the browser translates it with `t()` / `th()` / `tm()`
  from `app/static/i18n.js`. `{placeholders}` are the same in all languages; text that mixes directions goes into
  `<bdi>` (`t()` isolates its own parameters). Telegram texts live in `notify.TEXTS` and `tgbot.py`.
  *Test:* `I18nTest`.
- Comments and docstrings in `app/`, `tests/` and `tools/` (Python, JS, CSS) are in Russian. The four READMEs
  change together. `install.sh` talks only in English.
- **The browser never loads anything from a third-party host**: fonts and scripts are served by the panel
  (`app/static/fonts`, OFL). Google and CDNs are blocked in China and Iran and reveal who opens the panel.
  *Test:* `ProjectRulesTest`.
- Every action in a workflow is pinned by a 40-character SHA with a `# vN` comment (Dependabot updates them).
  *Test:* `ProjectRulesTest`.
- Every user-visible change gets a new `VERSION` in `app/version.py` and a section in `CHANGELOG.md` (English);
  release notes go to `release-notes/vX.Y.Z.md` in en / ru / zh / fa.

## Done means

- `python3 -m unittest discover tests` passes, as root **and** as an unprivileged user (CI runs it as a normal
  user): `runuser -u nobody -- python3 -m unittest discover tests` in a copy of the repository;
- `ruff check .` and `eslint app/static` pass (`ruff.toml`, `eslint.config.mjs`; CI job `lint`);
- a change in routing, tunnels, nftables or `tc` passes the network tests (`net-tests.yml`, below);
- a change in the interface is looked at in a browser: four languages, desktop and 375 px wide (no horizontal
  scrolling, right to left for fa), with the demo panel;
- new user texts exist in all four languages; README, `CHANGELOG.md` and release notes are updated when
  the change is visible to users.

## Checklists

**A new field in `state.json`**
- a default in `store.DEFAULT_STATE` (or reading with `.get` and a default);
- input checks in the API handler in `main.py` (a switch goes through `v_flag`, never `bool()`: the string
  `"no"` would turn it on);
- carried over by backup restore in `clean_backup_state` — unknown fields are dropped. *Test:*
  `RestoreKeepsFieldsTest`; a field that must not be carried over goes into its `DROPPED` with the reason;
- what the browser sees in `get_state`. `/api/state` is polled every few seconds: keep it small, load big data
  with a separate request (like a list's text through `GET /api/lists/<id>`).

**A new speed limit or a new interface with a `tc` queue**
- the plan in `shaping.plan` (commands only), applying in `Engine._sync_shaping`; our root qdiscs use the major
  number `shaping.HANDLE`, ifb devices are `shaping.IFB_PREFIX`N: foreign queues are never touched. *Tests:*
  `SyncShapingTest` (fake target), `tests/shaping_e2e.py` (real `tc`).

**A new place that can point to an exit** (`up:<id>`)
- both `Store.outbound_refs` and `Store.replace_outbound`; *test:* `ExitReferencesTest` (add the place there and
  update the expected number of references).

**A new interface text or server error**
- the key in all four dictionaries of `i18n.js` with the same placeholders; *test:* `I18nTest`;
- a validation error about one field of a form says which one: `bad(key, field=…)` or `with field("name"):`
  in `main.py`, and `data-field="name"` on the input — the browser outlines it (`markField`).

**A new file for the client's personal page** (`/s/…`, no login)
- in the allow list `app.public_files` in `main.py`; *test:* `FormatsTest`.

**A change in routing (nftables)**
- `nftgen.layout()` is shared by nftables and the `sniproxy.py` config — policy names must match (and `balance`
  is passed to it in both places: `build_ruleset` and `_sync_sni`);
- never rebuild the accounting table `awgr_acct` together with `awgr` (counters reset): bump `nftgen.ACCT_VER`
  when it changes;
- check the rule set with `nft -c -f` and with the network tests in namespaces.

**A new or updated action in a workflow**
- pinned by SHA with `# vN`.

**A change of the `traffic.json` format**
- `traffic.FORMAT` stays 2: older panels read only that and ignore new keys, so totals survive a rollback.
  *Test:* `FormatsTest`.

**A new HTTPS setting** (panel domain, own certificate, web server on port 80)
- goes to `data/tls.json` through `tlsconf.py`, not to `state.json`: it belongs to this server (DNS, files on
  its disk), so it is not part of backups and restore doesn't touch it.

## Invariants

### Server and target
- The AWG server is a `system.Target`: the AmneziaVPN container (`ContainerTarget`, `nsenter` into its
  network), a server on the host (`HostTarget`, `awg-quick@awg0`) or the demo (`DemoTarget`). `Target.key`
  includes the container's PID and start time: a restarted container is a new target and gets everything again.
- Peers change through `awg syncconf`; port, S1–S4, H1–H4 and HeaderProtectionKey only with an interface
  restart. If `awg syncconf` fails, the server's files are put back (`users._put_back`).
- A disabled client is a commented peer block marked `#awgr:disabled` (its address stays taken).
- Server files are written whole (`Target.write_file`: temporary file, `fsync`, `os.replace`), so a reader
  never sees half a file. That is why a client's config is given without the engine lock.
- `nsenter -n` changes only the network: anything that resolves names reads the panel's `resolv.conf`. Resolve
  names in the panel and pass addresses into the container's network (exit endpoints, `probe.py`, SOCKS5 proxy
  names — all with a time limit, `awgconf.resolve_host`).
- Client configs get `client_host`, never `public_host` (that is also the panel URL and the certificate name).
  Every value put into a client config must be a single line (`awgserver._one_line`): a line break would add
  `PostUp` lines that `awg-quick` runs as root on the client.

### Routing
- Mark `MARK_BASE + N` → `ip rule` `RULE_PRIO_BASE + N` → table `TABLE_BASE + N` → `default dev awgrN`, with a
  fallback `unreachable` route: no tunnel means no leak. Rules and routes are set by one `ip -batch`
  (`Engine._sync_rules`); routes again when the set of tunnels changes or every `ROUTES_EVERY`.
- An exit without a running tunnel becomes a block in `nftgen.layout()`. A balanced exit is `Sticky(N)`, which keeps
  a connection on its exit through the conntrack mark while it is among the live exits.
- A new target has an empty network: a pass puts the rules in before it starts any tunnel (`_hold_rules`). The
  order in `reconcile` (rules → tunnels → apply) doesn't change without the network tests. The panel hears about
  a container start from Docker's events (`Engine._docker_events`) instead of waiting for the next pass, and it
  keeps a "before the panel" rule set next to the server's config (`awgr-hold-<iface>.nft`, `Engine._save_hold`)
  that the panel's own container (`awg-server/start.sh`) and the host service (`ExecStartPre` in
  `system.UNIT_TEXT`, only when the panel's table isn't there) apply before the server comes up. With
  `on_stop = restore` there is no such file; uninstalling removes it.
- On the host the panel doesn't touch `all` / `default` `rp_filter`; the AWG interface and the exits' tunnels get
  `rp_filter=2` each.

### Domain rules and QUIC
- TCP 80/443 of clients with domain rules is redirected to `sniproxy.py`; a domain rule that leads where
  everything else goes, with no address rules, is dropped in `Engine._policies` (no pointless redirect).
- QUIC by name: the first packets of a new UDP 443 connection go to `config.QUIC_QUEUE` → `Sniffer.on_packet`.
  (1) Not parsed in time — reject, never "pass" (a listed site would leave by the wrong exit). (2) Every
  decision, "pass" included, goes into the conntrack mark with `QUIC_CT_BIT`. (3) A decision is taken from
  conntrack only while its exit is running. (4) No `nft_queue` in the kernel — rules without the queue, QUIC of
  these clients is blocked. *Tests:* `domains_socks_e2e.py` (QUIC), `test_v121c`.
- While the handler is down, redirected connections are refused (not a leak). A table built without the redirect
  is a leak of listed sites to the address rules, unless `routing.strict` turns those policies into a block.

### DNS on the server
- `dnsproxy.py` sends a client's queries the way the client's traffic goes (the exit's mark); names from domain
  rules go through the rule's exit; block → REFUSED. AAAA gets "no records": the tunnel carries only IPv4.
  Query IDs come from `secrets`.

### Panel web server and state
- Keep-alive: every response has `Content-Length`; unread request bodies are drained (`_drain_body`); a body with
  `Transfer-Encoding` is refused (411). Headers and body have a deadline for the whole request
  (`HEAD_DEADLINE`, `BODY_DEADLINE`), not per read.
- Limits: `MAX_CONNECTIONS`, `MAX_PER_IP` (IPv6 by /64), `MAX_PER_NET` (IPv6 /48); addresses that logged in
  recently get `RESERVE` extra places.
- `store.snapshot()` copies the whole state: never per client in a handler. Public routes (`/s/…`) read the state
  through `store.peek`. `Store.mutate` makes the new state live only after it is written to disk.
- Requests that change something pass `main.same_origin`. Pages have a Content-Security-Policy (`web.CSP`):
  scripts, styles and fonts only from the panel.
- `/api/state` carries a `tag` (without time, CPU and memory); a poll that sends it back gets a short answer when
  nothing changed, and the browser redraws nothing. The clients table is patched row by row.

### Interface
- The UI redraws on a timer: don't redraw while the user types in `#main`, and not under an open window —
  a window lives on the state it was opened with; a newer one is applied when it closes.
- Polling is `schedulePoll` (`setTimeout`, the pause grows with render cost), never `setInterval`.
- QR codes are PNGs drawn on a canvas, every module an integer number of device pixels (`drawQr`, the same code in
  `app.js` and `share.js`): a scaled SVG scans badly in AmneziaWG on Android.

### Installer
- `install.sh` rewrites `.env`: whatever it doesn't write itself, `keep_env` carries over from `.env.bak`.
- It reads answers from `/dev/tty` (works under `curl | bash`), never deletes an existing `amnezia-awg2`
  container (it renames it), and builds images with `docker build`, not `docker compose build`.
- An update runs the **already installed** `install.sh`: a fix in downloading reaches users only with the next
  update.

## Tests

```bash
python3 -m unittest discover tests            # no root needed
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
sudo PATH=<hev-socks5-tunnel>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
sudo PYTHONPATH=<pyroute2>:. python3 tests/shaping_e2e.py   # tc + ifb (kernel modules)
ruff check . && eslint app/static
```

- **Network tests on a GitHub machine** (`.github/workflows/net-tests.yml`, a few minutes, also run by hand): the
  e2e scripts above as root, then `movehost_e2e.py` (installs `awg-quick@awg0` on the machine itself — only on a
  throwaway one). `awg`, `amneziawg-go` and `hev-socks5-tunnel` are built from the stages of the current
  `Dockerfile`. The `kernel` job installs the kernel module the way users do (`install.sh --install-kernel`) and
  runs the real tunnel on it and mixed with `amneziawg-go`; it doesn't hold a release, but a red one means
  something that worked broke. The `lint` job runs ruff and eslint.
- **Upgrade end to end** (`.github/workflows/e2e.yml`, `tests/e2e/upgrade.sh`): published release → `install.sh` →
  a client through the API → `awg-router update` → the latest release. Runs after a release, on Mondays and by
  hand.
- Unit tests run on plain Python in CI: no PyYAML, `release.yml` is read as text. Functions of `install.sh` are
  tested cut out, with fake `curl` / `docker` in `PATH`.
- `.gitignore` contains `data/`: any folder named `data` stays out of git — test data lives in `tests/fixtures`.

## Demo and screenshots

```bash
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo PANEL_PORT=8099 PUBLIC_HOST=203.0.113.5 python3 -m app.main
```

- Demo clients have no config (no QR code): add a client through `POST /api/users`. Stop the demo with
  `kill $(pgrep -f "app[.]main")`.
- README screenshots (`docs/screenshots`): `python3 tools/screenshots/make.py` (`--out DIR` to look first) —
  demo panel, demo data through the API, Playwright. When a UI change changes what a screenshot shows, update the
  data or frames in this script, not by hand. The install GIF: `python3 tools/screenshots/gif.py`; addresses,
  paths and passwords in it are made up and the real ones never get into it.
