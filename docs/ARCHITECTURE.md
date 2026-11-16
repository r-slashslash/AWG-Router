# Architecture

A short map of how AWG Router works, for people who want to read or change the code.
Details live in the code and in the docstrings (written in Russian); numbers live in constants,
mostly in `app/config.py`.

## The big picture

```
browser / Telegram bot
        │
   panel (app/panel.py, app/api/*, app/web.py)  ──  state.json, traffic.json, tls.json  (./data)
        │
   engine (app/engine/*)  ──►  AWG server  (container, host or demo "Target")
        │                         exits: AmneziaWG tunnels awgrN, SOCKS5 proxies
        ├─ nftables / ip rule / tc      (routing, accounting, speed limits)
        ├─ sniproxy.py                  (domain rules; quic.py, nfqueue.py — HTTP/3 by name)
        └─ dnsproxy.py                  (optional DNS on the server)
```

The panel is a single Python process that uses only the standard library, including its own small
HTTP framework (`app/web.py`). It runs in a privileged container with the host network and PID
namespace, and enters the network of the AWG container with `nsenter`.

## Where the code lives

| Part | Files |
|---|---|
| Start | `app/main.py` (`python3 -m app.main`) |
| Shared objects: state, engine, HTTPS, notifications, the web app | `app/panel.py` |
| API by topic | `app/api/`: `auth` (login, sessions, 2FA, `same_origin`), `clients` (clients, limits, masking, the client's page `/s/…`), `exits`, `routing` (rules, lists, route check), `server` (AWG server, engine, HTTPS, updates), `state` (`/api/state`, settings), `backup`, `telegram` (settings and bot control) |
| Input checks, one per kind of thing | `app/checks.py`; the server's client settings in `users.py` |
| Engine (`Engine`, one class in parts) | `app/engine/`: `__init__` (the pass, loops, events), `tunnels` (exits' tunnels, health, traffic, quotas), `routes` (routing decisions, nftables, ip rule), `sni` (domain rules, QUIC by name), `dns` (DNS on the server), `server` (AWG server, kernel module, rules "before the panel"), `speed` (`tc`), `diag` (exit check, route check), `common` |
| Interface | `app/static/js/`, loaded in the order of `index.html`: `core.js` first (helpers, API, state, header, windows), a file per tab (`overview`, `clients`, `routing` with lists, `exits`, `server`, `system`, `settings` — Telegram, password, backup), `start.js` last; texts in `i18n.js` |

## The AWG server ("Target")

`app/system.py` describes where the AmneziaWG server lives, as a `Target`:

- `ContainerTarget` — the AmneziaVPN container (`amnezia-awg2`), layout `/opt/amnezia/awg/`;
- `HostTarget` — AmneziaWG installed on the host (`awg-quick@awg0`);
- `DemoTarget` — a fake server for `DRY_RUN=1` and for UI work.

Peers are changed with `awg syncconf`. Port, S1–S4, H1–H4 and HeaderProtectionKey need an
interface restart. A disabled client is kept in the config as a commented block marked
`#awgr:disabled`, so its address stays taken.

The server's interface comes from `awg-quick`, which takes the AmneziaWG kernel module when it is loaded
and `amneziawg-go` otherwise; the panel shows which one runs and warns when a module older than 3.x meets
an AWG 3.1 config. Tunnels to exits follow the server's engine (`EXIT_ENGINE` in `.env` can
pin them); any failure on the module moves them back to `amneziawg-go` until the server restarts. If the server's interface disappears while its target is
still there (for example, the kernel killed `amneziawg-go` when memory ran out), the engine restarts the
server with growing pauses.

The kernel module is the recommended engine. The installer asks for it on a new install (`kernel_fit`), and
the panel offers it (`api.server.engine_offer`) with a button that runs `install.sh --install-kernel` on the host
(`app/kernelmod.py`; its own state is `data/engine.json`, not part of backups). Whatever goes wrong, the
server ends up on `amneziawg-go`: a failed build changes nothing; a module lost after a kernel update is
reported (`Engine._watch_module`); a server that doesn't come up on a loaded module after `KERNEL_GIVE_UP`
restarts gets the module blocked and unloaded (`Engine._drop_module`, `kernelmod.block`), because awg-quick
falls back to `amneziawg-go` only when no module is loaded. The same block is how a manual choice of
`amneziawg-go` works (`Engine.switch_engine`): stop the server, block and unload the module, start the server;
choosing the module again lifts the block and restarts it (or installs the module first).

On a new target (the container restarted, so its network is empty) a pass puts in the rule set before it
starts any tunnel, with every exit that has no tunnel yet treated as down (`Engine._hold_rules`); the usual
apply at the end of the pass replaces it. The panel hears about a container start from Docker's event stream at
once, and the same "no tunnels yet" rule set is kept next to the server's config so that the panel's own AWG
container and the host service apply it themselves before the server comes up (`Engine._save_hold`). AWG exits wait while the 3.x module is loaded and the server's
interface is not up yet (`Engine.engine_pending`), so they don't start on `amneziawg-go` first. If
`awg syncconf` fails, the server's files are put back (`users._put_back`), so the files always match the
interface.

## Routing

For every exit N the panel creates a tunnel interface `awgrN` and sets up:

1. nftables `prerouting` puts a mark `MARK_BASE + N` on a client's packets;
2. an `ip rule` with priority `RULE_PRIO_BASE + N` sends marked packets to the table `TABLE_BASE + N`;
3. that table has `default dev awgrN` and a fallback route `unreachable`, so if the tunnel is gone
   nothing leaks;
4. SNAT to the tunnel address, MSS clamping and `rp_filter=2` complete the path.

`nftgen.layout()` builds the rule set and is shared with the sniproxy config, so policy names must
match. The accounting table `awgr_acct` is never rebuilt together with `awgr`, or counters reset
(`nftgen.ACCT_VER` is bumped when it changes).

Which exit a client uses is decided in `engine.resolve`: the chosen exit if it works, otherwise the
fallback; an exit over its monthly quota follows `quota_action`. With load balancing on,
`balance.Balancer` assigns the least busy exit and moves a client only after sustained overload.

## Domain rules

Domain rules can lead to any exit. nftables redirects TCP 80/443 of such clients to
`sniproxy.py`, which reads the site name (SNI or Host header): a match goes through a SOCKS5 proxy by name,
or to its original address with the mark of an AmneziaWG exit or Direct, or is closed for Block;
anything else goes to its original address with the client's policy mark. A domain rule that leads where
everything else goes, with no address rules, changes nothing and turns no redirect on. A connection whose
original address is the handler itself was opened to its port directly, not redirected, and is closed. Once
the path is chosen, data is relayed inside the kernel (`splice`), so Python only reads the name and counts bytes.

QUIC (UDP 443) of these clients is read by name too: the first packets of a new connection go to a kernel
queue (`nfqueue.py`, netlink without libraries), `quic.py` decrypts the Initial packets (their keys come from
the connection ID in the header, RFC 9001 / 9369), puts the ClientHello together from CRYPTO frames and
`sniproxy.py` answers with a mark: the exit's tunnel (an AmneziaWG exit, or a SOCKS5 exit with "Let QUIC
through the proxy", where it goes over UDP ASSOCIATE), the main table (Direct), a reject (Block and other SOCKS5
exits: the browser falls back to TCP, where the proxy gets the name) or "pass" to the address rules. A SOCKS5
exit without that box rejects UDP 443 for everyone routed to it, not only for domain rules. The decision,
"pass" included, goes into the conntrack mark for the rest of the connection. A ClientHello that doesn't come together in time
and QUIC that isn't Initial are rejected; no listener (`bypass`) or no `nft_queue` in the kernel means QUIC is
blocked for these clients, as before.

DNS on the server (`dnsproxy.py`) resolves names from domain rules through the rule's exit. With the DNS
filter setting, only addresses that it returned for those names (the `dom4` set with timeouts, refilled after
every rebuild of the table) are redirected to the handler.

The panel looks at the handler every second: it touches a heartbeat file every second, and a handler that
exited or stopped touching it for `SNI_HANG` seconds is restarted. While it is down, redirected connections are
refused. When domain rules can't work at all (the handler isn't running), the panel builds the table without
the redirect, so listed sites follow the address rules — or, with `routing.strict`, the policies that have
domain rules become a block.

## Speed limits

`shaping.plan` builds `tc` commands (HTB; `ifb` devices for incoming traffic) and
`Engine._sync_shaping` applies them. Only queues owned by the panel (`shaping.HANDLE`,
`shaping.IFB_PREFIX`) are touched. Nothing set means `tc` is not called at all.

## Panel state

- `state.json` — settings, clients, exits, rules. A new field needs a default in
  `store.DEFAULT_STATE`, an input check in `app/checks.py` (client settings of the server: in `users.py`),
  used both by the API handler and by backup restore (`clean_backup_state` drops unknown fields; where a
  backup always got a default instead of an error, it still does — `checks.forgive`). It is written with
  `fsync`; the previous version stays as `state.json.bak`, and the panel starts from it when `state.json`
  is damaged. State and backups of earlier releases are kept in `tests/fixtures/old` and must load as
  before (`tests/test_old_files.py`).
- Texts of the lists typed in by hand (networks and domains, up to 2 MB each) are not in `state.json`: each
  is in `data/texts/<id>-<tag>.txt`, and the list in the state has an empty `source` and the file's tag
  `text`. Read a text with `Store.list_text`; a backup is `Store.snapshot(texts=True)` (texts inline, as
  before 1.21.0). A new text gets a new file written before `state.json` refers to it; the previous one
  stays while `state.json.bak` needs it.
- `traffic.json` — counters (`traffic.FORMAT` stays 2 so older panels can still read it).
- `tls.json` — HTTPS settings for this particular server; not part of backups.
- `/api/state` is polled every few seconds, so keep it small; load big data with separate requests,
  and read the state once per request (`store.snapshot()` copies all of it). The server keeps connections
  open (HTTP/1.1) and compresses text responses from `web.GZIP_MIN` bytes; static files are compressed once per
  version (`web.gzip_static`). Public routes (`/s/…`) read the state with `store.peek`, without a copy.
- Requests that change something must come from the panel's own page (`api.auth.same_origin`: `Sec-Fetch-Site`,
  or `Origin`): the `SameSite=Strict` cookie is also sent from other pages of the same site.

## Interface and texts

The browser UI is plain JavaScript in `app/static` and loads nothing from third-party hosts.
Every string exists in four languages (ru, en, zh, fa) in `app/static/i18n.js`; the server returns
`Msg("key", **params)` and the browser translates it. Telegram texts are in `notify.TEXTS` and `tgbot.py`.

## Other parts

| Module | What it does |
|---|---|
| `tlsmgr.py`, `tlsconf.py`, `webfront.py` | HTTPS: Let's Encrypt (lego), own certificate, a web server on port 80 |
| `notify.py`, `tgbot.py` | Telegram notifications and control |
| `socks.py`, `health.py`, `probe.py` | SOCKS5 exit health checks and external IP probe |
| `selfupdate.py`, `updates.py` | Update check and self-update from GitHub releases |
| `awgconf.py`, `awgserver.py`, `cps.py` | AmneziaWG configs and the I1–I5 masking templates |
| `tgreq.py` | A request through an exit (Telegram, list downloads, a name's address), run inside the AWG server's network with the exit's mark |
| `totp.py` | Two-factor sign-in codes (RFC 6238); the secret is in `data/totp.json` |
| `qr.py`, `static/qrcode.js` | QR codes: PNG for Telegram (no third-party library), the browser's own for the panel and the client's page |
| `static/share.html`, `static/share.js` | The client's personal page (`/s/…`, no sign-in): config, QR code, traffic and term |
| `hostnet.py` | The host's addresses, CPU and memory without outside requests (`/proc`; the panel runs in the host's network) |
| `initserver.py`, `movehost.py`, `uninstall.py` | Run by the installer: a new AWG server in the AmneziaVPN format, moving the container's server to the host, removing the panel's routing |

## Tests

`python3 -m unittest discover tests` runs without root. The network tests (`tests/*_e2e.py`) need
root and run real nftables, tunnels and `tc` in network namespaces; CI runs them for every change
to `main`.
