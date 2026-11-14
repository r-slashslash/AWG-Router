# Architecture

A short map of how AWG Router works, for people who want to read or change the code.
Details live in the code and in the docstrings (written in Russian); numbers live in constants,
mostly in `app/config.py`.

## The big picture

```
browser / Telegram bot
        │
   panel (app/main.py, app/web.py)  ──  state.json, traffic.json, tls.json  (./data)
        │
   engine (app/engine.py)  ──►  AWG server  (container, host or demo "Target")
        │                         exits: AmneziaWG tunnels awgrN, SOCKS5 proxies
        ├─ nftables / ip rule / tc      (routing, accounting, speed limits)
        ├─ sniproxy.py                  (domain rules for SOCKS5 exits)
        └─ dnsproxy.py                  (optional DNS on the server)
```

The panel is a single Python process that uses only the standard library, including its own small
HTTP framework (`app/web.py`). It runs in a privileged container with the host network and PID
namespace, and enters the network of the AWG container with `nsenter`.

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

On a new target (the container restarted, so its network is empty) a pass puts in the rule set before it
starts any tunnel, with every exit that has no tunnel yet treated as down (`Engine._hold_rules`); the usual
apply at the end of the pass replaces it. AWG exits wait while the 3.x module is loaded and the server's
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

Domain rules apply to SOCKS5 exits only. nftables redirects TCP 80/443 of such clients to
`sniproxy.py`, which reads the site name (SNI or Host header): a match goes through the proxy by name,
anything else goes to its original address. QUIC is blocked for these clients because the name
cannot be read from it. A connection whose original address is the handler itself was opened to its port
directly, not redirected, and is closed. Once the path is chosen, data is relayed inside the kernel (`splice`), so Python
only reads the name and counts bytes.

## Speed limits

`shaping.plan` builds `tc` commands (HTB; `ifb` devices for incoming traffic) and
`Engine._sync_shaping` applies them. Only queues owned by the panel (`shaping.HANDLE`,
`shaping.IFB_PREFIX`) are touched. Nothing set means `tc` is not called at all.

## Panel state

- `state.json` — settings, clients, exits, rules. A new field needs a default in
  `store.DEFAULT_STATE`, input checks in the API handler in `main.py`, and handling in backup
  restore (`clean_backup_state` drops unknown fields). It is written with `fsync`; the previous version
  stays as `state.json.bak`, and the panel starts from it when `state.json` is damaged.
- `traffic.json` — counters (`traffic.FORMAT` stays 2 so older panels can still read it).
- `tls.json` — HTTPS settings for this particular server; not part of backups.
- `/api/state` is polled every few seconds, so keep it small; load big data with separate requests,
  and read the state once per request (`store.snapshot()` copies all of it). The server keeps connections
  open (HTTP/1.1) and compresses text responses from `web.GZIP_MIN` bytes; static files are compressed once per
  version (`web.gzip_static`). Public routes (`/s/…`) read the state with `store.peek`, without a copy.
- Requests that change something must come from the panel's own page (`main.same_origin`: `Sec-Fetch-Site`,
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

## Tests

`python3 -m unittest discover tests` runs without root. The network tests (`tests/*_e2e.py`) need
root and run real nftables, tunnels and `tc` in network namespaces; CI runs them for every change
to `main`.
