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
cannot be read from it.

## Speed limits

`shaping.plan` builds `tc` commands (HTB; `ifb` devices for incoming traffic) and
`Engine._sync_shaping` applies them. Only queues owned by the panel (`shaping.HANDLE`,
`shaping.IFB_PREFIX`) are touched. Nothing set means `tc` is not called at all.

## Panel state

- `state.json` — settings, clients, exits, rules. A new field needs a default in
  `store.DEFAULT_STATE`, input checks in the API handler in `main.py`, and handling in backup
  restore (`clean_backup_state` drops unknown fields).
- `traffic.json` — counters (`traffic.FORMAT` stays 2 so older panels can still read it).
- `tls.json` — HTTPS settings for this particular server; not part of backups.
- `/api/state` is polled every few seconds, so keep it small; load big data with separate requests.

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
