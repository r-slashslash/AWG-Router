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
| API by topic | `app/api/`: `auth` (login, sessions, 2FA, `same_origin`), `clients` (clients, limits, masking, the client's page `/s/…`), `exits`, `routing` (rules, lists, route check), `addrs` (the windows of Routing → Server addresses, 1.25.0), `server` (AWG server, engine, HTTPS, updates), `state` (`/api/state`, settings), `backup`, `telegram` (settings and bot control) |
| Server addresses (1.25.0) | `app/srcaddr.py` (the "Direct — address" value in memory, on disk and in backups, every place an exit is chosen), `app/engine/addrs.py` (adding, checking and removing addresses, Docker networks), `app/srcnet.py` (the panel's own connections from a chosen address), `app/ctflush.py` (closing connections whose path changed) |
| Input checks, one per kind of thing | `app/checks.py`; the server's client settings in `users.py` |
| Engine (`Engine`, one class in parts) | `app/engine/`: `__init__` (the pass, loops, events), `tunnels` (exits' tunnels, health, traffic, quotas), `routes` (routing decisions, nftables, ip rule), `sni` (domain rules, QUIC by name), `dns` (DNS on the server), `server` (AWG server, kernel module, rules "before the panel"), `addrs` (server addresses), `speed` (`tc`), `diag` (exit check, route check), `common` |
| Interface | `app/static/js/`, loaded in the order of `index.html`: `core.js` first (helpers, API, state, header, windows), `addrs.js` (server addresses: Direct — address in exit choices, the Server fields and Routing → Server addresses), a file per tab (`overview`, `clients`, `routing` — rules and the rule window with its lists, also used for a client's own rules, `clientrules` — the Client rules section of Routing (1.24.0), `exits`, `server`, `system`, `settings` — Telegram, password, backup); a window over a window (the rule window over the client window) is the second `dialog`, `#modal2`, `start.js` last; texts in `i18n.js`; the light or dark theme — `theme.js` in `<head>` (also on the client's page) |

## The AWG server ("Target")

`app/system.py` describes where the AmneziaWG server lives, as a `Target`:

- `ContainerTarget` — the AmneziaWG server in a Docker container (`amnezia-awg2`: the panel's own or the AmneziaVPN
  app's), layout `/opt/amnezia/awg/`;
- `HostTarget` — AmneziaWG installed on the host (`awg-quick@awg0`);
- `DemoTarget` — a fake server for `DRY_RUN=1` and for UI work.

Peers are changed with `awg syncconf`. Port, S1–S4, H1–H4 and HeaderProtectionKey need an
interface restart; a new port of a server in a container re-creates the container (Docker publishes the port
when it is created): `Target.change_port` → `system.recreate_with_port`, with the old container brought back
if the new one doesn't come up. A change or an update of the panel's own container cut off midway leaves the
server stopped under another name; `system.recover_renamed` (from `discover`) brings it back with its old config
(`data/port-change.json`). A disabled client is kept in the config as a commented block marked
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
`balance.Balancer` assigns the least busy exit and moves a client only after sustained overload. A rule
with load balancing (`balance`, 1.24.0) has its own `Balancer` per rule (per client and rule for a client's own
rule): `Engine.rule_out` gives the exit it assigned, the rule's `balance_fb` when none works, Block while a ticked exit
is still connecting, and the rule's `quota_action` once its monthly limit is used up.

Traffic by rule (1.24.0): every line of a policy chain sets a conntrack label with the rule's number — its place
among the client's enabled rules, `RULE_DEFAULT_SLOT` for Default — and the table `awgr_racct`
(`nftgen.racct_ruleset`, kept like `awgr_acct`: chains rewritten, sets with counters kept) counts bytes per client
and number. `sniproxy.py` counts its own connections by `client|exit|number`; `Engine.rule_keys` maps numbers back
to rules for `traffic.py`. A QUIC verdict carries the number in `QUIC_SLOT_MASK`, which the chain `q_lab` turns into
the label and takes off before routing.

A rule's speed limit (1.24.0) is a pair of nftables `limit` objects; its connections also get labels
`RULE_LIM_BASE + j` and `RULE_LIM_ANY`, and the chains `rl_f` (forward) and `rl_i` (input) drop what is over the limit
where packets arrive. `sniproxy.py` passes `j` in `RULE_LIM_MASK` of its sockets' marks (and QUIC verdicts), the
`type route` chain `rl_lab` in output turns it into labels and takes it off before the route is chosen again; the
proxy uses it only once a ruleset with `rl_lab` is in (`_rlim_key`), and `c_guard_post` drops packets still carrying
it. Numbers `j` are kept between passes (`Engine.rule_limits`).

### Server addresses (1.25.0)

Incoming addresses only change what goes into client configs (`settings.client_host`, `extra_hosts`, a client's own
`chost`); since 1.25.0 `client_host` is always written (`Store.split_hosts`), so the panel address
(`settings.public_host`, `PUBLIC_HOST`, the TLS domain) no longer moves clients. `install.sh` hands its own address
change to the panel once through `data/client-host` (`Store._installer_host`).

Outgoing addresses (`settings.out_hosts`, the main one `out_main`, "" — the system address):

- In memory every exit field (`srcaddr.slots`: Default, rules, their fallbacks and quota actions, clients, exits'
  fallbacks and quota actions, the Telegram path) can be `direct@<ip>` or `direct@system`; plain `direct` is the main
  address. On disk and in backups it is `direct` plus `<field>_src` (`srcaddr.to_disk` / `from_disk`), so 1.24 reads
  Direct and sends it from the system address. An exit's `bind` is the address it connects from. `srcaddr.normalize`
  turns an unknown address into the main one and reports where (backup restore, a removed address).
- `Engine.resolve` gives `direct` (the system address), an `nftgen.Addr` or `block`: an address is used only while
  its state is `ok` and its path is live (`_addr_live`); otherwise the traffic is blocked, never sent from another
  address. An exit whose `bind` doesn't work counts as down and follows its fallback.
- Address K (1..`ADDR_MAX`) has the mark `ADDR_MARK_BASE + K`, an `ip rule` `ADDR_PRIO_BASE + K` and a table
  `ADDR_TABLE_BASE + K`. Host mode: the address on the WAN interface (label `<dev>:awgr`, recorded in `data/addrs.json`
  and `data/own-addrs` for uninstall), `default via gw dev wan src IP` in the table and `snat` in `c_addr_nat`
  (`srcnat - 1`, before Docker's and the system's masquerade). Container mode: a Docker network
  `zz-awgr-out-K` with `com.docker.network.host_ipv4`, attached to the AWG container with the lowest gateway
  priority; if Docker makes it the container's default anyway, the panel detaches it and marks the address failed.
  Guards: `c_forward` rejects a marked packet leaving through the wrong interface or with an unknown mark in the
  range; `c_addr_post` (`srcnat + 1`) drops it after NAT when the sender isn't the address. While rules are put in
  before the panel (`awgr-hold`), address marks block.
- States (`addr_rt`): `checking` → `ok` (the path probe through the mark sees the same address as a probe bound to
  it), `failed` after two failed checks of an address that worked (events and Telegram `addr_down`/`addr_up`),
  `bad` — never worked, taken out of the system until the Server tab is saved again. An incoming IP that equals the
  public address or what an outgoing address is seen as counts as present (1:1 NAT, AWS).
- An exit connecting from an address carries its mark: `FwMark` in the AmneziaWG config (`awgconf.with_fwmark`),
  `mark` in hev-socks5-tunnel, `SO_MARK` in the SOCKS5 health check.
- DNS on the server asks with the address's mark too; its fallback DNS for Direct (`direct_fallback`, when the DNS
  servers don't answer) covers every Direct path — mark 0 and the address marks (`addr_marks`) — each with its own
  state (`dnsproxy.DirectPath`), always from the same address.
- The panel's own connections (updates, lists, lego through `srcnet.ConnectProxy`, `install.sh` via `AWGR_FROM`) go
  from `settings.own_src` while it works, else from the system address (`Engine.own_src`).
- A manual change of an exit choice (`api.routing.mutate_paths`) compares every client's path before and after
  (`Engine.paths`); only connections whose path changed are closed: `ctflush.py` in the AWG network (conntrack over
  netlink, by client and destination), `sniproxy.drop` for the domain handler, QUIC verdicts of clients whose domain
  rules changed. Balancing moves and fallbacks never close anything.

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
`sniproxy.py` answers with a mark: the exit's tunnel (an AmneziaWG exit, or a SOCKS5 exit with "Let QUIC (HTTP/3)
through the proxy", where it goes over UDP ASSOCIATE), the main table (Direct), a reject (Block and other SOCKS5
exits: the browser falls back to TCP, where the proxy gets the name) or "pass" to the address rules. A SOCKS5
exit without that box rejects UDP 443 for everyone routed to it, not only for domain rules. The decision,
"pass" included, goes into the conntrack mark for the rest of the connection. A ClientHello that doesn't come together in time
and QUIC that isn't Initial are rejected; no listener (`bypass`) or no `nft_queue` in the kernel means QUIC is
blocked for these clients, as before.

While DNS on the server is on, every DNS query of the clients goes to it: the ruleset has a `c_dns` chain (`nat`
prerouting, `dstnat`) that redirects UDP and TCP port 53 from the clients' interface to any other address to
`dnsproxy.py` (`Engine.dns_redirect`, `nftgen.generate(dns_to=…)`). It is in the rules before the panel too, so while the
panel restarts names don't resolve rather than go another way.
DNS on the server (`dnsproxy.py`) resolves names from domain rules through the rule's exit. With the DNS
filter setting, only addresses that it returned for those names (the `dom4` set with timeouts, refilled after
every rebuild of the table) are redirected to the handler.
On the direct path only, when the shared servers don't answer (DoH/DoT is often cut in Russia, China and Iran), it
asks the fallback DNS (`direct_fallback`: **Server → DNS → Fallback DNS for "Direct"**, `settings.fallback_dns_on` and
`fallback_dns`; **Apply for …** fills in the country's DNS) and skips the shared servers for `DIRECT_RETRY`, then tries
them again with one query in the background; a fallback that doesn't answer is skipped the same way. Paths through an
exit and names of a domain rule without a path (its exit down or "Block") never fall back.
A rule's own DNS and the fallback DNS are entries (`app/dnsaddr.py`): an IPv4 (plain DNS), `https://name/path` (DoH over
HTTP/2 or HTTP/1.1, whichever the server picks; `app/dohttp.py`), `h3://name/path` (DoH over HTTP/3 only) or
`tls://name` (DoT), each asked exactly as written (`dnsproxy.srv`). A service name on the Direct path from the system
address is resolved by the panel (`Engine.dns_lookup`) and passed as `tls://name#ip`; on a path through an exit or
**Direct — address** dnsproxy.py looks it up the same way (`_name_addr`): the shared DNS servers through that exit or from
that address (from an address also the fallback entries that are addresses, then the shared servers as plain DNS, when
they don't answer encrypted), so the lookup never leaves past the exit or from another address. On disk and in backups a rule's `dns` keeps the plain addresses only,
the whole list goes to `dns_all` (`dnsaddr.to_disk` / `from_disk`), so an older panel asks the usual servers instead.

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
- Lists live inside rules: a list that is no longer in any rule (shared or a client's own) is deleted when the rules are saved (`api.routing.drop_unused_lists`).
- Texts of the lists typed in by hand (networks and domains, up to 2 MB each) are not in `state.json`: each
  is in `data/texts/<id>-<tag>.txt`, and the list in the state has an empty `source` and the file's tag
  `text`. Read a text with `Store.list_text`; a backup is `Store.snapshot(texts=True)` (texts inline, as
  before 1.21.0). A new text gets a new file written before `state.json` refers to it; the previous one
  stays while `state.json.bak` needs it.
- `traffic.json` — counters (`traffic.FORMAT` stays 2 so older panels can still read it).
- `tls.json` — HTTPS settings for this particular server, with the Cloudflare API token when the domain is verified
  through Cloudflare DNS (1.24.0); written `0600`, not part of backups.
- `/api/state` is polled every few seconds, so keep it small (the clients' live speed, `speeds`, and CPU and memory come with every answer, outside the tag); load big data with separate requests,
  and read the state once per request (`store.snapshot()` copies all of it). The server keeps connections
  open (HTTP/1.1) and compresses text responses from `web.GZIP_MIN` bytes; static files are compressed once per
  version (`web.gzip_static`). Pages refer to static files as `static/v-<tag>/…` (`App.static_tag`: a hash of the names,
  times and sizes of all of them), sent as `immutable`: the browser keeps them until an update changes the tag. Public routes (`/s/…`) read the state with `store.peek`, without a copy.
- Requests that change something must come from the panel's own page (`api.auth.same_origin`: `Sec-Fetch-Site`,
  or `Origin`): the `SameSite=Strict` cookie is also sent from other pages of the same site.

## Interface and texts

The browser UI is plain JavaScript in `app/static` and loads nothing from third-party hosts.
Every string exists in four languages (ru, en, zh, fa) in `app/static/i18n.js`; the server returns
`Msg("key", **params)` and the browser translates it. Telegram texts are in `notify.TEXTS` and `tgbot.py`; when the bot
has to show a panel message (an error), `app/uitext.py` reads the same dictionaries from `i18n.js`.

Questions before an action are the panel's own, never the browser's `confirm()` (1.25.0): `ask()` in `core.js` puts a
button-on-the-page question into the bar `#askbar` above `main` (polling redraws only `main`) and a button-in-a-window
question into that window's footer. Unsaved changes on Routing and Server keep the tab and light up its save bar; what
saving the Server tab does (restart, AmneziaVPN app clients, addresses that move) is listed in that bar, and fields
whose change needs new client configs say so in orange under the field.

## Other parts

| Module | What it does |
|---|---|
| `tlsmgr.py`, `tlsconf.py`, `webfront.py` | HTTPS: Let's Encrypt (lego; HTTP-01 on port 80 or through a web server, DNS-01 through Cloudflare), own certificate |
| `notify.py`, `tgbot.py` | Telegram notifications and control (every Bot API request goes through `notify.Paths`: the chosen path, then other working exits — never Direct after an exit; "Turn on the bot" is the main switch); clients who opened their invitation see their own access in a private chat (bindings in `data/tgbot.json`, checked against the personal link's key on every message) and, if on, get reminders about the end date and the limit (`Notifier.client_fn` → `Bot.remind`, sent by the `tgbot-remind` thread) |
| `socks.py`, `health.py`, `probe.py` | SOCKS5 exit health checks and external IP probe |
| `countries.py` | Ready rules for Russia, China and Iran: the country's domain zones and DNS (the **Apply for …** buttons on Overview and Routing; the button also sets it as the fallback DNS for Direct) |
| `dnsaddr.py` | Entries of a rule's own DNS and of the fallback DNS (IPv4, DoH, DoT): parsing, service names, the disk form older panels understand |
| `dohttp.py` | DoH over HTTP/2 (own frames over `ssl`, chosen by ALPN) and over HTTP/3 (`h3://`: QUIC of the system's OpenSSL 3.2+ through `ctypes`, in its own threads) for `dnsproxy.py` |
| `selfupdate.py`, `updates.py` | Update check and self-update from GitHub releases |
| `awgconf.py`, `awgserver.py`, `cps.py` | AmneziaWG configs and the I1–I5 masking templates |
| `tgreq.py` | A request through an exit (Telegram, list downloads, a name's address), run inside the AWG server's network with the exit's mark |
| `totp.py` | Two-factor sign-in codes (RFC 6238); the secret is in `data/totp.json` |
| `qr.py`, `static/qrcode.js` | QR codes: PNG for Telegram (no third-party library), the browser's own for the panel and the client's page |
| `tgcard.py`, `tgcard.atlas` | The bot's menu and Status pictures (PNG, no third-party library): the words, ASCII characters and icons are alpha masks in `tgcard.atlas`, made by `tools/tgcard_atlas.py` in Chrome — run it after changing the `pc_*` / `ps_*` texts in `tgbot.py` (`AtlasTest` fails until then) |
| `static/share.html`, `static/share.js` | The client's personal page (`/s/…`, no sign-in): config, QR code, traffic and term |
| `hostnet.py` | The host's addresses, CPU and memory without outside requests (`/proc`; the panel runs in the host's network) |
| `initserver.py`, `movehost.py`, `uninstall.py` | Run by the installer: a new AWG server in the AmneziaVPN format, moving the container's server to the host, removing the panel's routing |

## Tests

`python3 -m unittest discover tests` runs without root. The network tests (`tests/*_e2e.py`) need
root and run real nftables, tunnels and `tc` in network namespaces; CI runs them for every change
to `main`.
