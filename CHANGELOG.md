# Changelog

Panels compare their version with the latest GitHub release and show "update available" when
it grows, so every user-visible change gets a new version.

## 1.25.0 — 2026-11-27

- **Outgoing server addresses.** **Server → Additional outgoing addresses** takes other IPv4 addresses of this server
  (up to 16); the panel adds them to the system itself (host: `ip addr add … label <dev>:awgr`, recorded in
  `data/addrs.json` and `data/own-addrs`, re-added after a reboot, removed with the field or on uninstall; container
  mode: a Docker network `zz-awgr-out-K` with `com.docker.network.host_ipv4`, attached to the AWG container) and checks
  each: a probe through the address's mark must see the same address as a probe bound to it. **Server outgoing
  address** picks the main one (default — the system address). Every exit choice (Default, rules, their fallbacks and
  quota actions, clients and their own rules, exits' fallbacks and quota actions, the Telegram path) lists **Direct —
  address** per address, main first; in memory `direct@<ip>`/`direct@system`, on disk and in backups `direct` plus
  `<field>_src`, so 1.24 reads Direct. Each address has its own mark (`ADDR_MARK_BASE + K`), `ip rule` and table
  (`default via gw src IP`); host mode swaps the sender in `c_addr_nat` (`srcnat - 1`, before any masquerade).
  Guards in `c_forward` and `c_addr_post` drop a marked packet leaving another way, from another address after NAT,
  or with an unknown mark of the range; while rules are put in before the panel, address marks block.
- **An address that stops working blocks, never leaks.** Two failed checks of an address that worked → `failed`:
  what goes through it is blocked, its card on **Routing** is red, exit choices mark it "not working", an exit
  connecting from it counts as down and follows its fallback, and Telegram gets `addr_down`/`addr_up`. An address that
  never worked is taken out of the system (`bad`) until the Server tab is saved again.
- **Exits connect from an address**: an exit's `bind` (**Connect from address** in its window, or the outgoing
  address window) puts the address's mark on the tunnel itself (`FwMark` in the AmneziaWG config, `mark` in
  hev-socks5-tunnel, `SO_MARK` in the SOCKS5 check). Under an exit through another server, exit choices say which
  address it connects from.
- **Routing → Server addresses**: incoming address cards (how many clients have each in their config) and outgoing
  ones (what websites see and the country, where it is used); their windows tick clients (`PUT /api/addr-in`) or
  Direct places and exits (`PUT /api/addr-out`, places from `GET /api/addr-places`). Unticked — back to the main
  address. The route check shows the address.
- **Changing the main outgoing address moves** everything on plain Direct to the new one; before saving, the Server
  tab asks (`confirm: false` → what moves, where removed addresses are used, which clients lose their incoming
  address). Removing a used address puts its places on the main one. Restoring a backup: addresses are the server's
  own (`OWN_SETTINGS`), places with an address this server doesn't have go to the main one and the panel says where.
- **Open connections follow a manual change**: saving routing, a client, an exit or an address window compares every
  client's path before and after and closes only the connections whose path changed — conntrack entries in the AWG
  network over netlink (`ctflush.py`, by client and destination; only the clients' entries are kept in memory, not the
  whole table of a busy server), the domain handler's own connections
  (`sniproxy.drop`) and QUIC verdicts of clients whose domain rules changed — then says "Open connections will
  reconnect over the new path". Load balancing moves and fallbacks close nothing, as before.
- **The server's own connections** (panel updates, lists, lego through a local CONNECT proxy, `install.sh` via
  `AWGR_FROM`) can go out from a chosen address: **System → Address the server itself goes out from**; if it stops
  working, from the system address.
- **Incoming address apart from the panel address.** **Server incoming address** (`client_host`, now always written:
  `Store.split_hosts` on every start, a domain also goes to `extra_hosts`) and **Additional incoming addresses** (IPs or
  domains; a missing IP is added to the system and checked like an outgoing one; 1:1 NAT as on AWS counts as present)
  replace **Server public address** and **Address in configs**. **System → Panel address** (an IP goes to
  `public_host`, a domain to the TLS domain) no longer moves clients; the certificate window lost its domain field.
  `install.sh` hands an address change of its own to the panel once (`data/client-host`): configs on the old address
  follow it, as before 1.25.0.
- **DNS on the server follows the address**: names of a client on Direct — address are asked from that address, and
  when the DNS servers don't answer there, from the fallback DNS (below) — also from that address (`addr_marks` in the
  dnsproxy config; each Direct path keeps its own "doesn't answer" state, the Server tab warns when any of them does).
  Paths through an exit still never fall back.
- **Fallback DNS for Direct is set by hand.** Until now, on a server in Russia, China or Iran the panel itself asked the
  country's local DNS (plain) when encrypted DNS didn't answer on a Direct path. Now it is **Server → DNS → Fallback DNS
  for "Direct"**: a checkbox and up to two servers (`settings.fallback_dns_on`, `fallback_dns`), off on a new install
  and after an update; **Apply for Russia / China / Iran** fills in the country's DNS and turns it on (replacing what
  was there). It works with any DNS encryption, only on Direct paths, from the same address; a fallback that doesn't
  answer isn't asked for `DIRECT_RETRY` (clients get SERVFAIL at once) and is retried in the background. The Server tab
  says "The DNS servers don't answer directly" and, under the fallback, "In use now" or "doesn't answer either".
- **One slow name no longer switches Direct to the fallback DNS** (full audit of 1.25.0, П31). A name the resolver
  took longer than the timeout to answer (its own name servers don't respond) or one lost UDP packet marked the DNS
  servers of the path as not answering for `DIRECT_RETRY`: for two minutes every Direct client went to the fallback
  (in 1.22.0–1.24.0 the automatic country DNS, plain); in this release before the fix, as such a name is slow at the
  fallback too, the fallback was marked down as well and they all got SERVFAIL. Now a name without an answer starts one
  background check of the same servers by the same path — `. NS` (any resolver answers it from its cache) to every
  server at once, each on its own new connection outside the pool's queue, plain DNS with a second try, at most
  `CHECK_TIMEOUT` (5 s); while it runs new names of that path go to the fallback, so real blocking (dropped SYN, RST,
  dropped ClientHello, a connection frozen after the handshake, cut UDP 53 or 443) switches as fast as before. Only a
  failed check marks the path down; the fallback gets the same check, and the probe every `DIRECT_RETRY` asks `. NS`
  instead of a client's name. Names through an exit and names of rules without a path never go to the fallback, during
  the check too; the Server tab warns only after a failed check. `dnsproxy.py` exits at once on SIGTERM (an HTTP/3
  query thread held the exit up to 5 s). From the independent check of the fix: a SIGHUP that changes the fallback
  while a name waits no longer writes the old fallback's failure into the new one (it then wasn't asked for two
  minutes); a pooled DoH/DoT connection cancelled by the query deadline is closed instead of dropped; checks over
  HTTP/3 have 16 threads of their own (a frozen entry keeps its thread until its deadline, and with 4 the next checks
  queued and failed).
- **Fixes from the independent check of P31.** A DoH/DoT connection cancelled right after its TLS handshake (the query
  deadline, or the path check cancelling its other queries) no longer leaves its descriptor number "used by transport"
  for up to 30 s: `open_conn` closed the socket the transport still owned, Linux gave that number to the next sockets,
  and under a burst of hundreds of names new connections failed, path checks failed in a row and Direct paths went to
  the fallback for two minutes (1000 clients on 17 paths, 300 dead names at once: 6–17 of 17 paths in 5 of 6 runs, up
  to half the names SERVFAIL; now none). The same query already on its way waits for its answer instead of going to the
  servers again (`Proxy.asking`): a dead name repeated every second or two held a pool connection per repeat until its
  deadline, and every Direct name waited 3–9 s; the key keeps paths, rules without a path and the RD, CD, EDNS and DO
  flags apart, each client gets its own ID and letter case, and followers take no `MAX_INFLIGHT` place (their own limits
  and the path state in the key — below). With **Domain rules only for addresses from this DNS's answers**, an address
  that isn't in the set yet goes there before the answer leaves (one `nft` command per batch in a thread, at most
  `SET_WAIT` = 1 s while the panel rebuilds its table, counted as `set_late`): clients connect at once, and the first
  connection to a new address went by the address rules — past the exit. A name that waited for the shared servers while the fallback was changed or switched off goes to the current
  one. "The fallback DNS doesn't answer either" shows only together with "The DNS servers don't answer directly" (once
  the shared servers answered again nobody asked the fallback, and the line stayed up to 15 minutes). A fallback written
  by name (`tls://…`) on Direct — address with unencrypted shared servers that don't answer uses the address the panel
  found when that path has nothing to ask (`name_hint`), instead of being marked down for two minutes. README: your own
  AdGuard Home as a shared server answers one address 20 queries a second by default.
- **The DNS cache keeps the query flags apart** (RD, CD, EDNS, DO; found while fixing the above, as old as DNS on the
  server): a device that validates DNSSEC itself (systemd-resolved with `DNSSEC=yes`) got a cached answer without
  signatures when a phone had asked the name first, and the name failed for it.
- **Fixes from the check of the P31 fixes.** With **Domain rules only for addresses from this DNS's answers**, an
  address that devices keep asking for no longer drops out of the `dom4` set after `SET_MIN` (30 minutes) — so since
  1.24.0: a repeated `nft add element` doesn't renew the timeout of an element already in the set (Linux 6.8 never,
  6.18 and 7.0 only with another timeout), and for minutes connections to the site went by the address rules and
  Default, past the exit. A batch is now one `nft -f -` transaction "add with 1 s → delete → add with the timeout"
  (`Proxy._nft_tx`): the timeout is renewed on every kernel, the address is never missing (100–1000 rewrites in a row,
  not one of 1–4 million packets past the set on 6.8 and 7.0), and `resync` after a table rebuild is one nft process
  instead of one per 2000 addresses (50 000 live addresses with 100 000 networks in the table: 15–18 s → 1.1–1.2 s).
  Without CAP_NET_ADMIN in the initial namespace (Docker in LXC) nft refuses a transaction over `net.core.wmem_max`
  ("Message too long", about 5000 addresses by default): such a batch is written in halves, and the size is remembered
  (`_set_tx`). An answer that renews an address (TTL over `SET_MIN`) while the command adding it still runs waits for
  that command as well. A device that repeats a question (Windows, Linux — every 1–2 s) no longer waits up to 20 s at
  the start of real blocking: while a Direct path with a fallback is checked or down, a query doesn't join one that
  still waits for the shared servers (`stage` in the key) and goes to the fallback itself; a repeat that joins a query
  older than `JOIN_CHECK` (5 s) on a path that answered nothing for as long starts the path check at once — before,
  a faster repeat of its own did (test VPS in Russia, real Cloudflare and Google, repeats every second: the longest
  wait 10–15 s before the same-query fix, 20 s with it, now 6–10 s; a slow name on a busy working path starts no check).
  Clients waiting for one query are limited — `JOIN_MAX` (1024) per query and `JOIN_ALL` (8192) in all, then SERVFAIL
  at once (`join_full`): a flood of one query kept every copy in memory (3000 a second for 30 s: 35 → 224 MB and 40 % of
  the queries unanswered; now 35 MB, all answered; 600 different dead names: 263 → 73 MB). "The fallback DNS
  doesn't answer either" compares paths: with two **Direct — address** paths it showed for the other one's fallback.
  Network tests: job `dns-set` (`tests/dns_set_check.py` on the kernels 6.8 and 7.x).
- **Fixes from the check of those fixes.** A repeat that joins a query still waiting for encrypted DNS (DoH or DoT —
  the shared servers or a rule's own DNS) for over `HEDGE_AFTER` (1.5 s) starts one second attempt of the same query by
  the same path on a new connection (`_hedge`); the first answer of the two goes to everyone waiting and into the cache,
  and the path counts as answering. Before the same-query fix a repeat asked the server itself and covered a lost answer;
  with it the repeat waited for the first query's deadline — 6–15 s instead of 1–4 where encrypted DNS answers only now
  and then (a server that loses answers, a block that comes and goes) — and on a quiet path it also started a path check,
  so names went to the unencrypted fallback while the path worked. The second attempt delays nothing: when the first ends
  without an answer it is cancelled and the check and the fallback go as before (full blocking: the same times to the
  hundredth); at most `HEDGE_MAX` (8) per path at once (each one waiting for a blocked server holds ~0.35 MB); plain DNS and `h3://` entries have none. GitHub machines, 80 ms,
  15 minutes: a model of DNSPod DoH from Russia (8 % of answers lost) — names waiting over 5 s 16 → 2 for one user (checks
  from repeats 14 → 2), 125 → 23 for five users, none sent to the fallback; a block that drops 30 % of queries — names
  waiting over 3 s 88–98 → 24–34 of 300; connections that freeze after a while — 5 names at the fallback → none, the
  longest wait 5.5 → 2.5 s. Queries that go straight to the fallback (a Direct path checked or down) have their own
  `MAX_INFLIGHT` places (`inflight_fb`): at the start of blocking the places were held by queries waiting 10–20 s for the
  blocked servers, and on a big server (300 and more new names a second) every Direct client got SERVFAIL for 15 s although
  the fallback answered at once. With Docker in an unprivileged LXC container the panel's rule table with a country list
  doesn't fit `net.core.wmem_max` of the host (nft: "Message too long"); the panel now says what to run on the host
  instead of nft's English error (README too). A set write that nft refuses by size even at `SET_TX_MIN` addresses ends
  instead of trying every part. The network test "frozen after the handshake" drops the client's TLS data records
  instead of counting bytes (it was red 4 times in 40, now 0 in 40).
- **A rule's own DNS and the fallback DNS take DoH and DoT**: `77.88.8.8` (plain), `https://name[:port]/path` (DoH),
  `tls://name[:port]` (DoT), the name or an IPv4 (`app/dnsaddr.py`). Each is asked exactly the way it is written — an
  encrypted one that doesn't answer is never asked as plain DNS; the second entry is asked when the first doesn't
  answer. A service name on the Direct path from the system address is resolved by the panel (cached,
  `Engine.dns_lookup`) and given to dnsproxy.py as `tls://name#ip`; on a path through an exit or **Direct — address** the
  panel doesn't look it up (that query would leave the server past the exit or from the system address) — dnsproxy.py
  looks it up the same way (`_name_addr`, cached by TTL): the shared DNS servers through that exit or from that address;
  from an address, when they don't answer, also the fallback entries that are addresses and the shared servers as plain
  DNS. Saving from the panel refuses a new name that doesn't resolve the way the rule goes (`Engine.dns_names_check`;
  through an exit or from an address — from the AWG network with that mark). On disk and in backups a rule's `dns` keeps only plain
  addresses and the whole list goes to `dns_all`, so 1.24 asks the usual servers for such a rule instead of failing.
- Pressing **Apply for …** again makes the country's rules what the first press made: Direct, on, the domain rule with
  the country's current DNS, at the end of the shared rules; other rules with only that list go (they would catch the
  country's sites first); a name, speed limits and a monthly limit someone added stay, balancing goes (Direct has none).
  Before, a second press only added a missing rule.
- **Server → DNS**: **DNS query encryption** comes right under **DNS on the server** (it is for those servers), then
  the fallback DNS, then **Domain rules only for addresses from this DNS's answers**; the hints are shorter.
  **System → Panel address** no longer says it doesn't change client addresses.
- The Telegram bot shows "direct — address".
- **Panel texts are shorter**: about forty hints, placeholders and confirmations say the same in fewer words in all
  four languages (country rules, load balancing, lists, exits, server, clients, Telegram, sign-in code, updates,
  certificate, backup); "For example:" is gone from placeholders; client hints point to **Additional incoming
  addresses** (the old section name was left there). Ten texts of the old address fields, unused since the start of
  1.25.0, are removed.
- **No browser pop-ups.** Every question before an action is the panel's own (`ask()` in `core.js`): a button on the
  page asks in a bar at the top, like "Changes apply after saving" (`#askbar`, outside `main`, so polling doesn't
  redraw it); a button in a window asks at the bottom of that window in place of its buttons. Esc, closing the window,
  another question or another tab mean "no". Twenty-two `confirm()` calls are gone; only the browser's own "Leave
  site?" when closing a tab with unsaved changes stays. Leaving the Routing or Server tab with unsaved changes no
  longer asks: the tab stays and its save bar lights up "Save or discard the changes".
- **Server → save bar says what saving does**: the AWG server restart (port, subnet, server-side parameters), AmneziaVPN
  app clients that lose the server after a port change, and — after the first **Save** — what moves with the addresses
  (`confirm: false`); the second **Save** saves.
- **An orange "Clients will need new configs."** appears under a field whose unsaved change needs them: port, subnet,
  server incoming address, DNS servers (with DNS on the server — the first one), **DNS on the server**, server-side
  obfuscation parameters; in the client window after changing its address or masking; in the incoming address window
  while the ticks differ. The hints no longer say it all the time.
- **Overview**: "No rules — all traffic goes through the default exit."; the two hints under **Apply for …** are gone.
  **System → Domain and certificate** is **Certificate settings**, without the panel address line; **Get a certificate
  now** moved into that window.
- **Route check resolves a name through the client's exit again**: since 1.21.0 (the engine split into a package) the
  lookup helper imported a module that no longer existed there, the error was swallowed, and names were resolved by
  the panel's own resolver — on a server in Russia, China or Iran possibly a spoofed address.
- **DoH over HTTP/2 and HTTP/3** (`app/dohttp.py`): Quad9 answers HTTP/1.1 with "505 HTTP Version Not Supported" and
  Yandex closes the connection, so DoH to them — the shared servers with DoH encryption and `https://` entries — never
  answered. A DoH connection now offers ALPN `h2, http/1.1` and speaks HTTP/2 when the server picks it (own frames over
  `ssl`; HPACK without Huffman and without a dynamic table; only `:status` is read, the body is checked as a DNS answer).
  A new entry `h3://name[:port]/path` is DoH over HTTP/3 only: QUIC from the system's OpenSSL 3.2+ through `ctypes` (the
  panel image has it), in its own threads, the UDP socket with the path's mark; an ISP may cut it apart from HTTPS, so
  it is written explicitly and the second entry is the spare. Saving refuses `h3://` where OpenSSL has no QUIC.
- **Fixes from the independent review**: only **Additional incoming addresses** are added to the system (on clouds
  with the public address outside — AWS, Oracle, Yandex Cloud — the panel put the address in client configs on the
  interface at every start and called it "not working"), and an extra incoming IP not in the system waits until the
  server's public address is known; an address keeps its last state over a panel restart (`data/addrs.json`), so
  Direct — address isn't blocked until two checks pass after every update; Telegram after an exit never goes Direct,
  also with a fallback "Direct — address"; a service name of a rule's own or the fallback DNS on Direct — address is
  looked up from that address, not the system's; an outgoing or incoming address inside the clients' network is
  refused; the kernel module's version via `modinfo` imported a module that isn't there (since 1.21.0) — a test now
  checks every import inside a function; plain DNS no longer retries the same silent server over TCP (only a
  truncated answer goes to TCP), so the fallback DNS takes over in about 2 s instead of 7–14; the connection reset
  after a manual change keeps only clients' conntrack entries in memory; name lookups share one deadline; the
  in-panel question is cancelled by the tab row too.
- **DNS on the server answers every DNS query of the clients** (owner's answer to the full audit of 1.25.0, П5): with
  it on, the ruleset gets a `c_dns` chain (`nat` prerouting, `dstnat`) that sends UDP and TCP port 53 from the clients'
  interface to any other address to `dnsproxy.py` on the server's tunnel address. The second DNS in client configs,
  a DNS typed into a device and private addresses no longer go past the exit or unencrypted; old configs need no new
  import. The redirect stays in the rules before the panel: while the panel restarts, names don't resolve for a few
  seconds instead of going another way.
- **AmneziaWG server image for arm64 too** (П4): `release.yml` builds `linux/amd64,linux/arm64`; the installer refuses
  a ready image of another CPU ("the ready image is for amd64, this server is arm64") and builds it on the server, checks
  free space in Docker's root (3 GB) before a build and prunes the build cache after it (П6).
- **The own AWG container runs without `--privileged`** (П24): `--cap-add=NET_ADMIN --cap-add=SYS_MODULE --device
  /dev/net/tun`; checked on GitHub with amneziawg-go and with the kernel module. It takes effect at the next
  `refresh_own_server` (update).
- **Installer** (full audit of 1.25.0): after the last question a lost SSH session (SIGHUP) no longer stops it in the
  middle of replacing the AWG container (П9), and a container left "created" by an interrupted update is started by the
  panel itself (`system._start_created`); Docker Compose v5.6.1 and buildx v0.38.1 are pinned with sha256 per CPU
  instead of "the latest from GitHub" (П22, `tools/upstream.py` watches them); `.env` and `.env.bak` are 0600 even when
  they existed; `AWGR_DOMAIN` from the environment is checked like a typed one; "Run as root: sudo -i, then the same
  command again"; the own AWG container NATs clients also on the interface of its default route (with outgoing address
  networks Docker may rename it after a restart, П34); `awg-router uninstall` names clients the panel turned off (they
  stay off without it, П67).
- **Routing fixes from the full audit of 1.25.0.** Domain rules: a manual change of an exit now reconnects their sites
  (a method shadowed by an attribute in `Sniffer`, П1); connections open before the redirect keep their path instead of
  getting the handler's mark and going past the exit (`ct status dnat accept`, a reject for the mark in `c_forward`, П2);
  SOCKS5 rules connect from the exit's **Connect from address** (П32); a reload failing in the first moments no longer
  stops the handler (П18); HTTP with headers over 16 KB or a short first piece is read correctly (П21); QUIC of a client
  not yet in the handler's settings is blocked (S11); an empty TLS record ends the read (S4). `c_prerouting` runs after
  `wg-quick`'s premangle (`mangle + 10`), so a full-tunnel wg-quick on the host can't wipe exit marks (П10); IPv6 of
  clients is closed in the rules before the panel too (`awgr-hold6-<iface>.nft`, П11); an exit with **Connect from
  address** blocks until the address path is up after a restart (П12, П17); a new server network without the panel's
  table gets a closed forward chain if the rules fail (П14); the cloud service address `100.100.100.200` (Alibaba) is
  closed like `169.254.0.0/16` (П33); the exit NAT runs at `srcnat - 1` (П49); address guards skip `lo` (П48); a port
  change keeps `GwPriority` of address networks (П42); a hung `awg show` marks AWG exits stale instead of failing every
  pass (П27); a working address is checked again soon after the system network restarts (П29).
- **DNS fixes**: DoH and DoT sockets use `TCP_NODELAY` (40–150 ms less per query, П3); at most 32 TCP connections per
  client and an idle timeout (П43); DoH bodies over 64 KB, more than 100 control frames or a bad PING are refused (П44);
  an HTTP/3 connection is replaced after 1000 queries (memory, П45); a service name keeps one address (`min`), so the
  proxy isn't reloaded for a reordered answer (П47); a rule's own DNS whose first server is down is asked second for 60 s
  (П30); the open files limit is raised.
- **Sign-in and web**: an empty password or session key file is made again (written atomically, П15); failed sign-ins
  count per /48 too (32), with one Telegram message per network (П16); `/api/restore` and `/api/backup/decrypt` take
  backups up to the backup limit through the middleware (П26); a full disk is "507 out of disk space" (П56); a body
  that stops arriving is "408" (W6); wrong types in a backup are a clear refusal, and restored files stay 0600 (П57).
- **Telegram**: a changed bot token resets `offset` (П28); **Direct — main** goes from the main address (П53); exit names
  with `&` and `<` are shown right, the status picture fits plain DNS, a refused saved picture is uploaded again
  instead of "Couldn't", and after a Chat ID change the bot no longer deletes a message in another chat (П54); the
  memory of sent notifications is pruned.
- **Interface**: Persian isolates `vpn://`, `.conf`, `socks5://` (П38); messages in a window are at its top and close on
  click (П39); the rule window fits a phone (П40); route check says a cloud service address is closed and names
  **Direct — address** in a balance step (П50); errors of **Apply rules again**, **Sign out**, **Generate new** are shown
  (П59); an expired session closes the window over the window (П60); typed fields survive closing a window (П61); an
  empty client name says so, and the client window isn't saved twice (П62); contrast of warnings, muted text and dark
  buttons (П63); **Add exit** on **Overview** opens the window (П64); the proxy port, quota and non-JSON errors are
  clearer, and one typed letter no longer switches an exit to SOCKS5 (П65); deleting a client drops lists of its own
  rules (П55).
- **Faster** (full audit, optimization): address parsing is cached (`srcaddr._ipv4`), API answers are encoded by the C
  encoder with `Msg` as `default` (same bytes), a pass makes one full state copy instead of four (`Store.peek`) and
  computes client policies once; client speeds are measured and sent only for the **Clients** tab (`X-Speeds: 1`).
- lego (the program that gets the HTTPS certificate) 5.6.0 → 5.7.0 (#55): new DNS providers and small fixes;
  the flags the panel passes are the same.
- Going back to 1.24.x: Direct with an address goes from the system address there (not blocked), exits connect from
  it too, and addresses the panel added stay in the system until a reboot (the container mode's Docker networks stay
  until removed: `docker network disconnect zz-awgr-out-N <AWG container>` and `docker network rm zz-awgr-out-N`; they
  carry no traffic there). An incoming IP the panel added to the system works until a reboot. DNS on the server stops
  catching other DNS servers' queries.

## 1.24.0 — 2026-11-25

- **No traffic past the exits while default load balancing starts**: with no balanced exit up yet, `default_out` took
  **If all exits are unavailable** (the routing default) even while exits were still connecting after a panel start —
  with Direct there, past the exits for a few seconds; now it blocks until they answer, as a single exit does since
  1.23.0.
- **Traffic by rule** (#54, Alex4003). **Routing** shows this month's ↓ ↑ under each rule and **Default** (all clients
  with the shared rules); the client window shows the client's traffic by each of its rules, this month and last. How
  it is counted: every line of a policy chain sets a conntrack label with the rule's number (its place among the
  client's enabled rules; 63 — **Default**), and a separate table `awgr_racct` (forward hook, `filter + 11`) counts
  bytes per client address and number in dynamic sets (`ipv4_addr . mark`, counters). Like `awgr_acct`, its chains are
  rewritten and its sets kept (`add set`), so counters survive a new ruleset. `sniproxy.py` counts its connections
  itself by `client|exit|number`; a QUIC verdict carries the number + 1 in bits `0x3F000000`, and the chain `q_lab`
  sets the label and takes the bits off before routing — the proxy adds them only after a ruleset with `q_lab` is in
  (`_qlab_key`), and `c_forward` rejects a client packet that still has them. The kernel is checked once per server
  (`nft -c`): without labels (some OpenVZ/LXC) there is no traffic by rule and the panel says so; everything else is
  as before. Rules put in before the panel (`_save_hold`) never use labels. `traffic.json` gets `rules`, `racct` and
  `by_rule` per client (two months); `FORMAT` stays 2.
- **Load balancing inside a rule** (#53, Alex4003): the rule's exit can be **Load balancing** with ticked exits. Each
  rule (a client's own rule — each client and rule) has its own `Balancer`: its clients are those going by the rule,
  their rates are their traffic by the rule, an exit's load is all its traffic (from the default balancing). Open
  connections stay on their exit (`Sticky` for address rules; domain rules get the assigned exit); while a ticked exit
  is still connecting, the rule's traffic is blocked, and with none working it goes to the rule's own fallback (Block
  by default). Fields `balance` and `balance_fb`; `outbound` is the first ticked exit, so an older panel sends the rule
  through it. The rule row shows how many clients are on each exit, the client window — the exit "now", the route
  check — the step.
- **Client rules on Routing**: a new section lists the clients with their own rules, and they can be added (**+ Add
  rule** with a client picker; a client on the shared rules gets a copy of them with the new rule last — without the
  shared rules' monthly and speed limits, which belong to the shared rule and all its clients together; the client
  window copies them the same way), edited,
  deleted, or the client sent back to the shared rules. The rule window of a shared rule shows the clients that used
  the most by it this month (`GET /api/rule-top/{id}`).
- **Monthly limit per rule**: GB per month for all clients of the rule together (a client's own rule — that client),
  with the same choices as an exit's limit: Direct, Block, another exit or only a notification. Events at 90% and when
  it is used up; back to normal on the 1st (UTC). Fields `quota`, `quota_action`, `quota_hit`, `quota_warned`. A domain
  rule with a limit (or a speed limit) keeps the proxy even when it leads where **Default** does, otherwise its traffic
  could not be counted. A new limit or action clears the marks (`keep_quota_marks`), as an exit's does; an exit chosen
  for a used-up limit is one of the exit's references (`Store.outbound_refs`, `replace_outbound`).
- **Speed limit per rule**: `rate_down`/`rate_up` in Mbit/s for all clients of the rule together. One nftables `limit`
  per rule and direction (`rl_<j>_d`, `rl_<j>_u`, no `burst` — the kernel keeps a second's worth anyway); what is over
  it is dropped where packets arrive: in forward for transit traffic and in input for `sniproxy.py`'s connections (from
  the client and the site's replies). The sender sees ordinary loss; dropping what the server itself sends would make
  TCP wait for a timer. A connection of a limited rule gets labels 64 + j and 127 ("limited": other traffic costs one
  label test) — from the policy chain, from the QUIC verdict (bits `0x00FF0000`, `q_lab`) or from the proxy's socket
  marks (same bits; the `type route` chain `rl_lab` in output sets the labels and takes the bits off before the route is
  chosen again). `rl_lab` is in every ruleset with labels, the proxy uses the bits only after such a ruleset is in
  (`_rlim_key`), and `c_guard_post` drops a packet that still has them: an exit mark with extra bits would not match
  the exit's `ip rule`. Both `rl_lab` and that guard look only at the panel's own marks (`RULE_LIM_OWN`: an exit, a
  proxy policy, or the tag `0xE1F0` that a proxy socket without a mark of its own carries with the number): on a server
  on the host they see every program's packets, and Tailscale keeps its own marks in the same byte (`0x40000`,
  `0x80000`). A rule keeps its number between passes; new numbers go round, so a freed one comes back only after the
  others (labels stay on open connections); more than 63 limited rules — an event. A kernel without nftables `limit`
  turns rule speed limits off with an event; an apply error that only mentions a label or a limit turns them off only
  if the same ruleset without them passes `nft -c`. Uninstalling removes `awgr_racct` too. On GitHub's runners: 11.8–11.9 of 12 Mbit/s down and 5.45 of 5 up (measured from the
  first byte), transit and the proxy together 9.4–9.8 of 10; transit through a SOCKS5 exit gets 66–79% of the limit
  (hev's TCP takes losses worse). Kernel CPU time of forwarding: +2–3% with another rule limited, +4–7% under a limit.
- **Let's Encrypt through Cloudflare DNS** (the idea: PR #51, zabit-z). In **Domain and certificate**,
  for a domain (not an IP), **How to verify the domain**: through port 80 as before, or through Cloudflare with an API
  token (Zone → Zone → Read and Zone → DNS → Edit). `lego run --dns cloudflare`, the token only in lego's environment
  (`CF_DNS_API_TOKEN`), never on its command line or in the status; one name (the domain), no port 80 check and no web
  server step; the usual 90-day profile unless `ACME_PROFILE` is set explicitly (renewal depends on an outside API and
  the token, so the longer certificate leaves time to notice). Before saving, the panel checks the token against the
  Cloudflare API (`tlsmgr.cf_check`: the zone of the domain or its nearest parent is visible, its DNS records are
  readable) and marks the field on an error. The token lives in `tls.json` with the other per-server HTTPS settings —
  now written `0600`, not in backups — and is removed on going back to port 80 or to an own certificate. Not a way to
  put the panel behind Cloudflare's proxy: the hint asks for a DNS only (grey cloud) record.
- **Monthly totals in Telegram** (off by default, also after an upgrade): on the first pass of a month the bot sends
  last month's server total, exits and Direct, and the top general rules with **Default**. Once a month (`report` in
  `traffic.json`); the first run after an upgrade only remembers the month.
- **The bot's main menu is a picture with live numbers** (owner's request). Instead of the logo with a caption, the menu
  message is a PNG drawn by the panel (`app/tgcard.py`): the VPN server's address (`client_host`, the one in clients'
  configs; it was "Host", the panel's `public_host`), **exits online** of the enabled ones (green — all, orange — some,
  red — none, "none" without exits; online is what the exits screen marks 🟢: healthy and under its quota), the panel
  version, clients, clients online and all-time traffic. The caption is empty (a note such as "Backup sent" stays there).
  **Refresh** draws it again; the same numbers keep the picture and only edit the caption. Other screens (Clients,
  Exits, Panel…) keep the menu picture above their text, as they kept the logo.
- **Server → Status is a picture too**, in the same list style: a green "Running" or red "AmneziaWG server unavailable"
  mark, panel version (with "1.24.1 available"), AWG version, engine, IPv4, IPv6, DNS on the server (with its counters or
  "DNS servers don't answer" under the name), uptime, RAM, clients online and traffic this month. The **Host** line is
  gone. The picture replaces the menu's in the same message (`editMessageMedia`, `notify.edit_photo`); the next screen
  puts the menu picture back by its `file_id`, without an upload.
- How it is drawn: the standard library has no fonts, so `tools/tgcard_atlas.py` renders every fixed word of the
  pictures in Chrome (Golos Text and Vazirmatn from `app/static/fonts`, Noto Sans CJK SC for Chinese; Persian already
  shaped and right to left), the ASCII characters and the icons, and writes their alpha masks to `app/tgcard.atlas`
  (~520 KB). The panel only lays them out and colours them with `bytes.translate`: ~15 ms for the menu and ~20 ms for the
  status on one core; the atlas is read per picture, nothing stays in memory. Values (addresses, numbers, versions) are
  built from ASCII glyphs; an address that doesn't fit gets smaller, then is cut with "…". If a word is missing (texts
  changed without running the tool) or anything fails, the bot sends the screen as text as before — now with
  "VPN server" and "Exits online" and without "Host". `AtlasTest` fails until the tool is run again.
- A new install with `curl … | bash` no longer ends with `curl: (23) Failure writing output to destination`: the
  installer restarts from its downloaded copy (`exec … </dev/null`) and left the rest of itself unread in the pipe; now
  it reads it off first — not from a terminal (`bash -c "$(curl …)"` has no pipe, and the read would wait). The
  install itself was fine.

## 1.23.1 — 2026-11-21

- **The clients list no longer fills the browser's memory** (found by the optimization part of the full audit). Every
  poll that redrew changed rows of the clients table kept the old rows: the click handler of a new row was an arrow
  inside `patchClients`, so it held that call's scope (`rows` — the previous rows, `was`/`now` — the previous state), and
  that row's handler held the next one, in a chain. A page left on **Clients** grew by ~70 MB an hour with 50 clients and
  by ~20 MB a minute with 1000 (Chromium, garbage collected before each sample), without limit. Now
  every row shares one handler, `clientRowClick`; the page stays at the same size.
- **The panel opens faster over a slow link.** Pages refer to their scripts, styles, fonts and icons as
  `static/v-<tag>/…` (and `/s/assets/v-<tag>/…` on a client's page), the tag being a hash of the names, times and sizes
  of all static files (`App.static_tag`); such files are sent with `private, max-age=31536000, immutable`, so the
  browser no longer asks about each of them every time the panel is opened. Another tag, or none, keeps `no-cache` with
  the ETag as before; an update gives a new tag. Opening the panel again over a 300 ms link: 1.7 s with 16 requests →
  1.35 s with 3.
- **The route check no longer keeps domain lists in the panel's memory.** `domains.Matcher` kept a set of every domain
  list it had checked until the panel restarted: a 300 000-name list is about 36 MB on a 1 GB server. It now reads the
  list file line by line on each check (a fraction of a second for the largest list), with the same answer.
- **Python 3.15** in the panel image (Dependabot, #45) and in the tests (`setup-python` in `release.yml` and
  `net-tests.yml`; a rule test keeps them the same). The `lint` job of `net-tests.yml` now runs the unit tests too, so a
  branch is checked on the image's Python before it reaches `main`. Found that way: Python 3.14+ parses 100 000 nested
  JSON objects without `RecursionError` (the limit is the C stack), and the check after it in `Request.json` raised one
  instead — such a request body was a 500, it is 400 again.

## 1.23.0 — 2026-11-19

- **No traffic past the exit while the panel starts** (found by the full audit; also in 1.22.0). The rules put in
  before the tunnels start (`_hold_rules`) are built before the first health check, and `Engine.resolve` sent an exit
  with no health record to its fallback: with the fallback Direct (the default), after every panel restart, update and
  server reboot its clients went past the exit for 1–2 s (the test VPS: one probe past the exit each time; CI uses the
  fallback Block). Now an exit with no record is a block, like a `connecting` one; an AWG exit that waits for the
  server on the kernel module (`engine_pending`) is `connecting` too instead of `down`. `c_guard_post` drops every
  sniproxy.py policy mark (0xd100–0xe0ff), not only the first 256.
- **Safer defaults and client IPv6 closed** (owner's answers to the full audit, 2026-11-21). A new exit gets the fallback
  Block (`api/exits.py`, the exit window), a new rule — the exit Block (`openRoutingRule`, a client's own rules). A new
  AWG exit with own sites typed in no longer becomes the default exit by itself (`rdefAuto` in `js/exits.js`). With DNS
  on the server, names from domain rules get no HTTPS/SVCB records (`dnsproxy.T_HTTPS`): Chrome takes ECH keys from
  them, and with ECH the rule can't read the name. IPv6 forwarding from the clients' interface is refused by a separate
  table `ip6 awgr6` (`Engine._sync_v6`, best effort: a network without IPv6 just has none): a host server installed by
  another script gave clients IPv6 past every rule.
- **More fixes from the full audit (stage 2).** A damaged `state.json` is replaced by `state.json.bak` right away
  (`Store._read`), not at the first write: a failed write left no file, and the next start began with empty settings.
  Saving a client that was deleted on another device is refused (`err.client_gone`) instead of writing it back. DNS on
  the server skips its own address among the shared servers (it asked itself in a loop). A domain list link that
  answers empty counts as failed, so the list keeps its old content. Odd input answers 400 instead of 500 (a subnet in
  `/api/server/init`, «²» in a number, masking values that aren't an object, a non-ASCII cookie), and a port `1.5` or
  `true` is refused instead of becoming port 1. The installer: a failed `docker exec` into the AmneziaVPN app's container
  stops it instead of setting the container aside and making a new server; a move to the host cut off before the host
  config brings `-moved-` back; a new panel that doesn't start after an update falls back to the previous image; the own
  container update writes `data/port-change.json` before the stop, so `recover_renamed` brings back an update cut off
  before the rename; `awg-router info` without root asks for sudo. The install mark older than the system boot is stale
  (`selfupdate.installer_running`). `tests/fixtures/old/1.22.0` added; `make_old.py` creates the country lists itself and
  keeps a rule's `dns`.
- **Small things from the full audit** (owner 2026-11-21, group 1). Outdated texts (`ls.saved_busy`, `rt.leave`,
  `bk.enc_hint`); ready lists in a rule window show their kind; `badNumber` stops a save when a number field holds
  no number (the browser gave "" and the limit was removed); a long exit name ends with an ellipsis (`.line > bdi`),
  no sideways scroll on phones; `refreshKeep` keeps typed fields of other blocks of System after a block's save;
  `srvKeepTyped` asks to save typed Server fields before Generate, an engine switch, Hide and Restart; the bot's
  "+10 GB" shows `1010`, not `1e+03`; `notify.render` substitutes in one pass (a client named `{date}`);
  PersistentKeepalive over 65535 or a reversed range is refused.
- **The release build pins BuildKit and binfmt by digest** (full audit, Г8): `setup-buildx-action` (`driver-opts:
  image=moby/buildkit:v0.35.1@sha256:…`) and `setup-qemu-action` (`image: tonistiigi/binfmt:qemu-v10.2.3@sha256:…`)
  took their default tags, which can be moved to other code. Checked on a GitHub machine: amd64 + arm64 build.
- **Fixes from the full audit.** Backups up to 24 MB are accepted by `/api/restore` and `/api/backup/decrypt`
  (`backup.BACKUP_BODY`; a password-protected backup over ~3 MB hit the 4 MB request limit). Client config values
  refuse every line break `str.splitlines` knows (U+2028 and others), not only `\n`/`\r`. A 2FA code in Persian,
  Arabic-Indic or fullwidth digits is accepted (browser `codeDigits`, `totp.match`; before, the browser dropped them
  and the API answered 500). The panel domain, extra addresses and the address in configs refuse an IPv6 zone (`%…`:
  `ipaddress` takes any text there, and the domain goes into the web server's config). The self-signed certificate is
  written to temporary files first and its CN is cut to 64 characters (a longer domain left a new key with the old
  certificate, and the panel didn't start again); a key that doesn't match its certificate is regenerated instead of
  stopping the panel. A refused `setMyCommands` (a channel in Chat ID) no longer stops the bot's polling. Turning 2FA
  off syncs its folder. The test for repeated top-level names covers `theme.js` and `qrcode.js`.
- **Rules in their own window, lists inside rules.** The Routing tab has no separate Lists section any more. A rule
  opens in a window (**+ Add rule**, or a click on the rule row; `ruleWindow` in `js/routing.js`, a second `dialog`
  `#modal2` so it also opens over the client window): name, lists — an existing one or a new list made right in the window,
  without a second window; a country's list is just a list there (no domain rule, no DNS on the server: ready rules are
  only the **Apply for …** buttons, owner 2026-11-20; `countryPick` is gone) — the own
  DNS field, shown only when the rule has a domain list, the exit and on/off. On Routing, **Save**, on/off, order and
  delete take effect at once (`saveRules`; while one is saved the rows take no clicks, and the poll redraws them when the
  rules changed in another tab); "Default" (was "Everything else"), balancing and "block" keep the save bar. A client's own
  rules use the same window, with **Done** putting the rule into the client draft. A list that is no longer in any rule
  is deleted with it on the server (`api.routing.drop_unused_lists`, from `PUT /api/routing` and `PUT /api/clients/<pk>`;
  an exit forgets its own-sites list then), and lists made in a window that was cancelled are deleted by the browser
  (`dropNewLists`; `POST /api/country-preset` now returns `made`), as are lists made in a window that did not end up in
  its rule. **Apply for Russia / China / Iran** sit next to
  **+ Add rule** always (Overview keeps them only while there are no rules). "Refresh lists every, h" moved under the
  rules. A domain rule whose handler failed says so in its row.
- **The bot tries other paths when the chosen one fails** (System → Telegram → "If it fails, try other paths",
  `telegram.fallback`, on for everyone). For every Bot API request (`notify._post` → `notify.Paths`): chosen Direct —
  the working exits one by one; chosen exit — the other working exits, never Direct (`engine.own_route(via,
  direct=False)`: an exit whose fallback is Direct counts as down for Telegram). A path that worked is kept and the
  chosen one is tried again every `PATH_RETRY` (10 minutes); Telegram's own answers — refusals, 429, 5xx — don't switch
  paths; `/api/state` has `tg_path`, and the settings say
  "The bot now goes through …". This covers notifications, control, messages to clients and backups — before, only
  notifications had fallbacks, and Direct was their last resort.
- **Live speed of clients.** The clients list shows ↓/↑ Mbit/s under "online" (`engine.client_speeds`: two samples
  of `awg show dump` at least `CLIENT_SPEED_EVERY` apart, taken only when a browser asks, in their own thread: a poll
  waits at most `CLIENT_SPEED_WAIT`, so a hung `awg show` doesn't make the panel look offline). `speeds` comes with every
  `/api/state` answer, the short one too, outside the tag, and only the speed spots are refreshed (`fillSpeeds`), not
  the rows.
- **DNS encryption stays on after "Apply for …".** The country buttons turn DNS on the server on with only
  `{panel_dns: true}` (`panelDnsOn`), and the encryption wasn't written, so the next panel start (an update, a
  reboot) took it for DNS on the server turned on before 1.16.0 and set **No encryption** (`Store._upgrade`). Now
  `users.update_server` writes the encryption in effect (DoH by default) when DNS on the server is on without one,
  and a missing one becomes "plain" only in files from before 1.21.0 (`Store.missing_dns_enc`, by the
  `rule_names` mark; backups too), "doh" otherwise. Installs that pressed a country button in 1.22.0 and restarted
  since keep "plain": the release notes ask to check Server → DNS query encryption.
- **Engine switch without "Error".** After switching the engine or **Restart the AWG server** the header says
  "Switching the engine…" / "Restarting the AWG server…" until the first good pass with the server interface up, at
  most `SETTLE_SECS` (90 s) (`Engine._settle`, `_pass_done`); passes that fail while the server comes up on the new
  engine no longer show "Error" for ~30 s. The engine row says "starting" meanwhile.
- **Telegram settings, simpler.** **Turn on the bot** (`enabled`) is now the main switch: off — no notifications,
  control, clients or backups (`tgbot.admin_on` / `clients_on`). **Control from Telegram** is one checkbox right under
  it, without its own section and hint; "Notify about" is **Notifications**; client access and reminders are one
  checkbox (`client_notify` is written the same as `clients`, for a rollback). A token is needed to turn the bot on, a
  Chat ID only for notifications, control or backups (a bot just for clients works without it). Bots that had control
  or clients on with notifications off get `enabled` once (`store.BOT_SWITCH`) — they start sending notifications.
- **Server tab, by meaning.** Left: the AmneziaWG server, its addresses, address in configs, port, subnet, MTU and
  PersistentKeepalive; right: **DNS**. "below" is gone from the external address hint, and the "AmneziaWG engine — what
  it is and when you need it" box is gone.
- **Plain exit names.** Exit choices say "Germany", not "Via “Germany”" (rule window, client window, Telegram);
  the Overview title is **Traffic exits**; "Everything else" is now **Default** ("when no rule matches"). The
  example in a domain list starts with zones, then sites, then a link. The expiry date field looks like the other
  fields (it was light in the dark theme on Android), and a field next to a taller one no longer stretches.
- **The engine block follows the server.** Server → AmneziaWG engine is redrawn by the poll when it changes
  (`drawEngine`; the rest of the tab still isn't, for its fields): after an engine switch it showed the old engine and
  no pressed button until the page was reloaded.
- **Client window → Manage.** "This month by exit" is a column next to the totals ("Traffic this month", "All time"),
  one exit per line (`trafficHtml`), instead of full-width rows under them: with balancing over many exits it no longer
  stretches the window. **Delete client** moved from Manage to the bottom of the window, on the left next to
  **Save**, like **Delete rule** in the rule window (on a narrow phone the label wraps inside the button); the question
  before deleting is just "Delete client “name”?".
- **Routing.** **+ Add rule** and **Apply for …** sit in their own row under the "Shared rules" title in every
  language: in the title row, next to a short subtitle (en, zh), they used to slide to the right of the page. On a
  phone they form two even columns.

## 1.22.0 — 2026-11-19

- **Clients in the Telegram bot.** Every client gets a personal link as soon as it is created (`users.add_client`
  writes a `shares` token in the same mutation); clients made before 1.22.0 get a **Create link** button. The same token is
  the client's bot invitation, `https://t.me/<bot>?start=<token>` (`clients.bot_invite`, `bot_url` in the client rows;
  the bot learns its name with `getMe`). A client who opens it sees in a private chat with the bot what the personal
  page shows — status, traffic, expiry and quota — and gets the config (QR, file, `vpn://`), nothing else of the panel;
  the bot writes first only with reminders (below). Chats are bound in `tgbot.json` (`links`: chat → client and token, at most
  `LINKS_MAX`), not in `state.json` or backups, and the token is checked against `shares` on every message: **Renew**
  in the client window (`POST /api/shares-renew/<pk>`) replaces both the link and the invitation, and a chat bound to
  the old one is let go. The texts follow the client's Telegram language (ru, zh, fa, else en). One reply per second
  and one config per 30 s per chat; a chat without an invitation gets its hint at most once in `DENY_EVERY` (10 minutes,
  like "no access" before), so many such chats can't use up the bot's sending limit. Both links now live in the client window's **Connect** pane, under the QR and the
  `vpn://` button; **Revoke** is gone. The switch is **System → Telegram → Clients can check their access in the bot**
  (`telegram.clients`, on by default); the bot now polls when it is on even with control off. Installs before 1.22.0
  that use the bot for notifications only get it off once (`store.CLIENT_BOT`), since that bot may be read by another
  program. The bot's command menu is set only for the panel's chat (`BotCommandScopeChat`); the menu that 1.9.0–1.21.0
  set for every private chat is removed once.
- **Reminders to clients in the bot** (System → Telegram → "Remind clients in the bot about the end date and limit",
  `telegram.client_notify`, on by default). A client bound by an invitation gets in its chat: 3 days before the end
  date (`rm_expiring`), at 90% of the traffic limit (`rm_quota_warn`), when access is turned off by the end date or the
  limit (`rm_expired`, `rm_quota_month` / `rm_quota_total`) and when a monthly limit lets it on again
  (`rm_quota_reset`), each with a Refresh button. The same engine events as the owner's notices about clients
  (limits.py raises each once): `Notifier.engine_event` hands those with a `pk` to `Notifier.client_fn` =
  `Bot.remind`, which only queues them; the `tgbot-remind` thread sends to every chat in `links` bound to that client
  with a live token, in the chat's language. Each reminder is built from what the client has now (`share_info`): one
  that no longer fits (extended, on again) is not sent. Telegram unreachable — the rest waits (`REMIND_PAUSES`), a chat
  already sent to is not sent again, older than `REMIND_AGE` (a day) is dropped; a refusal (the client deleted the chat)
  skips that chat. Off, without the token or with clients in the bot off — nothing is sent. Only clients with a bound
  chat are queued, the same reminder to the same client goes at most once in `REMIND_REPEAT` (an hour: limits.py raises
  the event again every pass when its marks can't be saved, e.g. a full disk), new events don't cut the pause while
  Telegram is down, and "ends soon" / "90%" are checked against the window and the threshold again when sent (an
  extended date or a raised limit is not reminded). *Test:* `ClientReminderTest`.
- **Telegram group became a supergroup.** Telegram gives such a chat a new number and refuses the old one with
  `migrate_to_chat_id`; notifications used to stop silently. `notify.send` and file sends take the new number into
  the settings (only if the old one was there) and send again; the bot does the same on the service message
  (`migrate_to_chat_id` / `migrate_from_chat_id`).
- **Two programs reading one bot.** `getUpdates` 409 "terminated by other getUpdates request" now shows a clear
  error in the Telegram settings (`err.tg_conflict`: usually a second panel with the same token) instead of
  Telegram's English text.
- **The bot speaks in phrases.** Errors from the panel were sent as their keys (`srv.subnet_full`). `app/uitext.py`
  reads the browser's dictionaries from `i18n.js` (strings and plural forms, reloaded when the file changes) and the
  bot translates panel messages with their parameters into its language.
- **Two-factor sign-in.** Wrong codes after a right password are counted from all addresses together
  (`auth.CODE_MAX` per `CODE_WINDOW`), so a known password no longer lets many addresses guess the six digits in hours;
  past the limit code sign-in is closed for everyone until the window ends (`err.code_locked`). The owner gets a
  Telegram notice (`login_code_wrong`, `login_code_locked`; with sign-in notifications on, once in `CODE_WINDOW` per address). Turning 2FA on needs the panel
  password, so a stolen session can't lock the owner out with its own code.
- **Big network lists by link use a fraction of the memory.** Networks were kept as `IPv4Network` objects and merged
  with `collapse_addresses`: 300,000 lines took about 300 MB (a million — 1.7 GB), on a 1 GB server enough for the
  kernel to kill the panel. `lists.Nets` keeps merged ranges as numbers in `array` and gives the same minimal CIDR set
  (300,000 lines: about 10 MB on top of the downloaded text).
- **Server name in the browser tab (#38).** The tab shows the server's address, or a name set in **System → Settings →
  Server name** (`settings.panel_name`, up to 40 characters, checked by `checks.panel_name`). Like the server's
  addresses, it belongs to this server: a restored backup keeps the current one. Thanks to @MacSergey.
- **Day/night button in the header.** `static/theme.js` (loaded in `<head>` of the panel and of the personal page)
  sets `data-theme` from the button's choice (kept in the browser's `localStorage`) or from the system; styles,
  QR codes and the phone's browser bar follow it. Thanks to @paris19891 for the idea.
- **Clients' right column on a phone** (exit and "assigned manually") sits at the right edge like the month's traffic,
  so exit chips no longer jump from row to row.
- **Third-party code only by fingerprint.** The build fetched amneziawg-go, amneziawg-tools and hev-socks5-tunnel by
  tag name and took base images by tag: whoever can move a tag (or steals the account) could put other code into the
  release unnoticed. Sources are now fetched by a 40-character commit hash and checked with `git rev-parse`
  (hev's submodules are pinned by its own commit), images — by `@sha256`; `ProjectRulesTest.test_foreign_code_pinned`
  checks both Dockerfiles and that the AmneziaWG versions in them match.
- **amneziawg-go v3.1.20261116** (was v3.1.20260828), in the panel image and in the own AWG server image: fixes
  only — junk packets with `Jmin` above `Jmax` are refused instead of an underflowing size, a negative length in the
  `<r>`/`<rc>`/`<rd>`/`<dz>` tags of I1–I5 is refused, I1–I5 and S4 can change while handshakes are sent, a timer race.
- **A weekly check for new upstream versions** (`.github/workflows/upstream.yml`, `tools/upstream.py`): it compares
  the pinned amneziawg-go, amneziawg-tools, hev-socks5-tunnel and lego with the tags of their repositories and keeps
  one issue open with what is new (also a pinned tag moved to other code); nothing is updated by itself. A version
  held back on purpose is in `upstream.SKIP` (hev 2.20.0).
- **hev-socks5-tunnel 2.19.3** (was 2.9.3), pinned by its commit, with the fixes of ten releases (UDP among them).
  2.20.0 is held back: in the network tests a SOCKS5 exit under a speed limit got 2–12 Mbit/s instead of about 16. A
  run over the commits between 2.19.3 and 2.20.0 points at the hev-socks5-core update (`8e3b4cd`). Newer hev writes no
  log by default, so the panel asks for `log-file: stderr` (the reason of a failed start comes from there).
- **The panel's own AWG server image is built here and updated with the panel.** It was
  `amneziavpn/amneziawg-go:latest` (Alpine 3.19, no longer patched) and `awg-router update` never replaced it. It is now
  Alpine 3.24 with the same amneziawg-go and awg as the panel image. On an update the installer
  (`refresh_own_server`) re-creates the panel's own container from the new image with the same keys, clients and port
  (`awg-server/data`), so clients reconnect within seconds and keep their configs; if the new one doesn't bring `awg0`
  up, the old container is started again. The AmneziaVPN app's container is never touched.
- **"Find" for the Chat ID works while the bot is running.** A bot that already reads its messages (control or client
  invitations) takes them before the button could see them, and "Find" said no messages were found. The bot now
  remembers the last chat that wrote to it (`Bot.last_chat`, for 10 minutes) and the button uses it (`notify.chat_of`).
  A client's chat is never taken (`Bot._seen`: no button presses, no chat bound by an invitation, no `/start <token>`),
  neither from `last_chat` nor from the updates the button gets itself (`notify.detect_chat(accept=…)`: a bot that
  doesn't read messages, or waits after a 409, leaves them to Telegram): saved by mistake, it would get the
  notifications, the control and the backups with every key.
- **The bot keeps quiet in groups.** In a group where it sees all messages it answered every phrase with its menu;
  now only commands, a mention of `@bot` or a reply to its message get an answer.
- **The bot's ssh command names the right user and port.** With access through an ssh tunnel, **Panel** in the bot
  always said `root@<server>` on port 22, while the installer already printed the user behind sudo and `-p` for
  another port. The installer now also saves the port (`SSH_PORT` in `.env`, next to `SSH_USER`; when it can't tell
  the port on an update, the saved one stays), and the bot takes both (`config.SSH_USER`, `config.SSH_PORT`; a value
  that isn't a user name or a port means root and 22). The bot shows it after the next `awg-router update` or install.
- **A list edit without a name keeps the name.** `PUT /api/lists/<id>` with only the text used to be refused with
  "name required"; the panel itself always sends the name, so only hand-made requests saw it.
- **SOCKS5 exit health is checked from the AWG server's network** (`socks.check_in`), where hev-socks5-tunnel connects
  from, not from the panel's: a proxy on the VPS's own `127.0.0.1` showed as working although the AmneziaVPN container
  can't reach it, and the other way round. The proxy's name is resolved in the panel, the password goes through stdin.
  A network test checks both sides.
- **Many clients switched at once.** Expiry and quota used to turn clients off one by one, each with its own write of
  the server's files and `awg syncconf` — about 25 s for a thousand clients with one end date, with adding a client
  blocked meanwhile. A pass now switches them in one write (`ServerManager.set_enabled_many`).
- **The port of a server in a container can be changed** (Server → Port (UDP)), for the panel's own container and the
  AmneziaVPN app's. Docker publishes the port when the container is created, so `system.recreate_with_port` stops the
  container, renames it `<name>-old-<time>`, creates a new one from `docker inspect` (`recreate_body`: same config and
  host config, `old/udp` → `new/udp` in `ExposedPorts` and `PortBindings`, unnamed volumes carried as binds, other
  networks connected after create with their addresses) and waits for the interface (`PORT_UP_SECS`). A container
  without the server folder on the host's disk (AmneziaVPN) is first committed (`awg-router-port:<time>`), so its
  files and `clientsTable` stay. The old container is removed only when the new one is up; otherwise the new one is
  removed and the old one gets its config back (`PUT …/archive`), its name and restart policy, and starts
  (`srv.port_failed` on the port field). `docker_api` sends a body (JSON or tar). Before the change the browser warns
  when clients made in the app (their key only on the device) would stop connecting (`srv.confirm_port_app`).
  `srv.port_locked` / `srv.port_container` are gone; the port hint says the server restarts for a few seconds.
  *Tests:* `ContainerPortTest`, `container_e2e.py` (own container, AmneziaVPN-like container with a second network,
  busy port → old container back). A change cut off midway (panel killed, VPS off) — or an update of the own container
  by the installer with ssh dropped — left the server stopped as `<name>-old-…` / `<name>-prev-…` with no restart
  policy, and the VPN was down until fixed by hand: in container mode the panel now renames it back, sets the restart
  policy and starts it (`system.recover_renamed`: only when no container has the usual name, the installer isn't
  running and the old one has been stopped for `RECOVER_AFTER` s), with `ev.container_recovered` and a Telegram notice.
  The config with the new port is written before the container is re-created, so `recreate_with_port` keeps the old
  one in `data/port-change.json` (root only) while it runs, and the recovered container gets it back — otherwise it
  would listen on the new port behind Docker's old one. A change cut off before the rename (stopped, restart policy
  `no`) is brought back the same way. An `-old-` container without that mark (the installer keeps one on purpose
  when it puts a new server in place of a broken one) is left alone, and the mark goes once the server runs under its
  usual name. *Tests:* `RecoverRenamedTest`, `ContainerPortTest`.
- **"You have unsaved changes" sits at the top** of the Routing and Server tabs, right under the tab row
  (`position: sticky`, `top` = the tab row's height from `--tabs-h`), for as long as there is something to save; at
  the bottom it went off the screen with its section. "Save first" now flashes it (`flashBar`) instead of scrolling.
- **Refresh lists every, h** moved from System → Settings to the lists section on Routing (saves with its own
  button, shown when the number changed; Enter saves too). The lists subtitle no longer repeats the hours.
- On a phone the buttons of a table row (`td.acts`, `width: 1%`) were a 1% wide grid cell and stuck out past the
  right edge: the Routing tab scrolled sideways.
- The day/night button draws its sun and moon (`THEME_SUN`, `THEME_MOON`) instead of `☀` / `☾`: Android fonts set
  those below the middle of the line. The server name hint is shorter.
- The bot's menu picture (`static/icons/tg-logo.png`) is on a white background, 1200×780 (was 1200×520 on black).
  The saved Telegram `file_id` is tied to the picture's fingerprint (`tgbot.logo_sum`, `logo_sum` in `tgbot.json`),
  so after an update the bot uploads the new one once instead of showing the old one forever.
- A client's card in the bot starts with `cd_title` ("Your access"), not the name the owner gave the client; the QR
  and the file go with `cfg_caption_me` / `cfg_file_me` without the name. Card lines have icons (traffic, end date,
  limit, app-made client, hint), also in the panel chat's client card. Saving the Telegram settings says "Bot settings
  saved".
- **Own DNS of a domain rule** (`dns` in a rule: up to two IPv4, `checks.rule_dns`; written only when set, so state
  and backups without it are as before). `_policies` keeps every domain rule in order with its DNS (`"dns"`, only when
  one has it — not dropped with `domain` when the rule leads where everything else goes), `nftgen.layout` carries it
  (the policy key changes only for such policies), `dns_domains` gives dnsproxy.py `[lists, route, servers, to set?]`
  ("to set" only for rules nftables redirects, or an address would go to sniproxy without a rule), and dnsproxy.py asks
  those servers by plain DNS on the rule's path; the cache key includes them. Works with DNS on the server. While the
  rule has no path (its exit is connecting, down or "Block") the own DNS is not asked — the names would go the client's
  way, often direct, as plain DNS past the exit — and the shared servers answer as before 1.22.0; an own DNS equal to
  the address this DNS listens on is skipped (it would ask itself). *Tests:* `RuleDnsTest` (check, engine, a real
  dnsproxy.py process with a dead DoT upstream and a live own server, a down exit, the server's own address, the cache).
  Saving rules from the panel (general and a client's own) refuses an own DNS equal to the address DNS on the server
  listens on (`engine.dns_listen()` → `checks.rules(…, self_dns)`), with `err.rule_dns_self` at that rule's field
  (`data-field="rule_dns_<i>"`; the other own DNS errors are marked there too); backups and exits are checked without
  it, as before. *Test:* `RuleDnsTest.test_own_server_address_refused_at_the_field`.
- **Ready rules for Russia, China and Iran; a new install starts empty.** A new install has no rules and no lists
  (`DEFAULT_STATE`; before, the country lists `ru`, `cn`, `ir` and the rule `r_geo` "→ Direct", downloaded every day
  even if unused). Updated installs keep what they have. `app/countries.py` holds the presets: zones (`.ru .su .рф`,
  `.cn .中国 .中國`, `.ir .ایران`) and the country's DNS (Yandex 77.88.8.8/77.88.8.1, Alibaba 223.5.5.5/223.6.6.6,
  Shecan 178.22.122.100/185.51.200.2). `POST /api/country-preset {cc, apply?}` makes the country list (id = the code)
  and the domain list named by its zones (or takes one with the same domains); with `apply` it adds two Direct rules
  at the end: the domains with the country's DNS and the addresses. Overview → Shared rules shows "Apply for Russia /
  China / Iran" (all languages, the interface language's country first) only while there are no rules at all. In a
  rule, "+ list" always offers the three countries; picking one (or an existing country list of them) puts its
  addresses in this rule and a rule for its domains with the same exit and the country's DNS right below it. Both
  ways turn on DNS on the server (`PUT /api/server {panel_dns: true}`) when it is off; with clients already issued
  they first ask, since those configs keep the old DNS until imported again (the client window asks before it saves
  anything). A second press from another tab adds nothing. The hint says they are for a cascade. A domain rule is not
  intercepted when it, the address rules and the default all lead the same way (`Engine._policies`; before, any
  address rule kept the interception): on a new install, everything direct, a country preset doesn't send all web
  traffic through sniproxy.py. *Tests:* `CountryPresetTest`, `test_useless_domain_rule_skips_sniffing`;
  `tests/seed.py` puts the old country lists into the tests that rely on them.
- **DNS on the server when encrypted DNS is blocked from the server's country.** In Russia (DoH/DoT to Google and
  Cloudflare cut since August 2026), China and Iran the shared servers often don't answer over DoH/DoT on the direct
  path, and DNS on the server never fell back to plain DNS: clients going direct found no sites. Now the direct path
  (mark 0, no own DNS) asks the local DNS of the server's country by plain DNS (`direct_fallback` in dnsproxy.py's
  config = `countries.local_dns(engine.public_cc)`, the country from the "Direct" check), and doesn't wait for the
  encrypted servers again for `DIRECT_RETRY` (120 s); then one query tries them in the background, and clients keep
  getting the local answer meanwhile (DoH from Russia hangs until the timeout: tried with a client's query, names on
  the direct path stopped for ~10 s every two minutes). A SERVFAIL from the encrypted servers is an answer (a broken
  site), not a failure. Paths through an exit never fall back (names would go past the exit), and neither do names of
  a domain rule without a path (its exit connecting, down or "Block"; such rules now reach dnsproxy.py without the
  DNS filter too). New servers or a new encryption mode forget the old failure. Server → DNS on the server says when
  encrypted DNS fails directly (`direct_down` in `dns_view`, not with "No encryption"), with the local DNS used or,
  for other countries, what to do. The server's country is asked again in 10 minutes, not 6 hours, when the check
  found only the address. *Tests:* `DirectFallbackTest`, `ServerCountryTest`.
- **The client's name is not shown to the client.** The config file name and the `vpn://` description are
  `users.conf_label(pk)` — 8 digits from the client's key — everywhere (panel, bot, personal page); before, a Latin
  name was the file name and the name was the description. The personal page gets no name (`share_info` without
  `name`, `config` without `name`); its title and heading are `share.title` ("Your access"). The bot's "client
  linked" event takes the name through `ops.client_name`.
- "Show config" (personal page and client window): `.connect-actions` is `minmax(0, 1fr)` — a long `I1` line made the
  column as wide as itself and pushed the buttons past the card; the config is shown whole (`pre-wrap`,
  `overflow-wrap: anywhere`, no max height).
- Domain list window: the hint says a whole zone works (`.ru`, `.cn`, `.net`; a leading dot was always stripped), the
  placeholder shows it, and `ls.domains_how` keeps only what matters (ports, ECH, shared connections, no packet queue).
  The long `rt.strict_hint` under "If domain rules don't work…" is removed.
- A rule's number in the rule editor is a picker of its place (`re.position`), besides ↑ ↓. Examples in the list windows
  are per language (`ls.domains_name_ph`, `ls.domains_ph`, `ls.asn_name_ph`, `ls.asn_ph`, `re.dns_ph`).
- "DNS on the server" explanation: three short paragraphs (why; for a cascade, sites that go direct by an address list
  get the exit country's addresses — put them in a domain rule "Direct" with a local own DNS, since Cloudflare and Google
  are often blocked from the server's country; setup); `srv.panel_dns_how` and `srv.panel_dns_privacy` are gone (README keeps the details).
- No period right after a command in a hint (`pw.hint` ru, zh): it got copied with the command. *Test:*
  `test_no_period_after_a_command`.
- Interface terms made consistent: the server is "the AmneziaWG server" in status, banner, events and System, the
  container mode is "Docker container"; the empty client and exit list hints say what to do in the panel. The README
  intro starts with the panel's own server. Unused `cl.empty_hint` removed.
- An old (after **Renew**), deleted or mistyped personal link opens the personal page, which says "This link is not
  valid…" in the visitor's language (still status 404, the same page for every wrong token), instead of the raw JSON
  `{"detail": {"$t": "err.not_found"}}`; `web.Page` takes a status. An empty or 0 port keeps the port, and a wrong one
  (or 53) is marked at the field before the restart warnings — they used to end with "clients need new configs" for
  nothing. **Refresh lists every, h** refuses anything but a whole 1–720 instead of saving 1. The 2FA window keeps the
  typed code when the password is missing or wrong (the code isn't used up), Enter in the password field turns 2FA on,
  the key wraps between groups, and its step numbers follow the language. The country, ASN and "sites through this
  exit" examples follow the language too (`ls.cc_ph`); the Russian ASN example named Yandex is AS13238 only (AS47541 is
  VK). Persian texts of the client bot say «کلاینت», as the rest of the panel. The installer says "Found an AmneziaWG
  server in the Docker container" for any container, the panel's own included.
- **For GitHub's code scanning:** the exit check sets TLS 1.2 as the minimum explicitly (it was the default already),
  and the state fingerprint for polling is SHA-256 instead of SHA-1.

## 1.21.0 — 2026-11-17

- **Domain rules to any exit.** A domain list can now lead to an AmneziaWG exit, Direct or Block, not only to a
  SOCKS5 exit (`err.domains_need_socks` is gone). `sniproxy.py` already sent a matched site to its original address
  with an exit's mark when a SOCKS5 exit fell back (`Engine._sni_target`): for an AmneziaWG exit and Direct that is
  now the normal path, so the site goes to the address the device got from its own DNS (the hint suggests DNS on the
  server against spoofing); through SOCKS5 the proxy still gets the name. The exit window sets sites, domain and
  network lists and "everything else" for AmneziaWG exits too. Deleting an exit takes its own sites list with it,
  while shared lists go to the replacement. A domain rule that leads where everything else goes, with no address
  rules, no longer turns on the redirect of all HTTPS/HTTP into the handler (`Engine._policies`). The network
  tests check a matched site going through a tunnel exit by its mark.
- **HTTP/3 (QUIC) by site name.** Clients with domain rules no longer lose HTTP/3 for every site. The first
  packets of a new QUIC connection go to a kernel queue (`nft queue … bypass`, chain `c_quic`; `nfqueue.py` speaks
  nfnetlink_queue over a netlink socket with the standard library only), `quic.py` decrypts the Initial packets
  (v1 and v2; the keys come from the connection ID, RFC 9001 / 9369; AES from libcrypto through ctypes or pure
  Python; the GCM tag isn't needed for a routing decision), puts the ClientHello together from CRYPTO frames —
  Chrome with ML-KEM splits it across two packets and shuffles the pieces — and `sniproxy.py` answers with a
  mark: an AmneziaWG exit — its tunnel, Direct — `QUIC_DIRECT_MARK` (no ip rule, main table), Block and SOCKS5
  without the QUIC box (below) — reject (the browser takes HTTPS, where the proxy gets the name),
  a site not on the lists — `QUIC_PASS_MARK` and the usual rules. The decision goes into the conntrack mark
  (`QUIC_CT_BIT`) for the rest of the connection; repeated first packets of the same connection get the same
  answer. A ClientHello that doesn't come together in `QUIC_HOLD` and QUIC that isn't Initial are rejected, so
  a listed site never leaves through the wrong exit; no listener (`bypass`) means the old block. A kernel
  without `nft_queue` (some OpenVZ/LXC) fails to load the ruleset with the queue: the panel loads it without
  and says so once (`ev.quic_no_queue`); the domain list window shows that HTTP/3 is off. Tested on real
  Initial packets of Chromium 153 (v1 and v2, checked against the GCM tag) and in the network tests.
- **DNS on the server resolves names from domain rules through the rule's exit** (`dnsproxy.Proxy.domain_route`,
  `Engine.dns_domains`): the address isn't spoofed on the way and a CDN gives a node near the exit. Block rules
  and exits that are down resolve the usual way.
- **Optional DNS filter for domain rules** (Server → "Domain rules only for addresses from this DNS's answers",
  `settings.dom_filter`, works with DNS on the server): the handler gets only connections to addresses that DNS
  on the server returned for names in domain rules (the `dom4` nftables set, timeout = TTL but at least
  `SET_MIN`; after every rebuild of the table the panel sends SIGUSR1 and dnsproxy adds the live addresses
  back). Other traffic goes through the kernel without the handler, and HTTP/3 to it isn't touched. A device
  with its own DNS bypasses the filter — the hint says so.
- **QUIC through a SOCKS5 exit is a choice.** A SOCKS5 exit's window has "Let QUIC (HTTP/3) through the proxy"
  (`quic` on the exit, off by default). Off, UDP 443 to the exit is rejected (`o_uN` and `ob_uN`; in `ob_uN` after
  the line that keeps live connections on their exit), so browsers switch to HTTPS at once instead of waiting for
  QUIC through a proxy that may not carry UDP. This also covers clients whose main route is the SOCKS5 exit (their
  QUIC went into UDP ASSOCIATE before); other UDP goes through the proxy as before. On, QUIC goes through UDP
  ASSOCIATE, sites from domain rules included (the queue gives them the exit's mark, `Engine._quic_mark`). The
  exit check tells whether the proxy passes UDP: a QUIC packet with a version-negotiation version to 1.1.1.1 or
  8.8.8.8 port 443 has to get a Version Negotiation answer (`probe.py --udp`, only for SOCKS5 exits; also in the bot).
- **Exit check: honest latency, and the reason when the IP isn't found.** Latency is the time to the first byte
  of a TLS answer from 1.1.1.1 (or 8.8.8.8), not `connect()`: through SOCKS5 the connection is accepted by
  hev-socks5-tunnel on this server, which showed 0 ms. The external IP is asked from `https://1.1.1.1/cdn-cgi/trace`
  first (no DNS, port 443 — many proxies let only 80/443 through), then ipinfo.io and ifconfig.me; when none
  answers, "external IP is unknown" now says why.
- **The domain handler is watched every second.** `sniproxy.py` touches a heartbeat file every second; the panel
  looks at it and at the process every second (`Engine._watch_sni`) and restarts a handler that exited or whose
  event loop stood still for `SNI_HANG` seconds (before: on the next pass, up to `RECONCILE_INTERVAL`, and two
  minutes for a hang). While it is down the redirected connections are refused, not let through. A handler that
  keeps dying is started again once a minute, and the domain list shows when.
- **"If domain rules don't work, block all traffic of their clients"** (Routing, `routing.strict`, off by default).
  When the handler isn't running — it didn't start, crashed and waits for a restart, or the panel is stopped with
  "Block cascaded traffic" (also during an update) — the policies with domain rules turn into a block
  (`nftgen.generate(strict=True)`), instead of sending listed sites by the address rules and the main route. The
  header shows it as an error; the event log and Telegram say when it starts and ends (`ev.dom_strict_on` /
  `ev.dom_strict_off`). Not covered: a stop with "Send everything direct", and after a reboot until the panel starts
  with the AWG server in the AmneziaVPN app's container (the panel's own container and a server on the host apply
  the panel's rules before the server comes up, see below).
- **SOCKS5 exits start on Intel Xeon with AMX again** (broken since 1.20.0). musl 1.2.6 (Alpine 3.24, the build
  stage of hev-socks5-tunnel since the Dependabot bump) checks `sigaltstack` against `sysconf(_SC_MINSIGSTKSZ)`,
  which is about 13 KB on CPUs with AMX (Xeon 4th generation and newer), while hev-task-system's stack-overflow
  detector passes `SIGSTKSZ` (8 KB): hev exited with code 254 before printing anything, and the exit showed
  "tunnel to the proxy did not start" with an empty reason. The Dockerfile gives that stack 64 KB (the build fails
  if the replacement doesn't find both places), and an empty reason now shows hev's exit code. Seen in the network
  tests on Intel Xeon 6973P-C runners (AMD runners were fine); the test prints the CPU and an strace when hev
  doesn't start.
- **Config file names the apps accept.** The AmneziaWG and WireGuard apps take the tunnel name from the file name
  and accept only Latin letters, digits and `_=+.-`, up to 15 characters: a client named in Russian (or any
  non-Latin script, or a long name) got a file the app refused. Latin names stay (other characters → `_`, cut to
  15); the rest get 8 digits derived from the client's key — the same on every download (`users.conf_filename`).
- **Additional server addresses (#37).** Server → "Additional server addresses": other public IPs or domains of
  this server (`settings.extra_hosts`, at most `users.EXTRA_HOSTS_MAX`, IPv4, IPv6 or a domain). "Address in
  configs" offers them for everyone, and a client gets its own in its window (the Connect pane) or when it is
  created (`state.chost`: pk → address, `PUT /api/hosts/<pk>`, `host` in `POST /api/users`). Only the address the
  client connects to changes; what websites see stays the server's main address or the exit's. An address removed
  from the list is taken off its clients (they are back to the common one). Backups don't carry this server's
  additional addresses, and a client keeps its address after a restore only if this server has it too
  (`api/backup.restore_state`). Thanks to @MacSergey.
- **Clear error when the kernel module refuses an exit's config (#24).** The message no longer shows a piece of
  the `nsenter` command and the temporary config file inside the panel's container (people went looking for a
  file that isn't on the host): "The kernel module didn't accept the config of exit awgr3 (Invalid argument),
  amneziawg-go did — exits run on amneziawg-go until the AWG server restarts" (`ev.kernel_conf`, also in Telegram
  and in the engine block). Errors of commands in the AWG server's network show the command without `nsenter` and
  without file paths (`system.cmd_label`). When the reason is in I1–I5 (the module parses tags more strictly than
  amneziawg-go: `<b>` without `0x`, an odd number of hex digits, `<d>`/`<ds>`/`<dz>`, a number in `<t>`), the
  message names the field and what's wrong in it (`cps.kernel_problem`, `ev.kernel_conf_i`).
- **The exit window shows the exit's interface** (`awgrN`) next to its name.
- **DNS on the server: the description says how it works** — which way a query takes (a domain rule's exit, else
  the main exit, its fallback, direct, refusal for a block), why, encryption and cache, how to set it up — without
  comparisons with other resolvers.
- **A rule line says what it catches.** In the global policy and on a client's page a rule reads as its lists on
  the left — `Domains work (20)`, an exit's own sites by their first domain `Domains youtube.com +19` (lists keep
  their `first` domain), `Office (12 networks)`, countries and ASNs by name; more than two lists collapse to `+N`,
  opened by a tap — and the exit: right after the lists and a dash on a wide screen (as in "Everything else — …"),
  at the right edge on a phone (≤ 560 px), where a rule whose exit doesn't fit next to its lists shows only the first
  list and `+N` (`fitRules`, a `ResizeObserver` on the rule list). A rule's own name shows small and grey above it only when it is not
  the exit's or the list's name: the exit window no longer signs the rules it creates, and the names it wrote
  before are removed once (`Store.drop_auto_comments_once`: at the first start of 1.21.0 and when restoring a backup
  of an earlier version, marked in `state.upgraded`); a name given to a rule after that stays, even the exit's. A rule
  that is off stays numbered, grey and struck through. The rule editor shows the same list labels.
- **Exact AWG version on exit cards.** `AWG 3.1`, `2.0`, `1.5` or `1.0` from the config's keys
  (`awgconf.protocol_version`: H1–H4 as ranges or S3/S4 mean 2.0, I1–I5 1.5); the card no longer shows `awgrN`.
- **The header says what the panel is doing.** Besides **Running** and **Error**: **Starting…** until the first
  pass applies rules, tunnels and the domain handler; **Restarting the AWG server…** after the button or an
  auto-restart and while the panel waits for a lost interface (after 10 minutes it is an error,
  `SERVER_DOWN_AFTER`); **Switching the engine…** during a manual switch or the module install; **Updating…**,
  also for an update started in the console (`install.sh` keeps `data/installing` while it runs and the page
  reloads when it is gone); **No connection to the panel** after two failed polls in a row (a poll now gives up
  after 15 s). Yellow for the transitional states, red for errors and no connection (`Engine.phase`, `phase` in
  `/api/state`).
- **Status dot on the text line.** The dot next to "working", "online" and in the header sits at the middle of
  the text everywhere: the flex box around it took its baseline from the empty dot and pushed the text down.
- **Installer: ports.** AmneziaWG and panel ports may be anything from 1 to 65535; the random ones are four-digit
  (1000–9999: some mobile operators cut high ports). A random AmneziaWG port skips the ports of other VPNs, VoIP,
  STUN and local discovery (`AWG_AVOID`, the same list in the panel's own server creation); UDP 53 is refused —
  DNS on the server listens there (also in the panel). The panel can't take 80 (Let's Encrypt) or 443 (often a web
  server) unless it already is there, nor the domain handler's port from `SNI_PROXY_PORT`. `AWGR_AWG_PORT` is
  checked like a typed answer.
- **Installer: the ssh command names the right user.** With access through an ssh tunnel the final command used
  `root@`; now it is the user behind sudo, else the one who opened the terminal (`su -`), else the one saved at
  install (`SSH_USER` in `.env`, for `awg-router info` later), else root; and `-p` when ssh is not on 22.
- **No traffic past the exits while the AWG server restarts.** A restarted container has a new network without the
  panel's rules, and the panel found it only on its next pass (up to `RECONCILE_INTERVAL`): clients went direct
  meanwhile. The panel now follows Docker's event stream (`GET /events`, `system.docker_events`) and starts a pass at
  once, which puts the rules up before the tunnels (`_hold_rules`). On top of that the panel keeps a "before the
  panel" ruleset next to the server's config (`awgr-hold-<iface>.nft`: the rules left when the panel stops — exits
  that have no tunnel yet are blocked, Direct stays direct; `Engine._save_hold`), and the server applies it itself
  before `awg-quick up`: `awg-server/start.sh` (the image now has `nftables`) and, on the host, `ExecStartPre` in the
  panel's `awg-quick@.service`, there only when the panel's table isn't there (a reboot, not a service restart).
  With "When the panel is stopped: Send everything direct" (`on_stop = restore`) there is no such file; uninstalling removes it.
  For a server on the host the installer puts the `nft` program on the host when it is missing (`ensure_nft`); if the
  package's own `nftables.service` came enabled, it is disabled, not stopped (stopping it flushes every rule, Docker's
  too). Checked end to end on GitHub machines with the panel installed from the code (`tests/e2e/restart.sh`, job
  `restart` in `e2e.yml`): a restart of the server while the panel runs, and a "reboot" with the panel down, in both
  modes; `tests/container_e2e.py` and `movehost_e2e.py` in the network tests check the pieces.
- **The panel's web server can't be tied up by slow clients.** `IDLE_TIMEOUT` was per read, so a byte every 59 s kept
  a connection forever. Now the TLS handshake, request line and headers have `HEAD_DEADLINE` (30 s) in total and the
  body `BODY_DEADLINE` (120 s); a watchdog thread shuts the socket down when they run out (`Server.arm`). IPv6
  connections are also limited per /48 (`MAX_PER_NET`, 48), and addresses that logged in during the last day get
  `RESERVE` (16) places above `MAX_CONNECTIONS`, so the owner gets in during a flood.
- **Content-Security-Policy** on the panel's pages and the client's page: scripts, styles and fonts only from the
  panel itself, no frames, no plugins.
- **The external IP is checked.** When `PUBLIC_HOST` is empty the panel takes its address from 1.1.1.1, ipinfo.io or
  ifconfig.me — all over HTTPS now (ip-api.com, plain HTTP only, is gone; ipinfo.io also gives the country and the
  provider in the exit check); an answer that isn't an IP address is ignored (`probe.ip_of`), and a host or parameter
  with a line break never gets into a client config or `vpn://` link (`awgserver._one_line`). Before, a spoofed
  plain-HTTP answer could add lines such as `PostUp` to every client's config, or put a wrong address into them.
- **Telegram control needs a numeric Chat ID.** A `@name` can be freed and taken by someone else, and everyone in a
  public group with that name can write to the bot: commands are now accepted only from the chat with the numeric
  ID set in the panel (`Bot.allowed`), and saving control with a `@name` is refused (`err.tg_control_id`). A bot set
  up that way before keeps sending notifications and, in a private chat, answers commands with the chat's number.
- **Balancing spreads the clients of a failed exit.** `Balancer.plan` counted the loads once, so every client of an
  exit that went down landed on the same least loaded exit. The projected load of an exit now grows with each
  client given to it (the client's own recent rate, else its old exit's rate per client, else a typical active one).
- **Lists.** A country, ASN or URL list that can't be downloaded directly (raw.githubusercontent.com is often closed
  in China and Iran) is fetched through working exits (`tgreq.py` learned GET with a size limit, `notify.get_via`,
  at most two exits); a site that answers with an HTTP error isn't retried. A download over 64 MB is an error
  instead of being cut mid-line, an answer without a length drops its unfinished last line, and downloaded lists
  ignore networks wider than /8. A rule whose list has no entries (it didn't download, or it is empty) says so in its
  own line — such a list drops out of the rules silently (`rl.lists_failed`, `rl.lists_empty`). Saving or refreshing
  a list that needs the network answers at once; the table shows "Downloading…" until it is done. One list is refreshed by one thread at a time, and its file is written
  through a temporary file.
- **DNS on the server answers AAAA with "no records"**: the tunnel carries only IPv4, and apps no longer try IPv6
  first and wait.
- **The route check resolves a name the way the client's DNS will**: through the client's main exit, to 1.1.1.1 /
  8.8.8.8 (`Engine.resolve_name`, `tr.resolved_via`), not through the host's DNS, which may spoof blocked sites;
  without a way through (demo, block) it falls back as before.
- **SOCKS5 proxy names are resolved with a time limit** and together with the AWG exits' endpoints
  (`_prefetch_hosts`): a silent DNS no longer holds the engine's pass, and with it the API, for tens of seconds.
  A client's config and the client's page are given without waiting for the pass at all.
- **Limits.** Before turning a client off for its expiry or quota the panel reads the limit again: a term extended
  or a quota raised during the pass no longer turns the client off by the old values, and a client turned off just
  before such a change is turned back on by the next pass.
- **QUIC decisions follow the exits.** The `c_quic` chain takes a decision from conntrack only when its exit is still
  running (or it is pass, direct or block): a QUIC flow of a removed exit went by the main table, past the exit.
- **On the host the panel no longer changes `all` / `default` `rp_filter`** (that loosened the check for every
  interface of the server): only the AWG interface and the exits' tunnels get `rp_filter=2`.
- **The Server tab asks before leaving with unsaved changes**, like the routing rules do (`srv.leave`), and an
  older `/api/state` answer can no longer show a client that was just deleted.
- **Login.** Password checks in progress count together with failed ones, so 24 parallel attempts no longer get
  around the limit; addresses of old failures are forgotten. The panel password goes to the log only when it is
  created.
- **Fewer processes per pass.** The handshakes and traffic of all AmneziaWG exits come from one `awg show all dump`
  (`system.parse_all_dump`) and the counters of SOCKS5 tunnels from one `ip -j -s link show`, instead of a call per
  exit; an exit missing from the shared answer is asked alone, as before. `ip rule` and the exits' routes go in one
  `ip -force -batch -` (`Engine._sync_rules`), and the routes only when the set of tunnels changed or every
  `ROUTES_EVERY`; if the batch fails, a missing rule is added by its own command, whose error shows as before. With
  20 exits a pass started about 66 processes, now about 8. `awg_real_e2e` checks both on the real tools (amneziawg-go,
  the kernel module and mixed).
- **The interface with a thousand clients.** `/api/state` carries a `tag` of the state without time, CPU and memory;
  a background poll sends it back (`X-State-Tag`) and, when nothing changed, gets a short answer (0.2 KB instead of
  109 KB for 1000 clients) and redraws only the header. When something changed, the clients table replaces only the
  changed rows (`patchClients`); search, sorting and clicks keep working. 1000 clients in Chrome: a poll without
  changes ~25 ms instead of ~130 ms (a phone with a 4× slower CPU: ~45 instead of ~420 ms), with changes 22 instead of
  76 ms (116 instead of 310).
- **The field with an error is outlined.** A validation error names its field (`HTTPError.field`, `checks.field()`,
  `SERVER_FIELDS`, `params.<key>` for AWG parameters); in the exit, Server and Telegram forms the field gets a red
  frame, the cursor and a scroll to it (`markField`), and the frame goes away once the field is edited.
- **A window keeps the state it was opened with.** While a window is open, a background poll no longer replaces the
  state under it (its choice lists and its handlers see the same thing); the header still updates, and the new state
  is applied when the window closes.
- **Code checks on GitHub.** `net-tests.yml` has a `lint` job: ruff (`ruff.toml`: F, B, E9, PLE) over the repository and
  eslint (`eslint.config.mjs`, `no-undef` and plain errors) over the interface scripts; nothing of it goes into the
  panel. `tests/test_rules.py` also checks that files have no co-author lines, that every action is pinned by SHA and
  that the panel's pages load nothing from other hosts.
- **The domain lists hint says** that a browser may send a request for another site over an open HTTP/2 or HTTP/3
  connection when the sites share an address and certificate, and suggests keeping all domains of one owner in one
  list plus an address list for what matters.
- **Smaller fixes.** A Telegram backup period that isn't a string no longer gives 500: the settings answer 400, and a
  backup with one is restored with the current period;
  switches in the API — `dom_filter` and `panel_dns` in the Server settings, Telegram on/off, control and event kinds,
  turning a client or an exit on and off, balancing — must be `true` or `false` (a string such as `"false"` or `"no"`
  turned the setting on; the panel itself always sends `true`/`false`); the same now for a rule's `enabled`, an exit's
  `enabled` and Telegram on/off and control in a backup, and `list_update_hours: true` is refused.
  `PUT /api/server` with `params` that isn't an object answers 400, and a NUL in a static path 404 (both were 500
  with a traceback in the log). A change in `state.json` takes effect only after it is written to disk
  (`Store.mutate`). DNS query IDs come from `secrets`. Texts of the bot fill in their parameters in one pass (a client
  named `{gb}` kept its name). `sniproxy.log` and `dnsproxy.log` are cut when they grow over 5 MB, and a QUIC queue
  error is logged at most once a minute (`sniproxy.QUIC_ERR_LOG_EVERY`). The backup restore tests no longer go to the network.
- **One check per kind of input.** Exits, lists, rules, clients, limits, masking, Telegram and the panel settings are
  checked by one function each in `app/checks.py` (the server's client settings — DNS, MTU, keepalive, address — in
  `users.py`), used by the API and by backup restore alike; where a backup always got the default instead of an
  error, it still does (`checks.forgive`). Where the two disagreed, the form's rule now holds for backups too: a quota
  over 1,000,000 GB means no quota, more than four DNS servers — the first four, numbers written as text and extra
  spaces are accepted, and a Telegram backup password shorter than 8 or longer than 128 characters refuses the backup
  (a long one used to be dropped silently, and the backups would have gone out unencrypted). `expires: true` in
  `PUT /api/limits` is refused (it was saved as 1970 and turned the client off at once). State files and backups made
  by the real code of releases 1.0.0–1.20.0 are in `tests/fixtures/old` (`tools/fixtures/make_old.py`), and
  `tests/test_old_files.py` checks that they load as before.
- **The big files are split by topic** (nothing changes for users). `main.py` (2,600 lines) is now `app/panel.py`
  (shared objects) and `app/api/` (auth, clients, exits, routing, server, state, backup, telegram); `engine.py`
  (2,400 lines) is the package `app/engine/`, where `Engine` is put together from parts (tunnels, routes, sni, dns,
  server, speed, diag); `app.js` (2,900 lines) is `app/static/js/` — `core.js`, a file per tab and `start.js`, loaded
  in that order. Tests that read the interface's code read all its parts (`tests/panel_js.py`), and
  `tests/test_rules.py` checks that every part is in `index.html` and no top-level name is declared twice.
- **Texts of typed-in lists live in their own files.** The text of a manual network list or a domain list (up to
  2 MB each) is kept in `data/texts/<id>-<tag>.txt`; `state.json` has an empty `source` and the file's tag `text`
  (`store.TEXT_KINDS`, `Store.list_text`). `state.json` is written whole on every change and the state is copied on
  every request, so it stays small. A new text goes to a new file, written and fsynced before `state.json` refers
  to it, and the old file stays while `state.json.bak` needs it: a failed write or a start from `.bak` never loses
  a text. The first start on a `state.json` of an earlier release moves the texts out (`Store._upgrade`; tested on
  the files of 1.0.0–1.20.0). Backups still carry the texts in `source` (`Store.snapshot(texts=True)`), so earlier
  releases restore them. 1.20.0 started on these files (checked with its real code) shows such lists empty until a
  backup is restored, and comes back to 1.21.0 with the texts in place (it keeps the `text` tags).
- **Fewer moments past the exits** (found by an independent check of 1.21.0). On a new target the exits' `ip rule`s
  now go in right after the tunnels start, before DNS on the server and the nftables rules that set their marks
  (`_sync_rules(add_only=True)`; a mark without its rule took the main table, that is direct); rules of stopped exits
  are removed only at the end of the pass. A guard in nftables refuses a packet with an exit's mark that leaves by
  anything but a tunnel: `c_forward` for clients' packets, `c_guard_post` (postrouting: in output the interface is
  the one before `c_output` rerouted) for the server's own connections, and there also a `sniproxy.py` policy mark
  that `c_output` doesn't know. `sniproxy.py` blocks a client it has no settings for, and the policies' mark numbers
  no longer shift when a client is added (`nftgen.sniff_marks(slots)`: for a moment the handler's new numbers met the
  old nftables rules, and a client went by another client's rules). The rules "before the panel" on a new target go
  in right after the client list, before traffic and limits, even when the list can't be read — the AmneziaVPN app's
  container doesn't apply them itself, and README now says that such a container sends traffic direct for a few
  seconds after a reboot and how to avoid it. Moving the server to the host copies that ruleset, and
  `routing.strict` is part of its key.
- **Security fixes.** A backup's server config is refused when awg-quick would read it differently from the panel
  (`awgserver.foreign_ok`): bash drops NUL, so `Post\0Up` is `PostUp` to it, and a client line `[Interface] = x`
  reopens the server section — either way a command from the backup ran as root. No control or invisible characters
  outside comments, key names only Latin letters and digits, clients keep only `Endpoint` and `PersistentKeepalive`;
  backups of 1.3.0–1.20.0 load as before. An unread request body is skipped in 64 KB pieces (`web._skip_body`)
  instead of being read whole into memory (up to 4 MB from anyone without a password); a sign-in body is at most
  64 KB. Cookies are parsed by hand (`web.parse_cookies`): `SimpleCookie` gave up on another site's cookie with a
  space and dropped the panel's session with it. An address gets the reserve connection slots only after a
  successful sign-in or with a valid session, not on any sign-in attempt. A lone UTF-16 surrogate in JSON answers
  400 instead of 500. The panel's own password and 2FA files are fsynced with their folder. The Telegram control
  hint no longer says nothing can be deleted from the bot (it deletes a client after a confirmation). Release images
  are built without the GitHub Actions cache, and the network tests pin pyroute2.
- **Domain rules, QUIC, DNS and lists: narrow cases where a site went the wrong way.** A name longer than 253
  characters (SNI, Host, DNS) matches no list and is checked at once: 32,000 labels froze the domain handler and DNS
  for seconds and got the handler killed. A ClientHello or HTTP request that starts but doesn't arrive whole in
  `PEEK_TIMEOUT` closes the connection, like QUIC without a name, instead of going by the address rules; a silent
  client (server speaks first) is as before. A QUIC Initial with the fixed bit cleared (RFC 9287) is an Initial.
  `Host: site.test.` in HTTP is `site.test`. A domain list with links keeps its previous file whole when one link
  fails, shows the error and retries in 15 minutes (it used to drop that link's domains until the next day); the
  first build uses what it has. A body shorter than its `Content-Length` is an error (`read(n)` returned the cut
  body silently), also through an exit; a download has an overall `FETCH_DEADLINE` of 5 minutes. Domain lists with
  links were downloaded every 5 minutes, not once a day: the refresh loop looked for a network list's file. DNS on
  the server refuses a label with a dot inside (a question `victim.site` + `test` cached "no such name" for the
  normal `victim.site.test` of every client), caps the cache at 16 MB of answers (`CACHE_BYTES`) and echoes the
  asking client's question in a cached answer. A long run of spaces in a domain list no longer takes seconds (a
  backtracking regex), and non-Latin digits are refused in I1–I5, PersistentKeepalive and the Telegram chat ID.
- **Telegram.** A state pair ("exit down" / "back up", memory, CPU, domain rules) always sends a change of state
  after the last message sent (`notify.STATE_PAIRS`): an exit that went down, up and down again within 5 minutes
  left "back up" as the last message. The config file caption is HTML-escaped (a client "Mom <3" got no file). After
  waiting for commands the bot checks the settings again: control turned off meanwhile — the commands are marked read
  but not run. A cut Telegram answer (`http.client.HTTPException`) is a network error; it used to stop the bot thread
  until a panel restart when control was off.
- **Interface.** Messages show inside an open window (it is in the top layer and hid them). The DNS filter box shows
  **Save**. On the Server tab the speed limit's **Save** and **Restart the AWG server** ask to save or discard the
  edits above first instead of dropping them. A failed first request after sign-in is retried instead of leaving an
  empty page. A `host:port` proxy is SOCKS5 on the server too. On a phone "Direct instead of X" wraps under the exit
  and doesn't squeeze the client's name. A second Enter in **New client** doesn't create a second client; selecting
  text past the window's edge doesn't close it; a long name doesn't push the close button out; "No connection to the
  panel" instead of "Failed to fetch", and the Server tab says so (with **Try again**) instead of "the server isn't
  created"; the search keeps its caret; the arrow in a list's uses points left in Persian; the list picker fits the
  screen; the date and time separator follows the language. A port or subnet change says clients need new configs.
  Texts: "If domain rules don't work, block…", where that box works before the panel starts, "Shared rules" on the
  Overview as on Routing, "up to AWG 3.1"; zh and fa wording made consistent.
- **Installer, release and going back to 1.20.0.** When the own server's container is created again while its config
  is kept in `awg-server/data` (removed by hand, or a container check failed during an update), the port comes from
  that config (`saved_port`): a new random port made Docker publish a port nobody listened on. Ports with leading
  zeros (`0080`, `053`) are refused instead of slipping past "not 80/443", "not 53" and "in use". Uninstall lists what
  it leaves on the host (the module block, the kernel module, the Amnezia PPA, the panel's ufw rule). A manual run of
  `release.yml` makes a draft only from main, and **check** only for a released version (on a new one it published).
  The panel image carries compiled bytecode (`compileall` and an import of the panel at build time): the image had
  no `.pyc` even for the standard library, `PYTHONDONTWRITEBYTECODE` kept it so, and every start and health check
  compiled everything — 3 seconds on a one-core VPS before the panel put its rules up. A typed-in list with a text
  but an empty built file is rebuilt at start (`_rebuild_empty_texts`): 1.20.0's **Refresh now** on 1.21.0's files
  emptied it, and 1.21.0 never rebuilt typed-in lists. The release notes say how to go back and what to avoid there.
  `install.sh --install-kernel` tries `add-apt-repository ppa:amnezia/ppa` three times (10 and 30 s apart):
  Launchpad's API now and then cuts an answer short (`IncompleteRead`), as it did in three CI runs in a row.
  `awg-router uninstall` also asks whether to remove the panel settings (`/opt/awg-router`; kept on Enter): before,
  the folder always stayed, and a new install quietly took its `.env` and `data/` over, the access method too. Not
  asked while the kept server of our own container has its keys there; only a folder with the panel's
  `docker-compose.yml` is removed, after the list of leftovers (it reads the panel's port from `.env`).
- **Speed.** `/api/state` no longer carries each client's 12-month traffic history (the interface never read it;
  `Traffic.view(history=False)`), and the panel's and certificate's address are read without copying the whole state
  (`store.peek`): at 1,000 clients a full answer took 59 ms of server time instead of 71.5, a tagged one 30 instead
  of 38.5. The interface reuses its `Intl` number and date formatters instead of making one for every value (3,000
  numbers: 80 ms → 3 ms). `traffic.json` is written only when a client's counters changed, not every minute.
- **Tests and code tidy-up** (nothing changes for users). Two tests failed now and then: a wrong-password decrypt
  of a Telegram backup could, about once in 300 runs, give bytes instead of `None` (the test now checks that the data
  isn't returned), and the demo install test waited on a real clock under load. Every test file runs on its own, a
  test cleans the TLS domain it set, and tests close their connections, files and sockets. A test checks that every
  API handler is called with the arguments it takes (it catches `PUT /api/upstreams/{uid}` calling `_exit_rates`
  with the wrong one, as on the audit branch). Unused functions are gone (`parse_server_conf`, `setconf_resolved`,
  `WARN_PACKET`, `_resolved`, `tgbot._move`), comments name the files after the split, and `docs/ARCHITECTURE.md`
  lists every module.
- **Documents.** The README section "DNS on the server" says that names from domain rules go through the rule's
  exit, that AAAA gets "no records", and that with firewalld in host mode port 53 has to be opened by hand; the
  features list has the additional server addresses and the numeric Chat ID; changing `EXIT_ENGINE` is applied with
  `docker compose up -d` (`awg-router restart` keeps the old `.env`). The README and the Telegram box say CPU above
  95%, as the code has it (memory stays 90%). `.env.example` lists the settings the panel reads (without
  `UPSTREAM_BACKEND`), the bug report form says where to find the version, CONTRIBUTING says that a pull request
  gets only CodeQL, and two section references in the fa README are links.
- **A newly started exit blocks its clients instead of sending them to the fallback.** After a panel start or update,
  an AWG server restart or an exit edit, the first pass saw the exit's new tunnel without a handshake and sent its
  clients to the fallback: with the default "Direct" that was 9–12 s past the exit on every panel start (measured on
  the test server in Russia, exit 120 ms away). `resolve` now gives a block while the exit is `connecting` (no answer
  yet, at most `CONNECTING_SECS` = 30 s), and a thread (`Engine._watch_connecting`) looks at the handshakes of such
  AWG exits every `HANDSHAKE_POLL` (0.5 s) and wakes the pass as soon as one answers; a SOCKS5 exit wakes it with its
  first proxy check. An exit that doesn't answer in 30 s goes to its fallback as before. The exit window's hint says so.
- **Clients can't reach link-local addresses.** `c_forward` rejects `169.254.0.0/16` from the clients' interface
  (`nftgen.LINK_LOCAL`): the cloud's service address `169.254.169.254` (server data; on AWS, keys to the cloud
  account) was reachable — link-local is one of the local networks (`local4`), so it went straight from the entry
  server whatever the client's exit. The rules "before the panel" carry it too; `netns_e2e.py` checks it, with an
  exit as the default and with everything direct.

## 1.20.0 — 2026-11-14

- **AmneziaWG engine: amneziawg-go or the kernel module.** A new block on the Server tab shows what the server
  runs on (the link type of `awg0`) and which kernel module is loaded. Tunnels to exits follow the server
  with nothing to pick: on the kernel module when the server runs on it and the module is 3.x (if the module
  can't create a tunnel or rejects a config that amneziawg-go accepts, they move back to amneziawg-go until
  the server restarts; a config that neither accepts is the exit's error and leaves the module in use);
  `EXIT_ENGINE=go|kernel` in `.env` pins them for debugging. The server picks
  the module by itself, as `awg-quick` does. A loaded module older than 3.x with an AWG 3.1 config — the
  server then doesn't come up — is reported in the panel and in Telegram. `awg-router install-kernel` builds
  the module from the Amnezia PPA (Ubuntu 22.04+, Debian 12+ with the PPA key checked by Launchpad's full
  fingerprint; x86_64 and aarch64; not in OpenVZ/LXC), installs only `amneziawg-dkms` and removes a module older
  than 3.x again. It also loads the module at boot (`/etc/modules-load.d/amneziawg.conf`), so a server in
  a container that Docker starts early still comes up on it. The network tests install the module with the same command and run a real tunnel on it.
  Thanks to @paris19891 (#24).
- **The kernel module is the recommended engine.** A new install or `--reconfigure` asks "Which AmneziaWG engine
  should the server use?" when the server fits (`kernel_fit`: not OpenVZ/LXC, x86_64/aarch64, Ubuntu 22.04+ or
  Debian 12+): the module first, "(recommended)", Enter picks it; `AWGR_ENGINE=kernel|go` answers in advance, an
  update never asks. The module is installed before the AWG server is created, so a new server comes up right on
  it; any failure is a warning (`KERNEL_SOFT`) and the install goes on with amneziawg-go. The panel offers the
  module in a notice at the top (`engine_offer`: offer, old, lost, disabled, restart, installing; **Hide** is kept
  per kind in `data/engine.json`) with an **Install the module** button that runs `install.sh --install-kernel` on
  the host as a systemd job (`kernelmod.start`, log in `data/kernel.log`) and then asks to restart the AWG server.
  A module that no longer loads after a kernel update (the server came up on amneziawg-go) is reported once
  (`ev.kernel_gone`, Telegram). A server that doesn't come up on a loaded module after `KERNEL_GIVE_UP` restarts
  is moved to amneziawg-go by the panel: the module is blocked (`/etc/modprobe.d/awg-router-amneziawg.conf`, so
  `ip link add` can't load it again), its autoload removed and the module unloaded (`ev.kernel_disabled`; **Try
  again** reinstalls, which lifts the block). Installing the module also sets `kernel.panic = 10` unless there is an
  own value, so a crash in the kernel reboots the server instead of leaving it hanging. Texts of the engine block
  rewritten: the module is the recommended engine, in terms of system resources; the install part is gone once the
  module runs, and the panel no longer lists requirements it has already checked. **System → Connection to Amnezia**
  showed "Exit tunnels: amneziawg-go" from a leftover `.env` line (`UPSTREAM_BACKEND`, written by every install and
  never used): it now shows the real engine with the module version, and exits separately only when they differ
  from the server; the line is no longer written, and updates drop it from `.env`. The engine can also be picked by hand
  for the whole server (**Server → AmneziaWG engine → Engine**, `POST /api/engine/choose`): amneziawg-go stops the
  server, blocks and unloads the module and starts it again (`Engine.switch_engine`; `choice` in `engine.json`
  keeps the notice away); the module lifts the choice and restarts the server, or installs the module first. An
  already installed module is only loaded again, without the PPA (`install_kernel`). The move onto the module is
  an event and a Telegram message (`ev.kernel_on`), and the bot's status shows the engine.
- **CPU and memory in the status line.** The panel's status line shows the server's CPU and memory load,
  refreshed with the rest of the state; 90% and above is highlighted, and the hint has the load average and
  the memory in use. CPU is measured between two reads of `/proc/stat` (`hostnet.CpuMeter`), so it is the whole
  server, not the panel's container.
  The status line shows **Running** or **Error** (with the reason in the hint; a click scrolls to the banners at
  the top) instead of the container and interface names.
- **The AWG server comes back by itself.** When the server's interface is gone while its container keeps running
  (for example, the kernel's OOM killer ended `amneziawg-go`, and clients dropped until someone restarted it by
  hand), the panel restarts the container after `engine.SERVER_GRACE` and then with growing pauses
  (`SERVER_PAUSES`) if that doesn't help; the pass that restarts it applies nothing more, since the container
  has a new PID. In host mode the `awg-quick` service is restarted the same way: before,
  `systemctl enable --now` left a service that was "active" without its interface as it was. **Server → Restart
  the AWG server** does it by hand.
- **Telegram: server resources.** A new notification kind with its own checkbox: memory above 90% or CPU above
  95% for 5 minutes, and back to normal. The server restart above is reported under "server".
- **The panel over IPv6.** The panel now listens on IPv6 as well as IPv4 (one socket for all addresses; IPv4
  only if the kernel has no IPv6), so an IPv6 server public address works as one field was meant to: the panel
  opens at it, gets its certificate for it and clients connect to it unless "Address in configs" picks another
  one; the field's hint now says all three. With IPv6 in use (an IPv6 public address, or IPv6 in "Address in
  configs") the certificate covers both the IPv4 and the IPv6 address, so the panel opens without a warning at
  either; if Let's Encrypt can't validate the second one, the certificate covers the main address and the second
  is tried again after `tlsmgr.ALT_RETRY`. A Let's Encrypt certificate for an IPv6 address is found under the
  file name lego gives it (`:` becomes `-`), so it is no longer requested again every 30 minutes. Connection
  limits and the sign-in lockout count IPv6 clients by their /64. Thanks to @paris19891 (#20).
- **A domain in client configs.** `PUBLIC_HOST` may be a domain: with a panel domain the installer asks
  whether client configs use it (`AWGR_CLIENT_DOMAIN=yes|no` answers without a prompt), checks the domain's DNS
  against the server's IP instead of `PUBLIC_HOST`, and `--reconfigure` asks again (Enter keeps the current
  choice); `AWGR_CLIENT_DOMAIN=no` also returns configs that already use the domain to the IP. Saving the Server tab
  no longer turns the `.env` address into a panel setting that silently overrode `.env`, and the installer warns
  when the panel's own address does. Thanks to @koo-pub (#22, #23).
- **Let's Encrypt through a web server on port 80.** Since 1.14.0 the self-check put its test file next to
  `.well-known/acme-challenge/` instead of inside it (`host_path` drops the trailing slash), so validation
  through nginx, Apache or Caddy always got HTTP 404 and was rolled back, in the panel and in the installer
  alike. Thanks to @xiaomiiraqly-alt (#21).
- **Exits at an IPv6 address.** When the AWG server's network has no IPv6 route to an AWG or SOCKS5 exit (in
  the AmneziaVPN container mode Docker gives the container no IPv6 by default), the exit now says so and what
  to do instead of hanging on "no connection"; README → Limitations shows how to turn on IPv6 in Docker. The
  check looks at the route, so servers with IPv6 in Docker keep working. Thanks to @paris19891 (#20).

- **Moving the AWG server from its container to the host.** `awg-router reconfigure` (and the installer when
  it finds an Amnezia container) now offers to move the server to the host with the same files: keys, port,
  obfuscation parameters and clients stay, so client configs keep working (`app.movehost`; unattended —
  `AWGR_MODE=host AWGR_MOVE=yes`). The container is only stopped and renamed (`…-moved-<date>`); if the server
  doesn't come up on the host, the container is put back and the panel keeps managing it. The container's own
  hooks are not carried over: on the host the panel's NAT is used, as for a server it creates. The network
  tests move a server on a GitHub machine and connect a client with its old config. Thanks to @paris19891 (#25).
- **Uninstall no longer deletes the AWG server by surprise.** A server the installer put into a container
  keeps its keys and clients in `/opt/awg-router/awg-server/data`, so "delete the folder to remove the
  settings" after `awg-router uninstall` deleted the server too, while its container kept running empty and
  held the UDP port. `awg-router uninstall` now asks whether to keep that server (or the one on the host) or
  remove it as well, says when the folder must stay, and leaves containers of the AmneziaVPN app alone. The
  installer recognises an Amnezia container without a config, says so and sets it aside (stopped and renamed)
  instead of offering to manage it, so the port is free for a new server. Thanks to @paris19891 (#25).
  A server on the host is no longer taken silently either: a new install or `awg-router reconfigure` that finds
  `/etc/amnezia/amneziawg/awg0.conf` asks whether to keep it or put a new one in its place, in a container or
  on the host (the old one is stopped and its config folder set aside; `AWGR_REPLACE=yes` unattended).
  Removing a host server with `awg-router uninstall` also removes the service file and the `awg`,
  `awg-quick`, `amneziawg-go` the panel had put into `/usr/local/bin` — only when the service file is the
  panel's own. Thanks to @paris19891 (#27).
- **Updates keep `.env`.** The installer writes `.env` anew on every install and `awg-router update`; settings
  added by hand (`EXIT_ENGINE`, `AWG_CONTAINER`, `SNI_PROXY_PORT`, `ACME_HTTP_PORT` …) were dropped, and
  `TLS_MODE=selfsigned|off`, a `PANEL_HOST` other than `0.0.0.0` and `RECONCILE_INTERVAL` were reset. Every key
  of the previous `.env` that the installer doesn't write itself is now carried over (for a name written twice
  the last line wins, as for Docker); `TLS_MODE` and `PANEL_HOST` are kept while the access mode stays public,
  and `RECONCILE_INTERVAL` is kept when it is a number. Keys come only from this run's copy of `.env`: a `.env.bak`
  left from an earlier install does not bring old settings back when `.env` was deleted on purpose.
- **After the server's container restarts.** The new container's network had no rules until the end of the
  first pass, while tunnels to exits were already being started — clients went out directly, even with the
  "Block" fallback. Now a pass on a new target first puts in rules where every exit without a tunnel yet is
  treated as down (`engine._hold_rules`), and the usual apply replaces them at the end. With the 3.x kernel
  module loaded and the server's interface not up yet, AWG exits wait for it (`engine_pending`) instead of
  starting on amneziawg-go and being recreated on the module a pass later; after the panel restarts the server
  by itself, the next pass starts at once instead of after `RECONCILE_INTERVAL`. Exit endpoint names are resolved
  together (`awgconf.resolve_many`): three names that don't resolve held the pass, and the engine lock with
  config downloads and personal pages, for 3 × `RESOLVE_TIMEOUT`.
- **A faster panel.** The panel keeps its connection open between requests (HTTP/1.1; the next request is
  awaited `web.KEEP_IDLE` seconds, and with half the connection slots in use responses close the connection as
  before) instead of a new TLS handshake for every state poll, and compresses text responses from 1 KB
  (`/api/state` for 1000 clients: 234 → 29 KB, first load of the panel: 526 → 144 KB). `/api/state` no longer
  copies the whole state for every client with a personal link: 1.5 s → 30 ms for 1000 such clients. Static files
  are compressed once per version (`web.gzip_static`), and the public pages (`/s/…`) look up a link's token
  without copying the state: a request from anyone no longer costs the panel milliseconds of CPU. The browser
  polls the state every 5 s, but the page redraw now takes at most a twentieth of the time: with 1000 clients
  (a quarter of a second on a computer, one to two seconds on a phone) the pause grows up to 30 s.
- **Requests from other pages of the same site.** The session cookie (`SameSite=Strict`) is also sent from
  another port of the same IP or a sibling subdomain, and a form there could send an empty POST — restart the
  server, start an update. Requests that change something are now refused (HTTP 403, `err.cross_site`) when
  the browser says they came from another page (`Sec-Fetch-Site`, or `Origin` in older browsers).
- **Domain rules: a direct connection to the handler.** A client that opened the handler's port
  (`SNI_PROXY_PORT`) at the server's tunnel address directly made it connect to itself, again and again, until
  it ran out of file descriptors and stopped serving every client with domain rules. Such a connection is now
  closed at once (`direct` in the handler's counters).
- **Smaller fixes.** Restoring a backup from another server no longer takes the old server's public address
  and "Address in configs" when this server has none of its own (`PUBLIC_HOST` from `.env` stays in force);
  before, configs, the panel link and the certificate got the old IP. An exit whose fallback chain leads back
  to itself (A → B → A) is refused with a clear message: with all of them down clients would be blocked. The
  certificate thread survives an unexpected error instead of stopping renewals until a restart; a self-signed
  certificate is reissued when only the second address changes. `Infinity`, `NaN` and very deeply nested JSON
  in a request get HTTP 400 instead of 500, and so does a number out of range such as `1e999` (it was infinity in
  Python and failed in `int()`); a request with `Transfer-Encoding` gets 411. When `awg syncconf` fails, the
  server's files are put back as they were: before, the panel showed a client disabled or deleted while the
  peer kept working until the server restarted, and a client past its date or quota was marked as switched off
  and never tried again — now the switch-off is retried every pass, and the event comes only once it worked.
  A `vpn://` link is unpacked with a 4 MB limit (a link of half a megabyte took a gigabyte of memory), and a
  config nested too deeply is "not recognized" instead of HTTP 500. `state.json`, the clients' traffic and the
  server's files are written with `fsync`, and the previous `state.json` is kept as `state.json.bak`: the panel
  starts from it when `state.json` is damaged (the damaged file is kept as `state.json.broken`) instead of not
  starting at all. A field of the wrong type in the Telegram settings or a client's name gets HTTP 400 instead of
  500 (a name like `true` no longer becomes "True"); a client's end date later than the year 9999 is refused,
  and one in a backup is dropped (the bot failed on such a client's card). A loop of fallbacks (A → B → A) in a
  backup made before 1.20.0 is broken with "direct" when restoring. Reading traffic totals waits for the
  accounting (a new month appearing mid-read could fail the state request), and the cache of parsed exit
  configs no longer grows with every edit. The Server tab's "Subnet" field shows the subnet (`10.8.1.0/24`) in host
  mode too, not the server's own address with the mask (`10.8.1.1/24`), which looked like a wrong subnet. The
  field takes only the subnet: the panel puts the server's address in it by itself, in the form it had (the
  first address, or the network address as AmneziaVPN writes it) (thanks to @paris19891, #26).

## 1.19.4 — 2026-11-13

- **Faster domain rules.** `sniproxy.py`, which carries all TCP 80/443 of clients with domain rules,
  now relays data inside the kernel (`splice`) instead of copying it through Python, on the direct path
  and through SOCKS5 alike: about half the CPU at 1 Gbit/s and a higher ceiling through SOCKS5. Rereading
  the settings no longer stalls open connections: files are parsed in a thread, and lists whose files have
  not changed are not parsed again. Both sides of a connection stop together, sends to a site or a proxy
  have a timeout, the open files limit is raised, and a failed accept loop restarts the handler. Thanks to
  @alexeyvolodin (#19).
- **Busy port check in the installer.** With a long list of open sockets the installer could miss that
  the chosen panel port was already taken. Thanks to @alexeyvolodin.

## 1.19.3 — 2026-11-10

- **Release download fallback.** When github.com fails to serve the release archive (in Russia
  `/releases/download/` sometimes answers HTTP 504), the installer and the update take the same archive and
  its `.sha256` through api.github.com, which sends them straight to GitHub's file storage. The checksum is
  checked as before, and a failed download still never installs unreleased code from `main`. Thanks to
  @LCF30 (#13).

## 1.19.2 — 2026-11-08

- **Session cookie.** The tag in the session cookie that ties it to the current password is now an HMAC
  with the panel's secret key instead of a plain SHA-256 of the password, so a stolen cookie gives nothing
  to test password guesses against. Everyone signs in again once after the update.
- **Tab from the address.** An address such as `…/#toString` no longer breaks the page: an unknown tab
  opens **Overview**.

## 1.19.1 — 2026-11-08

- **Interface polish.** The common speed limit panel on the **Server** tab spans the full width like the
  other panels; on the **Exits** tab the empty hint and the **Direct** card have a gap between them; the
  QR code is centred when the buttons wrap below it (always the case in the dark theme); **Everything
  else** on the Routing tab shows **Load balancing** without the scales emoji.
- **Verifiable releases.** The images and the archive are now built with signed build attestations, and the
  images have an SBOM (list of components): `gh attestation verify oci://ghcr.io/r-slashslash/awg-router:<version>
  -R r-slashslash/AWG-Router`. Nothing changes for the panel itself.

## 1.19.0 — 2026-11-08

- **Load balancing across exits.** On the Routing tab, **Everything else** can now be **Load balancing**
  instead of one exit. Each client that follows the defaults gets the least busy of the checked exits (all
  of them by default); load is measured against the exit's speed limit when one is set, otherwise in
  Mbit/s, and when everything is idle new clients go where there are fewer of them. If one exit stays
  overloaded for two minutes while another has room, one active client is moved, at most one every three
  minutes and the same client at most every ten. A moved client's open connections stay on the old exit
  (the exit is remembered per connection in conntrack); only new ones use the new exit. Clients of an exit
  that fails, is turned off or runs out of quota move at once. When none of the checked exits works,
  traffic takes the path chosen under **If all exits are unavailable** (the former default exit, so a
  rollback to an older panel keeps working). Address and domain rules and clients' own exits work as
  before. The client list, the trace, DNS on the server and the bot show the exit a client got; **Make
  default** in the bot turns balancing off.
- **Speed limits.** All off until a value is set, download and upload separately, in Mbit/s:
  for all clients together (**Server** tab), per client (client card, next to the traffic limit) and per
  exit (exit settings). Within the common limit the speed is split evenly between those downloading right
  now. The strictest limit applies. Limits are `tc` HTB queues with fq_codel, so latency stays low under
  load; incoming traffic goes through an `ifb` device. The installer (and so `awg-router update`) installs
  `linux-modules-extra` for the running kernel and its flavour when the kernel has no `ifb` module, as on
  many cloud kernels; if there is no such package, the panel says so and the other limits still work. A SOCKS5 exit's limit is shared by both of its paths: sites from domain
  rules go to the proxy past the exit's tunnel, so the domain-rule handler measures itself and the tunnel
  every second and splits the limit — each path gets what the other leaves, but at least half.
- **Current speed of each exit** on the Exits tab and the overview, with its limit next to it.

## 1.18.0 — 2026-11-07

- **The installer asks for the panel port.** Like the AmneziaWG port: Enter takes a random free 4-digit
  port, as before, or type your own. It must be from 1024 to 65535, free, not one that browsers refuse to
  open and not 10443 (domain rules); otherwise the installer says why and asks again. `--reconfigure`
  offers the current port; an update keeps it without asking. Without a terminal: `AWGR_PORT=…`.
- **The connection name in a vpn:// key is just the client's name.** AmneziaVPN showed the connection as
  "name · server address", but the app shows the server address on its main screen anyway, so the address
  is no longer repeated in the name. Keys issued earlier keep their old name until they are imported again.
  The .conf file and the QR code carry no name at all: AmneziaWG takes it from the file name or asks for it.
- **One "Add exit" button.** With no exits yet, the Exits tab showed the button twice: at the top and in
  the empty card. Now it is only at the top, as on the Clients tab.

## 1.17.1 — 2026-11-07

- **Ready images actually used.** In 1.17.0 the installer still built the image on the server: when the
  release was published, the workflow replaced the release archive with one without the `IMAGES` file,
  because its check "the archive is already attached" never matched (the pattern needed two spaces
  between the file names). So `awg-router update` and **System → Update** silently went to the build
  and hung on Alpine packages where they are filtered. The check is fixed, and after publishing the
  workflow now checks that the archive carries `IMAGES` and warns if not.
- **The installer says why it builds.** When the downloaded archive has no ready image (a branch,
  `AWGR_SRC_URL` or an older release), the installer now warns that it builds the image on the server and
  that this needs dl-cdn.alpinelinux.org and github.com; before, it said nothing. With `AWGR_BUILD=1` it
  stays quiet: the build was asked for. Thanks @LCF30 for finding and explaining both (#8).

## 1.17.0 — 2026-11-07

- **Ready images instead of building on the server.** Installing and updating used to build the image
  on the server, and the build reaches dl-cdn.alpinelinux.org and GitHub over git, which are filtered in
  Russia, China and Iran, so the panel could not be installed or updated there. Now the release workflow
  builds the panel image (amd64, arm64) and the AmneziaWG server image (amd64) from the release commit and
  publishes them to ghcr.io/r-slashslash/awg-router; the release archive carries their digests in a file
  `IMAGES`, and `install.sh` (also `awg-router update` and **System → Update**) downloads the image by
  digest. It builds on the server, as before, only when there is no ready image: no image for this CPU,
  the registry doesn't answer within 10 minutes (`AWGR_PULL_TIMEOUT`), an archive of a branch, or
  `AWGR_BUILD=1`. An update also removes the previous panel image, and `awg-router uninstall` removes
  a downloaded image too. Thanks @LCF30 for the report (#8).
- **More problems at the top of the panel.** Two problems that were only visible on the System tab now
  also get a red banner on every other tab, with a button to System: an HTTPS certificate that wasn't
  obtained (the panel serves a temporary one and browsers warn), or one that can't be renewed with less
  than two days left; and an update that failed.
- **SOCKS5 exit: a proxy with nothing behind it is no longer "working".** The check counted the
  proxy's own "connection open" answer, but a proxy on this server (Xray, for example) gives it before
  it has reached the foreign server. So an exit whose foreign address was blocked stayed green, stayed
  in the fallback chain, and no "exit stopped working" message came. Now, after the connection, the panel
  sends the start of a TLS handshake, and the exit works only if 1.1.1.1 or 8.8.8.8 answers from behind
  the proxy; otherwise it is shown as not working ("the proxy accepted the connection, but nothing
  answers behind it"), clients move to its fallback and the notification is sent. The time shown for the
  exit is now the time to that answer. Thanks @LCF30 for the report (#9).
- **Telegram: notifications no longer depend on the exit they report about.** If the exit chosen in
  "Send through" doesn't work, the message tries the other working exits and then goes directly from the
  server. If nothing works, it waits and is retried (after 30 seconds, then 1, 2 and 5 minutes; up to 50
  messages, none older than a day) and goes out in order when Telegram is reachable again; a message that
  waited more than 90 seconds says when the event happened. The queue lives in memory, so a panel restart
  clears it. A refusal from Telegram itself (wrong token or chat) is not retried. A sending error is now a
  red banner at the top of the panel with the number of waiting messages, not only a small line in the
  Telegram settings. "Send test message" and backups still use exactly the chosen path. Thanks @LCF30
  for the report (#10).

## 1.16.0 — 2026-11-06

- **Encrypted DNS on the server.** A new setting under "DNS on the server": **DNS query encryption** —
  DoH (DNS over HTTPS, port 443, the default), DoT (DNS over TLS, port 853) or none. Queries to the
  servers from the "DNS" field are encrypted, so neither the entry server's ISP nor the exit's ISP
  can read or spoof them; the server's certificate is checked (by the service name for Cloudflare,
  Google and Quad9 addresses, otherwise by the IP address in the certificate). TLS connections are
  kept open per exit and server, so a query doesn't cost a handshake; a connection the server closed
  is replaced transparently. There is no fallback to plain DNS: if the encrypted channel is down,
  clients get SERVFAIL and ask the second DNS from their config, and the panel and the bot show
  "DNS servers don't answer". Panels that turned DNS on the server on in 1.15.0 keep it unencrypted
  until it is changed, so a server in the "DNS" field without DoH can't break clients' DNS.
- **Bot: Server › Status** shows the DNS encryption mode and a warning when the DNS servers don't answer.
- **Wording.** The description of the cascade catch said that with AmneziaDNS the local ISP can spoof
  answers. AmneziaDNS encrypts its queries, so the ISP can't spoof them, only block the connection;
  the real catch is that answers are fetched from the entry country. Fixed in the interface hint and
  the README.

## 1.15.0 — 2026-11-06

- **DNS on the server (optional).** **Server → Client settings → DNS on the server** runs a small
  DNS server (`dnsproxy.py`) in the AWG server's network, on port 53 of the server's tunnel address.
  Client configs get its address as the first DNS and the first server from the "DNS" field as the
  second (it answers while the panel restarts). Queries are forwarded to the servers from the "DNS"
  field through the client's main exit, with its fallback, like the client's traffic: the answer
  comes from the exit's country, so CDNs return nodes near the exit, not near the entry server,
  which is the catch with a resolver on the entry server such as AmneziaDNS (its queries are
  encrypted, so the ISP can't spoof them, but it can block the connection). Clients whose main route is direct get answers fetched directly; clients with a block
  get REFUSED. Answers are cached per exit for their TTL; through SOCKS5 exits queries go over TCP.
  The setting is kept in backups. README: new section "DNS on the server".
- **Exit with a domain name in Endpoint.** An exit whose config had `Endpoint = name:port` instead of
  an IP address never came up: `awg setconf` waited 30 seconds and failed, and every retry did the
  same. The cause was DNS: the command runs in the network of the Amnezia container, but the resolver
  settings stay those of the panel, and on hosts with systemd-resolved they point to 127.0.0.53,
  where nobody listens inside that network. The panel now resolves the name itself, in its own
  network, before the tunnel is created, and gives `awg setconf` the address. The config keeps the
  name, so it is resolved again every time the tunnel is brought up. If the name cannot be resolved,
  the exit shows a clear error instead of a 30-second timeout.
- **New address of an exit's name is picked up.** When an exit with a name in Endpoint stops
  answering, the panel resolves the name again (at most once a minute) and, if the address changed,
  switches the peer to it with `awg set … endpoint` without restarting the tunnel; an event in the
  log. A working tunnel is never touched, so a DNS failure or a spoofed answer can't move it.
- **Exit check and the server's IPv4.** The check resolved `ip-api.com` and `ifconfig.me` in the
  same broken network, so it showed "external IP unknown", and the server's own IPv4 (Server tab, bot
  status) was never found: the panel gave up after 30 tries until it was restarted. The panel now
  resolves these names itself, both at once, and passes the addresses to the check. The IPv4 search no
  longer gives up: 30 tries every 20 seconds, then every 10 minutes, and a found address is checked
  again every 6 hours.
- **Bot: Server › Status.** IPv4 shows "detecting…" or "unknown" instead of a dash, IPv6 shows "none
  on the server" when there is none, and a new line shows DNS on the server: off, running on its
  address with query and cache counters, or not working.

## 1.14.2 — 2026-11-05

1.14.1 was withdrawn soon after publishing; its changes are part of this version.

- **New icloud.com masking, and the panel switches to it.** The I1 that AmneziaVPN puts in by default
  is the same on every server (only the 2-byte DNS ID is random) and answers icloud.com with
  77.88.55.55, a Yandex address. The template "DNS response: icloud.com" is now a recursive
  resolver's answer with the real address 17.253.144.10, a random ID and TTL and EDNS0, like the
  "DNS query" template; it is also the default for new parameters. The panel replaces the old packet
  by itself, once: in the server's I1 when it finds it (also in a restored backup; an event in the
  log, no restart: I1 is a client parameter) and for clients that had the old template as their own
  (`cps.RENAMED`). Old client configs keep working; new configs carry the new packet.
- **Client masking list without a duplicate.** The default item is now named after the server's
  template, for example "DNS response: icloud.com (default)", and that template is no longer listed
  a second time below it. A client that had the same template chosen as its own still sees it until
  it is switched to the default. The icloud.com template is called "DNS response: icloud.com"
  everywhere.
- **Client route: "Default “name”".** The first item of a client's route list was "Same as everyone
  (now: …)"; it is now "Default “…”", like the masking list.

## 1.14.0 — 2026-11-04

1.13.1 was not released; its QR code fix is part of this version.

- **Panel domain.** The installer asks for a domain for the panel (Enter — open it by IP), and
  **System → Domain and certificate** changes it later. The panel checks that the domain points to this
  server before using it. The domain is only the panel's address: client configs keep the server
  address. It is kept in `data/tls.json`, not in backups; `TLS_DOMAIN` in `.env` still works until a
  domain is set.
- **Own certificate.** In the same window: paths on the server to a certificate (full chain) and key,
  for example from certbot. The panel checks that it is for the panel address and that the key
  matches, and picks up a renewed certificate within a few minutes, without a restart.
- **Port 80 taken by a web server.** If nginx (also Angie, OpenResty) or Apache already serves sites,
  Let's Encrypt validates the panel through it: the panel adds its own file `awg-router-acme.conf` that
  answers only `/.well-known/acme-challenge/` for the panel address from `/var/lib/awg-router/acme`.
  It shows the file and asks first (the installer and **System → Set up validation through the web
  server**), tests the config (`nginx -t`, `apachectl configtest`), reloads, and requests a test file
  through the web server; on any error it removes the file. Works for nginx on the host and in Docker
  when its config folder is mounted from the host, and Apache on the host; for others it shows the
  block to add by hand. Before, the panel stayed on a temporary certificate. Removed by **Remove from
  the web server** and `awg-router uninstall`. Thanks to @Neborya (#4).
- **QR codes scan reliably in AmneziaWG on Android.** QR codes in the panel and on a client's page are
  now drawn as a sharp picture where every square has the same whole number of screen pixels; before,
  squares came out of different sizes and blurred, and the scanner often failed. In the dark theme the
  white margin around a QR code is wider (the camera overexposes a thin one), but only from free space:
  the code itself keeps its size. Thanks to @koo-pub.

## 1.13.0 — 2026-11-03

- **Server traffic in the header.** A **TRAFFIC: N** badge next to the panel name shows all traffic
  through the server since the panel was installed (hover for the download/upload split). It replaces
  "rules applied …". It doesn't go down when clients are deleted; on panels updated from an earlier
  version it starts from the totals of the current clients. Stored in `traffic.json` (`"server"`,
  format unchanged) and carried over by restore.
- **Client traffic on phones.** Client cards on a narrow screen now show the client's traffic this month
  (or its limit meter) under the exit; before, the column was hidden there.
- **New Telegram menu.** `/start` sends the panel logo with a summary under it: host, panel version,
  clients, clients online and all-time traffic. Buttons: **Server**, **Clients**, **Panel**, **Backup**
  and a wide **Refresh**. Other screens change the text under the logo in the same message; a screen
  too long for a photo caption comes as text.
- **Server → Status:** host, panel and AWG versions, IPv4 and IPv6, server uptime, RAM, clients
  online, traffic this month and status. **Server → Exits:** exits as buttons (direct first, ⭐ marks
  the default); an exit opens its own screen with **Check exit** and **Make default** and its traffic
  this month.
- **Clients** start with a **New client** button above the list.

## 1.12.2 — 2026-11-02

- **Exit window keeps your rules.** Saving the routing part of an exit window no longer rewrites every
  rule to that exit: a list you unticked leaves its rule, a list you ticked joins an existing rule to the
  exit (or a new rule right after them). Turned-off rules, rule names and the order of rules stay as they
  were — before, turned-off rules were deleted and rules to the exit were merged above other rules.
- **Exit quotas count sites from domain rules.** HTTPS and HTTP of clients with domain rules pass
  through the server's own proxy, which nftables accounting did not see: SOCKS5 exit quotas and the
  by-exit split of clients missed most of that traffic. The proxy now counts bytes per client and exit.
- **Subnet change on a host server.** Changing the subnet of an AmneziaWG server on the host left NAT
  for the old subnet, so clients had no internet after the restart; NAT now follows the subnet. For an
  AmneziaVPN container, whose start script has the subnet written in at install time, the subnet field
  is locked with a note.
- **Restore keeps an exit's own sites list.** Before, after a restore the exit window showed no sites,
  and saving it created a second list with the same name.
- **A failing exit is retried with a pause** (10 s growing to 5 min) instead of every 10 s: the event log
  and Telegram no longer fill up with the same error, and the panel stays responsive. Edit the exit or
  press **System → Re-apply rules** to retry at once.
- **Updates install only a released version.** If the release archive can't be downloaded, the
  installer and the panel's update stop with an error instead of installing the `main` branch; the
  archive is checked against its `.sha256`. The branch is still used when the repository has no release.
- **Domain rules:** connections through the server's proxy get the same MSS clamp as forwarded traffic
  (no stalled HTTPS through AmneziaWG exits when path MTU discovery is broken), TCP keepalive and a
  15-minute idle timeout (connections of vanished devices no longer pile up).
- **API:** an exit's type and a list's kind can't change on edit (the panel never offered it; through
  the API it broke domain rules and restoring the panel's own backup).
- **Hints:** client and exit limits show when a new month starts in your own time (months follow UTC);
  the domain list hint says that QUIC is off for all sites of such clients and that sites with Encrypted
  Client Hello (ECH) can't be matched by name.

## 1.12.1 — 2026-11-02

- **Rules and lists on one tab.** The **Rules** and **Lists** tabs are now one tab, **Routing**: rules
  and the default exit on top, then the lists, then the route check. An old bookmark to Lists opens
  this tab at the lists.
- **A new list right from a rule:** the **+ list** menu of a rule has **Create a list** (country,
  ASN, link, your own, domains); once saved, the list is already in that rule.
- **Where a list is used:** the lists table shows each rule that uses the list and the exit it
  sends traffic to, and rules of clients; unused lists are marked **not used**.
- **README:** removed a wrong note that domain rules don't see DNS-over-HTTPS and act on whole
  shared (CDN) addresses — that was true only for a design that was never released.

## 1.12.0 — 2026-11-02

- **SOCKS5 exits.** An exit can be a SOCKS5 proxy: `socks5://login:password@host:port` (or
  `host:port:login:password`) in the exit's config field. TCP and UDP go through it; rules,
  fallbacks, limits, traffic counting, Check and Telegram work as with AmneziaWG exits. The panel
  checks the proxy every minute (login and a test connection) and shows its response time.
- **Rules by domain for SOCKS5 exits.** Lists has a new kind, **Domains**: `example.com` also
  covers all its subdomains, and a link to a ready-made list (plain domains, dnsmasq, hosts,
  Adblock, v2ray) is downloaded and refreshed like other lists. A domain list can go only to a
  SOCKS5 exit. The server learns the site from its name at the start of an HTTPS or HTTP
  connection (ports 443 and 80) and passes the name to the proxy, which finds the address itself.
  Client DNS and configs don't change. Domain rules are checked before address rules; other
  connections of such clients follow the address rules as before. QUIC (HTTP/3) is blocked for
  clients with domain rules — browsers switch to regular HTTPS by themselves.
- **Exit window: type first.** Adding an exit starts with **AmneziaWG | SOCKS5**. For SOCKS5
  there are fields for the address, port, login and password; they fill the connection string, and
  a string pasted from a proxy seller fills the fields (pasting one in AmneziaWG mode switches to
  SOCKS5). The same window sets the routing through the exit: sites (domains) to send through it,
  domain and network lists, or all traffic. It is saved as ordinary global rules (the sites become
  the exit's own domain list named after it, deleted together with the exit).
- **Route check** finds domain rules too: checking `www.youtube.com` shows the domain list it matched.
- **Telegram bot: everything in one message.** `/start` opens the menu as buttons in a message
  titled with the server's address (Status | Clients, Exits | New client, Panel | Backup) instead of the keyboard at the bottom of the
  screen, which is removed. Every screen opens in that same message and has **‹ Menu** to go back;
  a client's card also has **‹ Clients**. The personal link and an exit check show up in the
  message itself. After files (QR and config, backup) the menu moves below them, and an older menu
  message is deleted, so there is always one. **Panel** in the menu opens the panel right away.
- **Overview:** the block with the container name is gone; both columns are the same width, their
  headings share one row, and the cards start on one line. Exits are cards with a colored stripe.
- **System → Panel access:** **Install on a phone** sits next to **Check for updates**.

## 1.11.0 — 2026-11-02

- **Bot: a short greeting.** `/start` answers "🤖 AWG Router remote · /help — commands" and opens
  the menu; the full list of commands is in `/help`.
- **Bot: a new menu.** Status | Clients, Exits | New client, Panel | Backup. Route left the menu
  (the `/route` command still works, and an old Route button on the screen is still understood).
- **Bot: Panel** (and `/panel`) sends the panel's address with an Open button. In SSH-only mode it
  sends the `ssh -N -L …` command to open the tunnel instead.
- **Bot: deleting a client.** 🗑 Delete in a client's card asks first; after Yes, delete the client
  is removed the same way as in the panel (its config stops working; end date, limits and personal
  link go too). The event log shows who deleted it.
- **Backup with a password.** **Download backup** asks for an optional password: with one the file
  is encrypted (like the Telegram backups) and opens in **Restore from file** with that password.
- **System → Install on a phone.** Under Access, a button shows how to put the panel on the home
  screen. On a computer it shows a QR code of the panel's address to open it on the phone; on a
  phone with Chrome it opens the install window right away.

## 1.10.6 — 2026-11-01

- **Install and update from releases.** The installer, `awg-router update` and the panel's update
  button now download `awg-router.tar.gz` attached to the latest release instead of the `main`
  branch archive, so you always get a released version, never a commit in between. If a release
  has no archive, the branch archive is used as before. Settings are kept.
- **"Update available" follows releases too**: the panel takes the version from the latest
  release, so it never offers a version whose archive is not out yet.
- Nothing is sent about your server: GitHub only counts how many times the release archive was
  downloaded, which shows the author roughly how many panels install and update.

## 1.10.5 — 2026-11-01

- **`/start` opens the whole menu.** The bot puts every item on the keyboard at the bottom of the
  screen: Status, Clients, Exits, New client, Route, Backup. It stays there, so the bot works by
  taps; the buttons are understood in all four languages. It replaces the ☰ Menu button of 1.10.0.
- **Only their own buttons under messages.** Refresh (and Update to … when a new version is out)
  under the status, client actions and ‹ Clients in a client's card, Check and ⭐ under exits;
  the main menu is not repeated there.
- **Control from Telegram works without notifications.** It needs only the token, the Chat ID and
  **Accept commands and buttons**; before, the bot also required **Send notifications** and stayed
  silent without it, while **Send a test** still worked.
- **The bot no longer stays silent:**
  - command age is measured by Telegram's clock, not the server's: on a server whose clock ran
    ahead, every command looked older than 10 minutes and was skipped;
  - a command from a chat other than the one in Chat ID is still not run, but in a private chat
    the bot answers "No access" with that chat's Chat ID, to put into the panel;
  - a webhook left on the bot by another service is removed once, so commands reach the panel.
- **In the panel**, under Accept commands and buttons: the bot's state, the time of the last
  command and a note when the server's clock is off by two minutes or more (the authenticator-code
  sign-in depends on it too).
- `awg-router logs` no longer hangs in a pipe (`awg-router logs | grep …`): it follows the log only
  in a terminal and otherwise prints the last 2000 lines.

## 1.10.0 — 2026-11-01

- **A new client's first connection.** When a client created in the panel or the bot connects
  for the first time, Telegram gets "Client … connected for the first time — the config works"
  (with a button to open the client when control is on). Handy after sending a friend a QR code.
  It is part of the client notifications and shows in the panel's event log. Clients created
  in the AmneziaVPN app are not tracked; a client that never connects is forgotten after 90 days.
- **Bot: Route in the menu.** Checking where traffic to an address goes no longer needs the
  `/route` command: press Route and send the address.
- **Bot: a Menu button at the bottom of the screen.** After `/help` the bot sets a ☰ Menu
  button in place of the keyboard, so the menu is one tap away even when it has scrolled up.
  It is removed when control is turned off in the panel.

## 1.9.0 — 2026-11-01

- **Control from Telegram.** System → Telegram notifications → **Accept commands and buttons**
  turns the bot into a remote. `/status` shows the server, clients online, this month's traffic,
  the default exit and every exit; `/clients` lists clients with buttons: turn on or off, **QR and
  file** (the QR code as a picture, the `.conf` file and the `vpn://` key for AmneziaVPN),
  personal link, **+30 days** and **+10 GB** for clients with an end date or a limit. `/add Name`
  (or `/add` and then the name) creates a client and sends its QR code at once. `/exits` checks an
  exit and makes it the default; `/route address` shows where traffic to an IP or domain goes;
  `/backup` sends a backup now. A panel update can be started from the bot, and it writes when
  the panel is back.
- **Buttons under notifications** when control is on: +30 days under "access period ended" or
  "ends soon", +10 GB under "limit used up", Check under "exit stopped working", Update under
  "new version".
- Only the chat set in the panel is obeyed; other chats are ignored. Nothing can be deleted from
  the bot and server parameters can't be changed there. Commands are taken through the same path
  as notifications, so they work through an exit where Telegram is blocked. Everything done from
  the bot appears in the panel's event log as "Telegram: …".
- The panel shows whether the bot is receiving commands, or why not.

## 1.8.0 — 2026-11-01

- **Telegram through an exit.** Where api.telegram.org is blocked (Russia, China, Iran), the
  panel's requests to the bot used to time out ("api.telegram.org: timed out", #3).
  System → Telegram notifications → **Send through** picks an exit: messages, backups and
  "Find" for the chat ID then go through its tunnel, the same way as clients' traffic. The name
  is looked up through the tunnel too (DNS to 1.1.1.1 / 8.8.8.8), so a spoofed local answer does
  not get in the way. If the exit is down, its fallback is used; if the fallback blocks traffic,
  the error says so.
- Errors of Telegram backups and notifications are shown in the panel's language.
- **Deleting an exit that is in use.** Before, the panel refused and listed where the exit was
  used, so you had to change every rule, client and fallback by hand. Now **Delete** shows that
  list and asks what to put in its place (the exit's own fallback is picked by default). The
  default exit, rules, clients (including their own rules), other exits' fallbacks and limits,
  and Telegram notifications all switch to it, then the exit is deleted. Where the choice can't
  be used — an exit's fallback pointing to itself, "Block" for Telegram — the deleted exit's
  fallback or "Direct" is used, and an exit's limit becomes "Notify only".

## 1.6.0 — 2026-10-31

- **Server address in client configs: IPv4 or IPv6.** The Server tab finds the server's public
  IPv4 and IPv6 addresses and lets you pick which one goes into client configs (Client settings →
  Address in configs). It is separate from the public address, so the panel link and its
  certificate stay as they are. If the server has no public IPv6, or its port does not seem to
  accept IPv6 connections, the panel says so. Clients re-import their configs after a change.
- **Client DNS is IPv4 only.** An IPv6 DNS server is refused with a clear message (it would not
  answer: the tunnel is IPv4 only); IPv6 DNS saved earlier or found in a backup is left out of configs.
- **Route check and IPv6.** An IPv6 address, or a domain with only an IPv6 address, now gets a plain
  answer ("IPv6 is not routed inside the tunnel") instead of "enter an IP or a domain".
- **Network lists say what they skip.** Manual lists and lists from URLs show how many IPv6 entries
  were left out; a manual list with only IPv6 addresses is refused with its own message.
- README: "IPv4 only" now reads "inside the tunnel, IPv4 only; clients connect over IPv4 or IPv6".

## 1.5.0 — 2026-10-31

- **Masking templates for I1–I5.** The Server tab gets a template picker for the signature
  packets: STUN Binding Request (calls, WebRTC), QUIC Initial (HTTP/3, 1200 bytes as a real one),
  DNS query with EDNS padding, SIP INVITE, a fixed DNS response for icloud.com (the AmneziaVPN default) and "no signature". Headers
  follow the RFCs; IDs, names and keys are random, so no two handshakes carry the same bytes.
- **Per-client masking.** In the client window, Connect → Masking: as on the server, any template
  or custom I1–I5 for this client only. The client list shows a tag for such clients. Useful when
  one provider starts blocking: change only that client and hand out the new QR code.
- **Strict I1–I5 check.** Only the tags every AmneziaWG understands (`<b 0x…>`, `<r>`, `<rc>`,
  `<rd>`, `<t>`); `<c>`, `<d>`, text outside tags, odd hex and packets over 1400 bytes are refused
  with a clear message. The size of each packet is shown under its field.
- **New version in sight.** The status line at the top shows "1.x.y available" (opens System
  with the Update button), and the System tab gets a dot — before, the notice was only on the
  System tab, which is off-screen on phones.

## 1.4.0 — 2026-10-31

- **Update from the panel.** When a new version is out, System shows an **Update** button: the
  panel runs `install.sh --update` on the server as a separate systemd task (so it survives the
  panel's own restart), shows the progress and reloads the page with the new version. If the
  build fails, the previous version keeps running and the log is shown. **Check for updates**
  checks GitHub right away instead of waiting up to 6 hours. Servers without systemd keep using
  `awg-router update`.
- **Backups to Telegram.** The bot can send a backup every day or week, or right away. With a
  backup password the file is encrypted (AES-256, `openssl enc`); restoring such a file in the
  panel asks for the password.
- **Early warnings for clients:** 3 days before the end date and at 90 % of the traffic limit —
  in the log and in Telegram, once each. The client list gets an **Ending soon** filter.
- **Home screen.** The panel can be added to a phone's home screen and opens like an app
  (web app manifest, icons). Chrome on Android shows an **Install as an app** button in System.
- The installer shows its progress spinner only on a terminal.
- Clients tab: search, sorting and "Add client" stay on one line on a wide screen (the button
  used to drop under the search box or squeeze its text into two lines).
- README: new screenshots, including the Exits tab; the exit limit is described as it works
  since 1.3.0 (you choose where traffic goes). `SECURITY.md`: how to report a vulnerability.

## 1.3.0 — 2026-10-30

- **Traffic per exit.** The panel now counts how much client traffic goes through each exit
  and how much goes direct, for the month and all time, and splits each client's monthly
  traffic by exit (client → Manage). Counting runs in a separate nftables table
  (`awgr_acct`) that only counts: it sets no marks or routes, it is not rebuilt when rules
  change (so counters don't reset) and, if the kernel can't load it, the panel turns
  counting off with one log entry and routing works as before. Blocked traffic is not counted.
- **Monthly limit for an exit.** You choose what happens when it is used up: notify only,
  block, go direct or switch to another exit, until the 1st (UTC). This is separate from the
  exit's "if the server stops responding" choice. Log entries and Telegram
  notifications at 90 %, at the limit and when a new month starts.
- Exit cards show monthly and all-time traffic instead of the tunnel counter that reset with
  every tunnel restart.
- Client configs download as `.conf` on Android too (Chrome used to save them as
  `.conf.txt`, which the AmneziaVPN app does not accept).
- Installer: Docker is installed after the questions; a stopped Docker service is started;
  apt waits for a running unattended upgrade instead of failing. Docker Compose and buildx
  are kept at the latest GitHub release on every install and update (checked against their
  sha256); distro packages are only a fallback when GitHub is unreachable (Debian 11/12 have
  only Compose v1, Debian 13 ships buildx 0.13 while Compose needs 0.17+). Images are built
  with `docker build`, so a Compose/buildx version mismatch no longer stops the install.
- System and Server tabs are laid out evenly: cards side by side have the same height, the
  Telegram card spans the width with its events in a second column, obfuscation parameters
  fill whole rows and long parameter names no longer run into the client/server tag.
- The exit limit hint says that traffic inside the tunnel is counted; the footnote under the
  exit cards is gone.

## 1.2.0 — 2026-10-30

- Traffic per client by month and in total, end dates and traffic limits with auto-off,
  personal links for clients, backup and restore, password change in the panel, version check.
- Optional two-factor sign-in (TOTP) and Telegram notifications.
- A panel sign-in lasts 4 hours (was 7 days).
- Traffic is counted from the first sight of a client; auto-refresh no longer interrupts
  typing; unknown personal links answer 404; `Server: httpd`.
- **Fonts are served by the panel itself.** Google Fonts are no longer used: they are blocked
  in China and Iran (the page loaded slowly there) and they told Google about every visit to
  the panel and to personal pages.
- **Lighter auto-refresh.** The panel state no longer carries the text of manual network
  lists. A list of 60 000 subnets used to add almost 1 MB to every 5-second refresh; the
  list editor now loads the text when it opens.
- **The web server resists stuck connections.** A request with a negative or non-numeric
  `Content-Length` is answered with 400 instead of hanging; at most 128 connections at once and 24 from one address;
  slow or silent clients are dropped after 60 s. Static files are revalidated with an ETag
  instead of being downloaded again.
- **Exit tunnels:** the log file is closed after a tunnel starts (each tunnel restart used to
  leave a file descriptor open); a tunnel process that failed to start is reaped.
- **Exit configs:** `FwMark` and `ListenPort` in `[Interface]` are ignored. A foreign
  `FwMark` could match the panel's routing marks.
- **Restore checks every field of a backup** the same way the panel checks its own forms:
  list and exit ids, exit numbers and configs, rules, client policies, keys, limits, personal
  links and settings. A damaged field is named in the error. `PreUp`/`PostUp`/`PreDown`/`PostDown`
  commands from a backup are not restored: a server on the host gets the panel's standard NAT
  rules, a container server gets none (its start script does NAT).

## 1.0.0 — 2026-10-29

- First release: clients, every AmneziaWG 3.1 parameter, exits with fallback, rules by country,
  ASN, URL and manual lists, per-client policies, route check, Let's Encrypt IP certificates.
