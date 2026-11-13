# Changelog

Panels compare their version with the latest GitHub release and show "update available" when
it grows, so every user-visible change gets a new version.

## 1.20.0 — 2026-11-14

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
  against the server's IP instead of `PUBLIC_HOST`, and `--reconfigure` keeps the domain. Saving the Server tab
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
