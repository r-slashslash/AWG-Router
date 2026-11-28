<p align="center">
  <b>English</b> · <a href="README.ru.md">Русский</a> · <a href="README.zh.md">中文</a> · <a href="README.fa.md">فارسی</a>
</p>

<p align="center">
  <a href="https://github.com/r-slashslash/AWG-Router/releases/latest"><img src="https://img.shields.io/github/v/release/r-slashslash/AWG-Router" alt="Release"></a>
  <a href="https://github.com/r-slashslash/AWG-Router/releases"><img src="https://img.shields.io/github/downloads/r-slashslash/AWG-Router/total" alt="Downloads"></a>
  <a href="https://github.com/r-slashslash/AWG-Router/blob/main/LICENSE"><img src="https://img.shields.io/github/license/r-slashslash/AWG-Router" alt="License: MIT"></a>
  <br>
  <a href="https://github.com/r-slashslash/AWG-Router/actions/workflows/release.yml?query=branch%3Amain+event%3Apush"><img src="https://img.shields.io/github/actions/workflow/status/r-slashslash/AWG-Router/release.yml?branch=main&event=push&label=CI&logo=github" alt="CI: unit and network tests, image build"></a>
  <a href="https://github.com/r-slashslash/AWG-Router/actions/workflows/e2e.yml"><img src="https://github.com/r-slashslash/AWG-Router/actions/workflows/e2e.yml/badge.svg" alt="E2E"></a>
  <br>
  <a href="https://github.com/r-slashslash/AWG-Router/attestations"><img src="https://img.shields.io/badge/provenance-signed-brightgreen" alt="Signed build provenance"></a>
  <a href="https://github.com/r-slashslash/AWG-Router/pkgs/container/awg-router"><img src="https://img.shields.io/badge/docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="Docker image on ghcr.io"></a>
  <img src="https://img.shields.io/badge/dependencies-stdlib%20only-brightgreen" alt="Dependencies: Python standard library only">
</p>

# AWG Router

A web panel for **AmneziaWG**: users, tunnel settings, cascade routing and individual routing for each client in one place.

It installs its own AmneziaWG server — in a Docker container or on the host — or takes over a server that already runs, the one the AmneziaVPN app installed (the `amnezia-awg2` container) included, with all its users. Protocol support goes up to **AmneziaWG 3.1**.

**Quick start** — on an Ubuntu or Debian server, as root (Docker is installed if it's missing):

```bash
curl -fsSL https://raw.githubusercontent.com/r-slashslash/AWG-Router/main/install.sh | bash
```

The installer sets up everything, including Docker Compose, and prints the panel link and password at the end. Details: [Install](#install).

<p align="center">
  <img src="docs/screenshots/install.gif" alt="Installing with one command, then the panel: sign in, rules for Russia with one button, a new client with its QR code, exits and routing" width="860">
</p>

```
                               ┌── RU / CN / IR ──────────► internet (this server's IP)
 clients ──AWG──► this server ─┤
                               ├── everything else ──AWG──► server #2 ──► internet
                               └── client "Dad" ─────AWG──► server #3 ──► internet
```

<p align="center">
  <img src="docs/screenshots/overview.png" alt="Overview: exits and where traffic goes" width="860">
</p>

## Cascade VPN (double VPN): local traffic direct, the rest through a server abroad

AWG Router makes your AmneziaWG server the entry point of a cascade. Clients connect to it only, and the server decides where each connection leaves for the internet:
- traffic to the countries, networks or sites you choose goes out directly from the entry server, with its local IP and no detour;
- everything else goes through a second AmneziaWG server (or a SOCKS5 proxy) in another country and reaches the internet from that server's IP;
- there can be several exits: different lists to different servers, or a separate exit for a single client;
- the split (split tunneling) lives on the server, so client configs stay ordinary — nothing to set up on phones or routers;
- exits, lists and rules are set up in the panel instead of hand-written iptables and ipset scripts;
- if an exit goes down, traffic doesn't slip past it: it goes direct, is blocked or moves to another exit, as you choose.

A fallback helps only when it fails separately from the main exit. Two exits to the same server are one path, not two: if its address is blocked entirely, a SOCKS5 proxy over that address and a direct AmneziaWG tunnel to it stop working at the same moment.

So put an exit on a different server in the fallback — a different address, a different host, a different autonomous system. And where possible don't reach the final server directly from a country that blocks: if it is only reached from abroad, its address is not visible there.

Details are in [How routing works](#how-routing-works).

## Features

**Clients**
- Add, rename, disable and delete clients.
- Connect a device with a QR code, a `.conf` file or a `vpn://` link for the AmneziaVPN app.
- Clients created in the AmneziaVPN app show up and can be managed too. The panel can't show their config, because the private key exists only on the device.
- A disabled client stays in the config as a comment, so nobody else takes its address.
- Traffic per client for the month and all time; it survives restarts. A client that is online also shows its speed right now (download and upload) in the list. Sort by name, address, traffic or activity.
- All-time traffic through the server next to the panel name (it stays when clients are deleted).
- The panel's status line starts with what the panel is doing: **Running** (green); **Starting…**, **Restarting the AWG server…**, **Switching the engine…** or **Updating…** (yellow, an update started in the server console too); **Error** or **No connection to the panel** (red; hover for the reason, click to jump to the messages at the top), then the server's CPU and memory load (hover for the load average and how much memory is in use), then clients online.
- If the AmneziaWG server's interface disappears while the container keeps running (for example, the kernel killed `amneziawg-go` when memory ran out), the panel restarts the server by itself and tells you in Telegram. **Server → Restart the AWG server** does it by hand.
- An end date and a traffic limit (per month or in total). When they run out, the client turns off by itself; a monthly limit resets on the 1st at 00:00 UTC (the panel shows when that is in your time) and the client turns back on. Three days before the end date and at 90% of the limit you get a warning, and **Ending soon** in the client list shows who is close.
- Speed limits (off until you set them): a cap for all clients together, a personal cap per client and a cap per exit, download and upload separately. Within the common cap the speed is split evenly between those downloading right now. Connections don't drop, the internet just gets slower, and latency stays low under load.
- A personal link: the person opens it, downloads their config or scans the QR code, and sees their traffic and end date — no panel sign-in. The link exists from the moment the client is created, and the same key is the client's invitation to the Telegram bot: there they see the same and get their config, nothing else of the panel; by choice the bot also reminds them about the end date and the limit (**System → Telegram**). Both are in the client window, under **Connect**; **Renew** there replaces both.
- Light and dark themes with a day/night button in the header. The browser tab shows the server's address or a name you give it (**System → Settings → Server name**) — handy with several servers open.

<p align="center">
  <img src="docs/screenshots/clients.png" alt="Clients: activity, traffic this month, limits and exits" width="860">
</p>

**Server**
- Every AmneziaWG parameter: Jc/Jmin/Jmax, S1–S4, H1–H4, I1–I5, HeaderProtectionKey, ContentPaddingAddition, AWG 3 timings, RandomTrailers and DisableCookies.
- Ready-made masking for the signature packets I1–I5: STUN (calls, WebRTC), QUIC (HTTP/3), DNS query, SIP and a DNS response for icloud.com with Apple’s real address, with random parts so no two handshakes look alike. The packet AmneziaVPN puts in by default (the same everywhere, with icloud.com pointing to a Yandex address) is replaced with this one by the panel itself. I1–I5 are checked strictly (only tags every AmneziaWG understands, packet size shown) and can be set per client: if a client's provider starts blocking, give that one client another masking.
- Fresh parameters on demand, generated the same way as the AmneziaVPN installer does for AWG 3.1.
- Port, subnet, client DNS/MTU/keepalive and the **server incoming address** — the one in client configs (IPv4 or IPv6).
- **Server addresses, incoming and outgoing.** Incoming: other IPs or domains of this server that clients connect to. Any of them can go into all configs or into one client's config (for example, when one address is blocked for that client). Outgoing: other IPv4 addresses of this server (copy them from the hosting panel; on AWS, the internal second address) — the panel adds them to the server's system itself and checks what websites see from each. Every **Direct** in exit choices then comes per address (**Direct — 198.51.100.7**), and an exit through another server can connect from one of them. **Routing → Server addresses** shows each address and where it is used; tap one to tick clients, rules and exits. If an outgoing address stops working, what goes through it is blocked (never sent from another address), an exit connecting from it switches to its fallback, and Telegram says so. The panel itself (updates, lists, the certificate) can go out from a chosen address too (**System → Address the server itself goes out from**), falling back to the system address if it stops working.
- **DNS on the server** (optional): clients ask the server for DNS, and it asks the servers from the settings the same way the client's traffic goes, with a cache and encryption (DoH or DoT). See [DNS on the server](#dns-on-the-server).
- Adding or removing a client is applied live without dropping anyone. Server-side parameters restart the interface, which takes a few seconds.

**Routing**
- Exits are client configs from other AmneziaWG servers or SOCKS5 proxies (`socks5://login:password@host:port`). Both TCP and UDP go through a SOCKS5 exit (UDP if the proxy supports UDP ASSOCIATE); HTTP/3 (QUIC, UDP 443) only with “Let QUIC (HTTP/3) through the proxy” in the exit's window — without it browsers open sites over HTTPS right away. **Check** on the exit shows whether the proxy passes UDP. If an exit fails, its traffic goes direct, gets blocked or moves to another exit, whichever you choose.
- Traffic per exit and direct for the month and all time, and each client's monthly traffic split by exit. An exit can have a monthly limit; when it is used up, its traffic until the 1st goes direct, gets blocked or moves to another exit, whichever you choose (or you only get a notification).
- Rules map a list to an exit. Lists can be countries, autonomous systems (ASN), lists fetched from a URL, your own subnets or domains, and they refresh automatically. Each rule is set up in its own window (**Routing** → **+ Add rule**, or a click on the rule): name, lists — existing ones, a country or a new one made right there — the own DNS of a domain rule, and the exit. There is no separate lists section: a list that is no longer in any rule is deleted with it.
- Domain rules for any exit (AmneziaWG, SOCKS5, Direct or Block): `example.com` on a list also covers all its subdomains, and a whole zone works too (`.ru`, `.cn`, `.net`); you can paste a link to a ready-made list (plain domains, dnsmasq, hosts, Adblock, v2ray). The server learns the site from its name at the start of an HTTPS, HTTP or HTTP/3 connection (TCP 443 and 80, UDP 443). Through SOCKS5 it passes the name to the proxy, which finds the address itself, so DNS spoofing by the ISP doesn't matter; through AmneziaWG and Direct the connection goes to the address the device got from its DNS; DNS on the server resolves such names through the rule's exit, so the address isn't spoofed and is near the exit. Client DNS and configs don't change. Such rules are checked before address rules.
- A rule in a policy reads like what it catches and where it goes: its lists on the left (`Domains work (20)`, an exit's own sites by their first domain `youtube.com +19`, `Russia, China +1`, `Office (12 networks)`), then the exit — right after them on a wide screen, at the right edge on a phone, where a rule whose exit doesn't fit next to its lists shows only the first one and `+N`; a rule's own name shows above it in small grey; a rule that is off stays in its place, grey and struck through.
- The exit window asks for the type first (AmneziaWG or SOCKS5). For SOCKS5 there are separate fields for the address, port, login and password (they make up the connection string; a pasted string fills them in). For both types the routing for that exit is set in the same window: sites (domains) to send through it, domain and network lists, or all traffic. This is saved as ordinary global rules; rules you turned off, rule names and their order stay as they are.
- Each client can have its own exit and its own rules: they replace the shared ones and are set up in the same rule window. All of them are also listed under **Routing → Client rules**, where they can be added, edited and deleted.
- **Load balancing** (optional) instead of the default exit: each client gets the least busy of the chosen exits, measured against the exit's speed limit when one is set. If one exit is overloaded while another sits idle, some clients are moved over within a few minutes without dropping their open connections; a failed exit's clients move at once. Rules and clients' own exits still apply.
- **Load balancing inside a rule**: pick **Load balancing** as the rule's exit and tick its exits — the rule's clients are spread across them the same way. If none of them works, the rule's traffic is blocked (or goes where you choose).
- **Traffic by rule**: under each rule and **Default** on **Routing**, how much all its clients downloaded and uploaded this month; in the client window, the client's traffic by each of its rules (this month and last). The rule window shows who used the most by that rule this month.
- A rule can have a **monthly traffic limit** for all its clients together: when it is used up, until the 1st the rule's traffic goes direct, gets blocked or moves to another exit, whichever you choose (or you only get a notification). And a **speed limit**, download and upload separately, also for all its clients together. A client's own rules start as a copy of the shared ones without these limits. A connection that is already open keeps the speed limit it started with until it reconnects.
- **Route check** shows which way an IP or domain would go.

<p align="center">
  <img src="docs/screenshots/exits.png" alt="Exits: traffic per exit and direct, monthly limits, speed now and speed limits" width="860">
  <img src="docs/screenshots/routing.png" alt="Routing: the rules from “Apply for Russia” and the rule window — the list of .ru sites, their own DNS and the exit" width="860">
</p>

**Panel**
- HTTPS with a Let's Encrypt certificate for the server's IP or your domain, renewed by itself, or with your own certificate (for example, from certbot). If nginx or Apache already holds port 80, validation goes through it; a domain whose DNS is in Cloudflare can be validated through Cloudflare instead, without port 80.
- Alternatively, the panel can be reachable only through an SSH tunnel.
- The address uses a random port and a secret path, and login is password-protected with brute-force protection. A sign-in lasts 4 hours.
- Optional second factor: a 6-digit code from an authenticator app (Google Authenticator, Aegis, 2FAS…). Turned on in **System**.
- Optional Telegram notifications: an exit stops or recovers or nears its limit, a server outgoing address stops or works again, the AmneziaWG server is unreachable or restarted, server memory stays above 90% or CPU above 95%, a client nears or hits its end date or limit, a new client connects for the first time, panel sign-ins, a certificate that can't be renewed, a new panel version, and, if you tick it, last month's totals on the 1st (the server, exits and rules). Set up in **System**. Where Telegram is blocked (Russia, China, Iran), the bot can send through one of your exits; if the chosen path doesn't work, the bot tries others (**If it fails, try other paths**, on from the start): from Direct — your exits one by one, from an exit — the other exits, but never directly. A path that works is kept, the chosen one is tried again every 10 minutes; if nothing works, messages wait for a connection. This covers everything the bot does: notifications, control, messages to clients and backups. **Turn on the bot** is the main switch: off means the bot is silent.
- Optional control from Telegram: the bot becomes a remote: `/start` opens the menu in a single message — a picture with the VPN server's address, how many exits are online, the panel version, clients, how many are online and all-time traffic (**Refresh** draws it again) — and everything happens in that message, with a ‹ Menu button to go back. **Server** holds the status, also as a picture (whether the server is running, versions, IPv4 and IPv6, DNS on the server, uptime, RAM, traffic this month) and the exits (tap an exit to check it or make it the default); **Clients** starts with **New client**. Also: turning a client on or off or deleting it (after a confirmation), its QR code and config file, +30 days or +10 GB, a new client with `/add`, checking an exit and changing the default one, where traffic to an address goes, a backup, a link to the panel and a panel update. Buttons also appear under notifications (for example, +30 days under “access period ended”). Only the chat with the numeric Chat ID set in the panel is obeyed (a `@name` can later be taken by someone else); a command from another chat is not run, and in a private chat the bot answers it with that chat's number.
- The password can be changed right in the panel.
- Backup and restore in one file: panel settings, exits, rules, client keys and the AmneziaWG server config — handy for moving to another server. The server's own addresses (incoming, outgoing, the panel address) and its name stay as they are on the server you restore to: after a reinstall, enter them again before restoring. The downloaded file can be encrypted with a password. The bot can also send a backup to Telegram every day or week, encrypted with a password if you set one.
- The panel shows its version, tells you when an update is out and updates itself with one button (or `awg-router update` on the server). Only a released version is installed, and its archive is checked against its checksum.
- Can be installed on a phone: **System → Install on a phone** shows a QR code and how to add the panel to the home screen, where it opens like an app.
- Languages: English, Russian, Chinese and Persian. The language follows the browser or system setting, and a manual choice is remembered.

<p align="center">
  <img src="docs/screenshots/client-connect.png" alt="Connecting a client with a QR code" width="420">
  <img src="docs/screenshots/server.png" alt="Server settings" width="420">
</p>

<p align="center">
  <img src="docs/screenshots/mobile.png" alt="The panel on a phone" width="300">
</p>

## Install

You need an **Ubuntu 20.04+ or Debian 11+** server (22.04+ or 12+ for the kernel module), x86_64 or arm64; if `curl` is missing: `apt-get install -y curl`. Run this as root (if you log in as another user, run `sudo -i` first). If Docker is missing, the installer sets it up.

```bash
curl -fsSL https://raw.githubusercontent.com/r-slashslash/AWG-Router/main/install.sh | bash
```

The installer downloads the panel into `/opt/awg-router` and asks a few questions:

1. **What to manage.**
   - If it finds an AmneziaVPN container, it offers to manage that container or a separate AmneziaWG server on the host.
   - If there's no AmneziaWG on the server, it offers to install one, either in a Docker container like AmneziaVPN does (the app will see it too) or directly on the host as a systemd service. It suggests a random UDP port.
2. **How to open the panel.** Choose a browser over HTTPS, or an SSH tunnel only.
3. **Engine** (only when the server can take the kernel module). Enter — the kernel module (see [AmneziaWG engine](#amneziawg-engine)).
4. **Panel port.** Enter — a random free 4-digit one.
5. **Panel domain** (browser only). Press Enter to open the panel by IP; a domain must point to this server. With a domain it also asks which address goes into client configs.

If port 80 is already taken by nginx or Apache, the installer shows the small file it can add there for the Let's Encrypt validation and asks before adding it (see [Port 80 is taken by a web server](#port-80-is-taken-by-a-web-server)).

The rest is automatic: a password, the panel image, the certificate. The image is downloaded ready-made from GitHub's registry (ghcr.io), so the server doesn't have to reach Alpine and GitHub sources, which are filtered in some countries; if the download fails, the image is built on the server as before (`AWGR_BUILD=1` always builds it). At the end it prints the link and password:

```
  AWG Router is ready
  Link:     https://203.0.113.5:4721/3f9a1c2e7b6d/
  Password: Xk3vQ9mT2pLw8ZrA
  Let's Encrypt certificate valid until 2026-11-04 08:15, renews automatically
```

> **Firewall:** open the AmneziaWG **UDP** port (**Server → Port (UDP)** in the panel), TCP port **80** (used for a few seconds while Let's Encrypt validates) and the panel port. If your hosting provider has its own firewall in its control panel (AWS, Oracle, Google Cloud…), open them there as well: without the UDP port the panel opens, but clients can't connect.

### If something doesn't work

- The panel doesn't open: check the firewall (above) and run `awg-router info` for the exact link.
- Logs: `awg-router logs` (Ctrl+C to stop). If the first install stopped with an error, there is no `awg-router` command yet: run the install command again, or look at `docker logs awg-router` and `/opt/awg-router/data/*.log`.
- Clients don't connect: the UDP port must be open in the hosting firewall too.
- When you open an issue, give the version, the server mode and the log (remove passwords and keys).

### The `awg-router` command

| Command | What it does |
|---|---|
| `awg-router info` | show the link and password |
| `awg-router update` | download the latest version and update (settings are kept) |
| `awg-router password` | set a new random password |
| `awg-router 2fa-off` | turn off the authenticator code (if you lost your phone) |
| `awg-router restart` | restart the panel |
| `awg-router logs` | show the panel log |
| `awg-router reconfigure` | choose the mode and access method again; can also move the AmneziaWG server from its container to the host with the same keys, port and clients |
| `awg-router install-kernel` | build and load the AmneziaWG kernel module (see [AmneziaWG engine](#amneziawg-engine)) |
| `awg-router uninstall` | remove the panel and its routing rules; asks whether to keep the AmneziaWG server it installed (kept by default; its keys live in `/opt/awg-router/awg-server`, so don't delete the folder while it runs), then whether to remove the panel settings in `/opt/awg-router` too (kept by default, and a new install picks them up; not asked while the kept server's keys are there) |

### Going back to an earlier version

Run as root (in a root shell: `sudo` with the variable in front of it drops the variable):

```bash
AWGR_SRC_URL=https://github.com/r-slashslash/AWG-Router/releases/download/vX.Y.Z/awg-router.tar.gz awg-router update
```

Settings, clients and backups stay. An archive given this way isn't checked against a checksum. What the earlier version doesn't know is written in the release notes of the version you leave, under "Going back". `awg-router update` without the variable brings the latest version back.

### Access through an SSH tunnel

In this mode the panel isn't reachable from the internet. On your computer or phone (Termux), run:

```bash
ssh -N -L PORT:127.0.0.1:PORT root@SERVER_IP
```

Keep it running and open `http://127.0.0.1:PORT/secret-path/`. Run `awg-router info` to get the exact command and address.

## Certificate

- The panel gets a Let's Encrypt certificate with [lego](https://go-acme.github.io/lego/) for the server's IP or the panel domain, validating over port 80, and renews it without a restart. For an IP address Let's Encrypt issues only 6-day certificates (the `shortlived` profile), so the panel renews about every 3 days.
- **System → Panel address** is the IP or domain the panel opens at and the certificate is for; **System → Certificate settings** chooses Let's Encrypt or your own certificate. For your own, give the paths on the server to the certificate (full chain) and the key, for example certbot's `/etc/letsencrypt/live/example.com/fullchain.pem` and `privkey.pem`. The panel checks that the certificate is for the panel address and that the key matches; when certbot renews it, the panel picks up the new one within a few minutes.
- **Through Cloudflare** (for a domain whose DNS is in Cloudflare): in the same window choose **How to verify the domain → Through Cloudflare** and paste a Cloudflare API token with **Zone → Zone → Read** and **Zone → DNS → Edit** for that domain only (Cloudflare: **My Profile → API Tokens → Create Token**). Let's Encrypt then checks a TXT record that the panel adds through the Cloudflare API, so port 80 and a web server aren't needed. The panel checks the token before saving it; the token is kept only on this server (`data/tls.json`, readable by root only), isn't part of backups and is removed when you switch back to port 80. Such certificates are the usual 90-day ones. This only gets the certificate: the domain's record in Cloudflare must be **DNS only** (grey cloud) — behind Cloudflare's proxy (orange cloud, the default for a new record) the panel doesn't open by the domain.
- With IPv6 in use (an IPv6 **Panel address**, or IPv6 picked as the **Server incoming address**), the certificate covers both the server's IPv4 and IPv6 addresses, so the panel opens without a warning at either. If Let's Encrypt can't validate the second address (for example, port 80 is closed over it), the certificate covers the main one and the panel tries the second again a day later. Through a web server on port 80 the certificate covers only the main address.
- The panel address is only the panel's: client configs use the **Server incoming address** from the **Server** tab, and changing one doesn't change the other. The installer offers to put the panel domain into configs too.
- If issuance fails, the panel runs with a temporary self-signed certificate, so the browser will show a warning. It retries every 30 minutes.
- The status is on the **System** tab; **Get a certificate now** is in **Certificate settings**.

### Port 80 is taken by a web server

If nginx or Apache already serves sites on this server, Let's Encrypt validates the panel through it. The installer and **System → Set up validation through the web server** show the file first and add it only when you agree:
- nginx (also Angie and OpenResty) on the host or in Docker when its config folder is mounted from the host: `awg-router-acme.conf` next to your configs (`conf.d`, `sites-enabled`). Apache on the host: a site `awg-router-acme.conf`.
- The file answers only `/.well-known/acme-challenge/` and only for the panel address, from the folder `/var/lib/awg-router/acme`. Your sites and other config files don't change.
- Before the reload the config is tested (`nginx -t`, `apachectl configtest`), then the panel requests a test file through the web server. On any error the file is removed and the web server goes back to its previous settings.
- Caddy, other web servers, and containers with the config inside the image: the panel shows the block to add by hand, then press **Check**.
- **Remove from the web server** and `awg-router uninstall` delete the file.

## Server modes

### AmneziaVPN container

The panel writes the config in the app's own format:
- a shared PSK;
- `clientsTable` with client names;
- I1–I5 kept as comments.

Clients added in the panel appear in the app, and vice versa.

Limitations:
- Changing the port in the panel re-creates the container with the same files and the new port; the VPN pauses for a few seconds. Clients created in the app keep their key only on the device: after the change they need the new port in their config, or a new client from the panel.
- In a container created by the AmneziaVPN app the subnet can't be changed either: the app writes it into the container's start script.
- If you change server-side parameters in the panel (S1–S4, H1–H4, header protection key), the app doesn't learn about it. New clients from the app won't connect until you re-check the server in the app, which reads the parameters back from the server.
- After the server reboots, a container created by the AmneziaVPN app starts before the panel and without its rules: for a few seconds, until the panel starts, clients go direct, past the exits. The panel's own container and a server on the host put the panel's rules up before the VPN starts. If this matters, move the server to the host with `awg-router reconfigure` (the same keys, port and clients).

If the AWG Router installer created the container, its configs live on the host in `/opt/awg-router/awg-server/data` and survive re-creating the container.

### AmneziaWG on the host

The panel installs `awg`, `awg-quick`, `amneziawg-go` (AWG 3.1) and the `awg-quick@awg0` service.
- The config is at `/etc/amnezia/amneziawg/awg0.conf`.
- NAT and forwarding are set up in `PostUp`, so the VPN keeps working even when the panel is stopped. When you change the subnet, the panel moves NAT to the new one.

## AmneziaWG engine

AmneziaWG runs either as a Linux kernel module or as the `amneziawg-go` program.

- **The kernel module** (recommended) encrypts inside the kernel and uses several times fewer system resources, with more speed. It shows most on a small VPS with many clients and in a cascade, where every packet is encrypted twice (on the server and in the tunnel to the exit). The module is built for your kernel (DKMS) and rebuilt by itself when the kernel is updated. Ubuntu 22.04+ or Debian 12+ (kernel 7.x included), x86_64 or aarch64, and a VPS that isn't OpenVZ/LXC are needed.
- **amneziawg-go** works on any server, OpenVZ/LXC included, and comes with the panel, but encryption takes a noticeable share of system resources.

How to get the module:
1. On a new install the installer asks which engine to use when the server fits; Enter picks the module. To answer in advance: `AWGR_ENGINE=kernel` or `AWGR_ENGINE=go`.
2. On an installed panel: the **Install the module** button (in the notice at the top or in **Server → AmneziaWG engine**), or `sudo awg-router install-kernel` on the server. The module is built from the Amnezia PPA, checked to be 3.x (an older one is removed) and loaded at boot (`/etc/modules-load.d/amneziawg.conf`). Then the panel offers to restart the AWG server: it picks the module by itself (awg-quick prefers the kernel).
3. Tunnels to exits follow the server: on the module too, with nothing to pick. To keep exits on one engine regardless of the server (for example, to read the amneziawg-go logs while looking into a problem), set `EXIT_ENGINE=go` or `EXIT_ENGINE=kernel` in `/opt/awg-router/.env` and run `cd /opt/awg-router && docker compose up -d` (`awg-router restart` doesn't apply changes in `.env`).

If something is wrong with the module, the server stays reachable:
- the module didn't build or load — the installer or the button says so, and the server runs on amneziawg-go;
- after a kernel update the module no longer loads — the server comes up on amneziawg-go by itself, and the panel says so (in Telegram too) and offers to install the module again;
- the server didn't come up on the module after two restarts — the panel switches the module off, moves the server to amneziawg-go and tells you; **Try again** brings the module back;
- the module couldn't start a tunnel to an exit — exits run on amneziawg-go until the next server restart.

Installing the module also sets `kernel.panic = 10` unless you have your own value: after a crash in the kernel the server reboots by itself instead of hanging. **Server → AmneziaWG engine** shows what the server runs on and which module is loaded. The AmneziaVPN app may install a kernel module by itself; if it is older than 3.x while the server uses AWG 3.1 parameters, the panel warns (in Telegram too). To switch engines by hand, use **Engine** in the same block: amneziawg-go restarts the AWG server without the module (the module stays installed but is not loaded), the kernel module loads it again (or installs it first) and restarts the server; clients reconnect within seconds. To remove the module completely: `apt remove amneziawg-dkms && rm -f /etc/modules-load.d/amneziawg.conf`, then reboot the server.

## DNS on the server

Turned on in **Server → DNS → DNS on the server**; off by default. It is similar to AmneziaDNS in the AmneziaVPN app, but built with the cascade in mind.

**How it works.** The panel runs a small DNS server in the AWG server's network (`dnsproxy.py`, port 53 on the server's tunnel address, for example `10.8.1.1`). Clients get its address in the `DNS` line of their config, and the first server from the "DNS" field as the second one. The server does not resolve names itself: it forwards the query to the servers from the "DNS" field **through this client's main exit** (if the exit is down, through its fallback, like the traffic). Answers are cached for their TTL separately for each exit, so a repeated query does not cross the cascade.

**Every DNS query.** While it is on, the server also answers queries the clients send to any other DNS server — the second DNS in their config, a DNS typed into a device or an app, a private address: no name goes past the exit or unencrypted, and configs issued earlier keep working.

**Encryption.** Queries to the servers from the "DNS" field are encrypted — the **DNS query encryption** setting:
- **DoH** (default) — DNS over HTTPS, port 443, over HTTP/2 or HTTP/1.1, whichever the server picks. It looks like ordinary HTTPS and is the hardest to block;
- **DoT** — DNS over TLS, port 853;
- **no encryption** — plain DNS.

With encryption, neither the entry server's ISP nor the exit's ISP can see which sites clients open or spoof the answer: the server's certificate is checked. TLS connections are kept open, so the handshake is not repeated for every query. The servers in the "DNS" field must support encryption: `1.1.1.1`, `1.0.0.1` (Cloudflare), `8.8.8.8`, `8.8.4.4` (Google), `9.9.9.9`, `149.112.112.112` (Quad9) do. If the encrypted channel is unavailable, plain DNS is not used instead: the client asks the second DNS from its config, and the panel shows "DNS servers don't answer". The exception is **Fallback DNS for "Direct"** (**Server → DNS**, off by default): when the DNS servers don't answer on a Direct path — in Russia, China and Iran the encrypted connection to them is often cut — names of clients that go Direct are asked there, from the same outgoing address and exactly the way it is written (plain, DoH or DoT); the Server tab says when it is in use. One slow site or one lost packet doesn't switch it on: the panel first checks the DNS servers (a fraction of a second when they answer); where the encrypted connection is really cut, the fallback takes over as fast as before. Paths through an exit never do this.

**The cascade catch.** A resolver on the entry server that asks the internet straight from there (this is how AmneziaDNS works) gets answers as seen from the entry country. CDNs judge where the client is by the resolver's address and return nodes near the entry server, while the traffic goes out through an exit in another country: sites and video load slowly, and services that check the region may refuse. AmneziaDNS encrypts its queries, so the ISP can't spoof the answers, but it can block the encrypted connection itself.

Here a query takes the same way as the client's traffic, so clients that go out through another server get answers right for their country. For clients whose main route is "direct", queries leave straight from the entry server, as with AmneziaDNS. That's right for them: their traffic leaves from there too, and encryption protects the queries from the ISP.

**Names from domain rules.** A name on a domain rule's list is resolved through that rule's exit (with its fallback, like the traffic), not through the client's main exit: the address comes from near the exit the connection will take, and the ISP can't spoof it. For a Direct rule the query leaves straight from the server; for a Block rule it takes the client's usual way. With **Domain rules only for addresses from this DNS's answers** ticked, only connections to the addresses this DNS gave for such names go to the domain handler; the rest of these clients' traffic stays in the kernel. A new address is on that list before the answer reaches the device, so the very first connection to it already goes the rule's way, and it stays there while devices keep asking for the site (except a short moment while the panel applies changed rules).

Limits:
- a client with a block gets a refusal;
- a query for an IPv6 address (AAAA) gets "no records": the tunnel carries only IPv4, so apps go to IPv4 straight away;
- rules by addresses (for example, "local networks direct") don't affect DNS: names of such sites are also resolved through the client's main exit, and a CDN may return a node abroad for them;
- the server only forwards queries and does not validate DNSSEC itself — the servers from the "DNS" field do;
- your own AdGuard Home in the "DNS" field answers one address at most 20 queries a second by default (**Rate limit** in its DNS settings), and all the panel's queries come from one address: on a server with many clients raise it or set 0;
- while the panel restarts or updates, names don't resolve for a few seconds; while it is stopped — until it starts (with **When the panel is stopped → Send everything direct** the queries go to the servers they were sent to);
- in host mode with an nftables-only firewall (for example, firewalld), allow incoming UDP and TCP port 53 on the clients' interface; with iptables or ufw the panel does it itself.

**Own DNS of a domain rule.** A domain rule can have its own DNS server (one or two: an IPv4 address for plain DNS, `https://…/dns-query` for DoH, `h3://…/dns-query` for DoH over HTTP/3 only (it goes over UDP, and an ISP may cut it separately from HTTPS — put `https://` as the second entry; Google, Cloudflare and Alibaba serve it, AdGuard doesn't answer it from every network, Quad9 and Yandex don't), `tls://…` for DoT, **Routing → rule → Own DNS for these sites**): names from its lists are asked there — the same way the rule's sites go, exactly the way it is written — and everything else goes to the usual servers. For example, Russian sites (`.ru`, `.su`, `.рф` on the list) go direct and are asked from Yandex DNS (`77.88.8.8`), Chinese ones from Alibaba (`223.5.5.5`), and the rest through the exit to `1.1.1.1` over DoH. The local DNS learns only about local sites. Only domain lists can do this: an address list can't pick a DNS server, because the address is known only from the DNS answer. **Ready rules** (for a cascade, when everything else goes through an exit)**:** while there are no rules, **Overview → Shared rules** has **Apply for Russia / China / Iran**: the country's addresses and domains (`.ru`, `.su`, `.рф`; `.cn`, `.中国`, `.中國`; `.ir`, `.ایران`) go Direct, the domains with that country's DNS, the fallback DNS is set to it, and DNS on the server is turned on (with clients already issued it asks first: their configs keep the old DNS until imported again). Pressing it again makes the country's rules as at the first press (Direct, on, the country's current DNS, at the end); speed and monthly limits stay. On **Routing** these buttons are always there, next to **+ Add rule**. A new install starts without rules. The address of DNS on the server itself can't be a rule's own DNS: it would do nothing.

**How to use it best.**
1. Keep **DoH** encryption and servers that support it in the "DNS" field, for example `1.1.1.1, 8.8.8.8`. Your local ISP's servers don't fit: queries to them go through the exit anyway, and they usually can't do encryption.
2. Turn it on if most clients' main route is through an exit.
3. After turning it on or off, give clients new configs (QR codes or files): old ones keep asking the previous DNS.
4. A separate AmneziaDNS is not needed then; if it is installed, the panel leaves it alone.

## How routing works

The panel runs in its own container (`network_mode: host`, `pid: host`, `privileged`) and enters the AWG server's network namespace with `nsenter`.
- Each exit gets a tunnel `awgrN` with its own routing table. For a SOCKS5 exit it is a [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) interface: whatever enters it goes through the proxy.
- Domain rules: TCP 80/443 of clients that have them is redirected to a handler in the server's network (`sniproxy.py`). It reads the site name (SNI or Host); on a match the connection goes through the SOCKS5 proxy by name, or, for an AmneziaWG exit and Direct, to the original address with that exit's mark; otherwise to the original address with the client's policy mark, and the usual address rules pick the path (an nftables `type route` chain in the output hook). Data is relayed inside the kernel (`splice`), not copied through Python. HTTP/3 (QUIC, UDP 443): the first packets of a new connection of such clients go to a kernel queue (NFQUEUE); the handler reads the name from the QUIC Initial packets (v1 and v2, a ClientHello split across packets is put back together) and marks the packet with the exit's mark (an AmneziaWG exit, Direct), or rejects it for Block and for SOCKS5 without “Let QUIC (HTTP/3) through the proxy” (the browser then takes HTTPS, where the proxy gets the name); with that box ticked QUIC goes through the proxy over UDP ASSOCIATE; sites not on the lists go by the usual rules; the decision is kept in conntrack for the rest of the connection. A ClientHello that doesn't come together in 100 ms is rejected. With DNS on the server turned on, names from domain rules are resolved through the rule's exit; an optional setting intercepts only the addresses this DNS returned for those names (an nftables set with timeouts), so the rest of the traffic goes through the kernel. The panel looks at the handler every second and restarts it if it exits or hangs; while it is down, the panel removes the redirect and only address rules apply — or, with **Routing → If domain rules don't work, block all traffic of their clients**, those clients are blocked until it works again.
- Client packets are marked by nftables rules in the `ip awgr` table.
- The tunnel address on the exit server is applied with SNAT, so it never clashes with your clients.
- Outgoing addresses: **Direct — address** is its own mark with its own routing table (`default via <gateway> src <address>`). On the host the panel adds the address to the internet interface (label `<interface>:awgr`) and swaps the sender address for it (`snat`, before the usual masquerade); in the AmneziaVPN container mode each address is a Docker network with `com.docker.network.host_ipv4`, connected to the AWG container, and the container's route for the mark leads into it. Guards in `c_forward` and in `postrouting` drop a marked packet that is about to leave another way or from another address, so a broken address never leaks out from the main one. An exit connecting from an address carries the mark too (`FwMark` of the AmneziaWG tunnel, `mark` of hev-socks5-tunnel). When an exit choice changes by hand, the panel closes only the connections whose path changed (`ctflush.py`, conntrack over netlink; the domain handler closes its own); load balancing and fallbacks don't close anything.
- If a tunnel disappears, an `unreachable` route stays in its table, so traffic never leaks around the exit.
- While the panel is stopped or updating, traffic through exits is blocked; **System → Settings → When the panel is stopped → Send everything direct** sends it out from this server's IP instead (past the exits).
- A newly started exit (panel start or update, AWG server restart, an edited exit) gets up to 30 seconds to answer, and until then its clients are blocked rather than sent to the fallback; usually it answers within a second. With the fallback "Direct" its clients used to go direct for about 10 seconds after every panel start.
- Traffic by rule: the policy chains give each connection a conntrack label (`ct label`) with the number of its rule, and a separate table (`awgr_racct`) counts bytes per client and rule; the domain rule handler counts its own connections. A rule's speed limit is one nftables `limit` per rule and direction: what goes over it is dropped where packets arrive at the server (from the client and from the internet), which the sender sees as ordinary loss, so TCP slows down. On GitHub's test machine this added 2–7% to the CPU time spent forwarding.
- Load balancing pins each client to one exit, and each connection remembers its exit in conntrack (`ct mark`), so moving a client sends only its new connections through the new exit. Speed limits are `tc` HTB queues: on the clients' interface (`awg0`) for clients and on `awgrN` for exits; incoming traffic is shaped through an `ifb` device.

Everything that's applied is visible on the **System** tab under **What's applied right now**.

## Security

The panel effectively has root access to the server.
- The password is long and random, and the address includes a random port and a secret path.
- After 8 wrong passwords, logins from that IP are blocked for 10 minutes. Behind your own reverse proxy (nginx and the like in front of the panel) every visitor comes from the proxy's address, so 8 wrong passwords from anyone block everyone, you included; open the panel directly or through an SSH tunnel instead.
- The most locked-down option is access through an SSH tunnel only.
- Private keys of exits and of clients created in the panel are stored in `/opt/awg-router/data/state.json`, with permissions 600.
- Telegram control obeys a chat, not a person: if that chat is a group, every member can control the panel, and in a channel every subscriber can press the buttons under notifications. Use a private chat with the bot.
- Clients can't reach the cloud's service addresses: `169.254.169.254` (server data, on AWS also keys to the cloud account) with the whole link-local network, and `100.100.100.200` (the same on Alibaba Cloud).
- Private networks of the server (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` — for example the hosting's internal network) are reached from the server itself whatever the rules say, also with **Block**; rules with such networks don't apply.
- A client's personal link and bot invitation give that client's config to whoever opens them: send them only to that person. **Renew** in the client window makes the old ones stop working.
- A backup holds the private keys of the server and of all clients. Set a password for downloaded backups and for backups sent to Telegram.
- Starting with 1.19.1, the images and the archive are built by GitHub Actions and carry a signed build attestation, and the images also have an SBOM (list of components). You can check a download with `gh attestation verify oci://ghcr.io/r-slashslash/awg-router:<version> -R r-slashslash/AWG-Router` (images) or `gh attestation verify awg-router.tar.gz -R r-slashslash/AWG-Router` (the archive).

## Limitations

- Inside the tunnel, IPv4 only. Clients connect to the server over IPv4 or IPv6, and the panel opens over both. Outgoing addresses are IPv4 only.
- From a chosen outgoing address the panel downloads lists and updates and gets the certificate, but Docker downloads images from the system address, and so do lego's DNS lookups when the domain is verified through Cloudflare.
- Domain rules see HTTPS, HTTP and HTTP/3 (TCP 443 and 80, UDP 443) and can't see the site when the browser hides the name (Encrypted Client Hello); such connections follow the address rules. Without a packet queue in the kernel (`nfnetlink_queue`, missing on some OpenVZ/LXC servers) HTTP/3 is turned off for all sites for clients with domain rules, as before 1.21.0. In host mode with an nftables-only firewall (for example, firewalld), allow incoming TCP port 10443 on the clients' interface; with iptables or ufw the panel does it itself.
- SOCKS5 exits need IPv6 support in the kernel (always there, except on servers booted with `ipv6.disable=1`).
- Exits over IPv6 in the AmneziaVPN container mode need IPv6 in Docker: by default the container's network has none, and the panel says so instead of a bare “no connection”. Add `"ipv6": true, "fixed-cidr-v6": "fd5a:3c71:9e20::/64", "ip6tables": true` to `/etc/docker/daemon.json` (keep what is already there; Docker older than 27 also needs `"experimental": true`) and run `systemctl restart docker` — this restarts every container. Or give the exit an IPv4 address or a domain with an A record. Without restarting Docker: move the AmneziaWG server to the host with `awg-router reconfigure` (the same keys, port and clients, so client configs keep working) — there the exits use the host's own network, IPv6 included.
- Country lists are built from registry data. For a specific service, an ASN list is more accurate.
- Traffic by rule and a rule's monthly and speed limits need connection labels in the kernel (`ct label`; missing on some OpenVZ/LXC servers). Without them the panel says traffic by rule isn't counted; everything else works.
- Load balancing (the default one or inside a rule) moves clients between exits by load alone: it can't see that a site dislikes one exit's address (for example, Google keeps asking “I'm not a robot” there). Send such sites through one exit with a rule of their own.
- Upload limits for clients and download limits for exits need the kernel's `ifb` module. The installer adds it (`linux-modules-extra` on cloud kernels); if the kernel has no such package, the panel says so and the other limits still work.

## Development

```bash
python3 -m unittest discover tests                                     # configs, nftables, parameters
sudo PYTHONPATH=<pyroute2>:. python3 tests/netns_e2e.py                 # routing in network namespaces
sudo PATH=<awg,amneziawg-go>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/awg_real_e2e.py
                                                                        # a real AWG tunnel client ↔ server
sudo PATH=<hev-socks5-tunnel>:$PATH PYTHONPATH=<pyroute2>:. python3 tests/domains_socks_e2e.py
                                                                        # a SOCKS5 exit and domain rules
DRY_RUN=1 PANEL_PASSWORD=demo DATA_DIR=./demo python3 -m app.main       # demo without a server
```

The panel has no Python dependencies outside the standard library. The Docker image adds `amneziawg-go`, `amneziawg-tools`, `hev-socks5-tunnel` and `lego`.

## Credits

### People who helped

They found problems, traced them down to the line of code and suggested solutions; a lot of this panel exists because of them.

<table>
<tr>
<td align="center" valign="top" width="33%"><a href="https://github.com/Neborya"><img src="https://github.com/Neborya.png?size=128" width="72" alt=""><br><b>Neborya</b></a><br>🐛 💡<br><sub>Compose package on Debian 13 <a href="https://github.com/r-slashslash/AWG-Router/issues/1">#1</a>, traffic per exit <a href="https://github.com/r-slashslash/AWG-Router/issues/2">#2</a>, Telegram through an exit <a href="https://github.com/r-slashslash/AWG-Router/issues/3">#3</a>, port 80 shared with a web server <a href="https://github.com/r-slashslash/AWG-Router/issues/4">#4</a>, client names in configs <a href="https://github.com/r-slashslash/AWG-Router/issues/7">#7</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/koo-pub"><img src="https://github.com/koo-pub.png?size=128" width="72" alt=""><br><b>koo-pub</b></a><br>🐛 💻 🔍<br><sub>QR codes that scan reliably in AmneziaWG on Android <a href="https://github.com/r-slashslash/AWG-Router/issues/5">#5</a>, the panel domain in client configs <a href="https://github.com/r-slashslash/AWG-Router/issues/22">#22</a> <a href="https://github.com/r-slashslash/AWG-Router/pull/23">#23</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/LCF30"><img src="https://github.com/LCF30.png?size=128" width="72" alt=""><br><b>LCF30</b></a><br>🐛 💻 🔍<br><sub>exits with a domain name in Endpoint <a href="https://github.com/r-slashslash/AWG-Router/issues/6">#6</a>, ready images for Russia, China and Iran <a href="https://github.com/r-slashslash/AWG-Router/issues/8">#8</a>, SOCKS5 exit health <a href="https://github.com/r-slashslash/AWG-Router/issues/9">#9</a>, Telegram alerts that don't depend on the failing exit <a href="https://github.com/r-slashslash/AWG-Router/issues/10">#10</a>, release download through the GitHub API when github.com fails <a href="https://github.com/r-slashslash/AWG-Router/pull/13">#13</a></sub></td>
</tr>
<tr>
<td align="center" valign="top" width="33%"><a href="https://github.com/alexeyvolodin"><img src="https://github.com/alexeyvolodin.png?size=128" width="72" alt=""><br><b>alexeyvolodin</b></a><br>💻 🔍<br><sub>domain rules relayed inside the kernel <a href="https://github.com/r-slashslash/AWG-Router/pull/19">#19</a>, busy port check in the installer <a href="https://github.com/r-slashslash/AWG-Router/pull/17">#17</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/paris19891"><img src="https://github.com/paris19891.png?size=128" width="72" alt=""><br><b>paris19891</b></a><br>🐛 💡 🔍<br><sub>IPv6 exits and the panel address in the container mode <a href="https://github.com/r-slashslash/AWG-Router/issues/20">#20</a>, the kernel module engine <a href="https://github.com/r-slashslash/AWG-Router/issues/24">#24</a>, moving the server and uninstall <a href="https://github.com/r-slashslash/AWG-Router/issues/25">#25</a>, the subnet field <a href="https://github.com/r-slashslash/AWG-Router/issues/26">#26</a>, reinstalling over a host server <a href="https://github.com/r-slashslash/AWG-Router/issues/27">#27</a>, the day/night button <a href="https://github.com/r-slashslash/AWG-Router/issues/38">#38</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/xiaomiiraqly-alt"><img src="https://github.com/xiaomiiraqly-alt.png?size=128" width="72" alt=""><br><b>xiaomiiraqly-alt</b></a><br>🐛 🔍<br><sub>Let's Encrypt validation through a web server on port 80 <a href="https://github.com/r-slashslash/AWG-Router/issues/21">#21</a></sub></td>
</tr>
<tr>
<td align="center" valign="top" width="33%"><a href="https://github.com/MacSergey"><img src="https://github.com/MacSergey.png?size=128" width="72" alt=""><br><b>MacSergey</b></a><br>💡<br><sub>several server addresses in client configs <a href="https://github.com/r-slashslash/AWG-Router/issues/37">#37</a>, the server name in the browser tab <a href="https://github.com/r-slashslash/AWG-Router/issues/38">#38</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/Alex4003"><img src="https://github.com/Alex4003.png?size=128" width="72" alt=""><br><b>Alex4003</b></a><br>💡<br><sub>load balancing inside a rule <a href="https://github.com/r-slashslash/AWG-Router/issues/53">#53</a>, traffic by rule <a href="https://github.com/r-slashslash/AWG-Router/issues/54">#54</a></sub></td>
<td align="center" valign="top" width="33%"><a href="https://github.com/zabit-z"><img src="https://github.com/zabit-z.png?size=128" width="72" alt=""><br><b>zabit-z</b></a><br>💡<br><sub>the Let's Encrypt certificate through Cloudflare DNS <a href="https://github.com/r-slashslash/AWG-Router/pull/51">#51</a></sub></td>
</tr>
</table>

🐛 found and explained problems · 💡 ideas · 💻 code · 🔍 testing on real servers

### Projects

- [AmneziaWG](https://github.com/amnezia-vpn) — the protocol, `amneziawg-go` and `amneziawg-tools`
- [lego](https://github.com/go-acme/lego) — Let's Encrypt client
- [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) — SOCKS5 exits (MIT)
- [ipverse](https://github.com/ipverse) — country and ASN IP lists
- [QR Code Generator](https://github.com/kazuhikoarase/qrcode-generator) by Kazuhiko Arase (MIT)
- Fonts [Golos Text](https://github.com/googlefonts/golos-text), [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono), [Vazirmatn](https://github.com/rastikerdar/vazirmatn) (SIL Open Font License 1.1)

## License

[MIT](LICENSE)
