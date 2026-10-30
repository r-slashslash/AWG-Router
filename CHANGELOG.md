# Changelog

Panels compare `app/version.py` with GitHub and show "update available" when it grows,
so every user-visible change gets a new version.

## 1.3.0 — 2026-10-30

- **Traffic per exit.** The panel now counts how much client traffic goes through each exit
  and how much goes direct, for the month and all time, and splits each client's monthly
  traffic by exit (client → Manage). Counting runs in a separate nftables table
  (`awgr_acct`) that only counts: it sets no marks or routes, it is not rebuilt when rules
  change (so counters don't reset) and, if the kernel can't load it, the panel turns
  counting off with one log entry and routing works as before. Blocked traffic is not counted.
- **Monthly limit for an exit.** When it is used up, the exit's clients go to its fallback
  exit until the 1st (UTC), or the panel only notifies you. Log entries and Telegram
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
- Exit limit hint: says that traffic inside the tunnel is counted; the footnote under the
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
