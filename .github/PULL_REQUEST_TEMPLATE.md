<!-- Write in English, Русский, 中文 or فارسی, whichever is easier. One change per pull request. -->

## What and why

<!-- What does this change fix or add? Link the issue: "Fixes #123" or "Part of #123". -->

## How I checked it

<!-- Commands you ran, what you saw in the panel (a screenshot helps for interface changes). -->

- [ ] `python3 -m unittest discover tests` passes
- [ ] Network tests (`tests/*_e2e.py`) run, if the change touches routing, shaping, tunnels or the installer

## Checklist

Tick what applies; delete what does not. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rules.

- [ ] Standard library only: no new Python dependencies
- [ ] Every new user-facing text is in all four languages (ru, en, zh, fa) in `app/static/i18n.js`, with the same `{placeholders}` (Telegram texts: `notify.TEXTS` / `tgbot.py`)
- [ ] README changes are made in all four files together (`README.md`, `README.ru.md`, `README.zh.md`, `README.fa.md`), or I said below which languages I could not write
- [ ] Comments and docstrings in `app/`, `tests/` and `tools/` are in Russian; `install.sh` stays in English
- [ ] The browser loads nothing from third-party hosts (fonts, scripts, images are served by the panel)
- [ ] A new field in `state.json` has a default, input validation, and is kept by backup restore (`clean_backup_state`)

## Does this touch `.github/workflows/` or `tests/e2e/`?

<!-- These run on CI machines and get an extra careful review. Say what changed and why. -->

- [ ] No
- [ ] Yes: described above
