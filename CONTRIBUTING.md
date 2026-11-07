# Contributing

Thanks for helping. Bug reports, ideas and pull requests are all welcome, in English,
Русский, 中文 or فارسی.

## Before you start

- For a question or an early idea, start a thread in [Discussions](https://github.com/r-slashslash/AWG-Router/discussions).
- For a bug or a concrete proposal, open an issue first and use the template. For a larger change,
  describe it in an issue before writing code, so nobody's time is wasted.
- Vulnerabilities go through the private form, not a public issue: see [SECURITY.md](SECURITY.md).

## Rules for the code

New to the code? Start with the [architecture overview](docs/ARCHITECTURE.md).

- **Standard library only.** The panel has no Python dependencies; the HTTP layer is `app/web.py`.
- **Every text a user sees exists in four languages: ru, en, zh, fa** (fa is right to left).
  Add the key to all four dictionaries in `app/static/i18n.js` with the same `{placeholders}`.
  Telegram texts live in `notify.TEXTS` and `tgbot.py`.
- **README changes go to all four files together:** `README.md`, `README.ru.md`, `README.zh.md`,
  `README.fa.md`. If you only know some of the languages, write the text you can and say so
  in the pull request; the maintainer will help with the rest.
- Comments and docstrings in `app/`, `tests/` and `tools/` are written in Russian.
  `install.sh` talks only in English.
- The browser never loads anything from a third-party host: fonts and scripts are served by the panel.

## Tests

```bash
python3 -m unittest discover tests
```

These run without root and must pass. `tests/test_rules.py` checks many of the rules above
(translations, saved fields, exit references), so a failure there tells you what was missed.
Network tests (`tests/*_e2e.py`) need root and are listed in the README, "Development".

## Pull requests

- Keep one change per pull request, and say what it fixes or adds and how you checked it.
- Changes in `.github/workflows/` and `tests/e2e/` get an extra careful review, because
  they run on CI machines.
- By contributing you agree that your work is released under the [MIT license](LICENSE).
