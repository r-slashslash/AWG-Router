# Contributing

Thanks for helping. Bug reports, ideas and pull requests are all welcome, in English,
Русский, 中文 or فارسی.

## Before you start

- For a question or an early idea, start a thread in [Discussions](https://github.com/r-slashslash/AWG-Router/discussions).
- For a bug or a concrete proposal, open an issue first and use the template. For a larger change,
  describe it in an issue before writing code, so nobody's time is wasted.
- Vulnerabilities go through the private form, not a public issue: see [SECURITY.md](SECURITY.md).

## Rules for the code

New to the code? Start with the [architecture overview](docs/ARCHITECTURE.md). The rules — standard library
only, every text a user sees in four languages (ru, en, zh, fa), the four READMEs changed together, comments in
Russian, nothing loaded from third-party hosts — the checklists for typical changes and what "done" means are in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). If you only know some of the languages, write the text you can and
say so in the pull request; the maintainer will help with the rest.

## Tests

```bash
python3 -m unittest discover tests
```

These run without root and must pass, and so do `ruff check .` and `eslint app/static`. `tests/test_rules.py`
checks many of the rules (translations, saved fields, exit references, pinned actions, no third-party hosts), so
a failure there tells you what was missed. Network tests (`tests/*_e2e.py`) need root; see
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Pull requests

- Keep one change per pull request, and say what it fixes or adds and how you checked it.
- Changes in `.github/workflows/` and `tests/e2e/` get an extra careful review, because
  they run on CI machines.
- By contributing you agree that your work is released under the [MIT license](LICENSE).
