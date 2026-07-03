# Contributing

## Setup

```bash
make dev     # creates app/.venv, installs deps
make test    # runs the test suite
```

## Before opening a PR

- `make test` passes (123 tests today — add tests for whatever you change,
  especially anything in `app/auth.py`/`app/oauth.py`/`app/main.py`'s
  `/mcp` handler; see [SECURITY.md](SECURITY.md) for why those files get
  extra scrutiny).
- Keep `app/server.py` free of anything beyond the one demo tool — this
  repo is a starting point, not a place to accumulate example tools. If
  you want to contribute a second example, open an issue first to discuss
  where it should live.
- No new runtime dependencies without a good reason — the point of this
  repo is staying small enough to read in one sitting.

## Reporting bugs

Functional bug → open an issue.
Security issue → see [SECURITY.md](SECURITY.md), not a public issue.

## Code style

Match what's already there: no type-annotation ceremony, docstrings only
where the *why* isn't obvious from the code, flat `from x import y` module
layout (no package nesting) — matches the original repo this was extracted
from, and keeps the diff between "read main.py" and "understand main.py"
as small as possible.
