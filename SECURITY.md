# Security Policy

This repo is an authentication/authorization implementation (OAuth 2.0 +
JWT) — a bug here is a security bug by definition, not just a functional
one. Please report responsibly.

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Preferred: use GitHub's [private vulnerability reporting](../../security/advisories/new)
(Security tab → "Report a vulnerability"). This opens a private advisory
visible only to you and the maintainer until a fix is ready.

If that's not available, open an issue titled `SECURITY: <short summary>`
with no technical detail in the body and ask for a private channel to
follow up on.

Please include:
- What you found and why it's exploitable (a PoC helps, but isn't required)
- Affected file(s)/endpoint(s)
- Impact if you can estimate it (auth bypass, token forgery, revocation
  not actually revoking, etc.)

## Scope

In scope: `app/auth.py`, `app/oauth.py`, `app/main.py`'s `/mcp` auth gate,
`app/users.py`'s password handling. Anything that could let a request
reach `call_tool()` without a valid, currently-active session, or that
weakens password/token storage.

Out of scope: the demo `whoami` tool itself, deployment scripts, and
anything in `services/` (those are examples, not hardened configs — treat
generated secrets, default users, etc. as yours to secure per-deployment).

## Known tradeoffs (not vulnerabilities, but worth knowing)

- `oauth_tokens`/`oauth_clients` are cached in-memory (`dict`) in addition
  to SQLite, for read speed. Every mutation writes through to the DB first,
  so a crash can't lose state, but if you run multiple processes behind a
  load balancer, the in-memory cache **is not shared** — put SQLite on
  shared storage or move to a real DB before scaling horizontally.
- Rate limiting (`_check_rate_limit`) is in-memory and per-process, same
  caveat.
- Authorization codes live for 60 seconds and are single-use, in-memory
  only — they don't survive a server restart between `/oauth/authorize`
  and `/oauth/token`.

## Supported versions

Pre-1.0, single-branch — only `main` is supported. There's no version
matrix yet.
