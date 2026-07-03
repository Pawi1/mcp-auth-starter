# MCP Auth Starter

A minimal, working example of the part of building an MCP server that's
annoying to get right: **OAuth 2.0 with Dynamic Client Registration (RFC
7591) + JWT bearer tokens, served over Streamable HTTP** — so Claude.ai (or
any other OAuth-aware MCP client) can add your server as a connector with a
normal browser login. No manual token pasting, no bypassing OAuth with a
"just give me a token" shortcut that quietly stops working the moment you
add real revocation.

This is *not* a framework — it's ~600 lines of plain Starlette you're meant
to read, fork, and build on. There's exactly one demo tool (`whoami`) to
prove the auth chain works end to end. Your actual tools go in `app/server.py`.

## What's in here

| File | What it does |
|---|---|
| `app/main.py` | Starlette app, `/mcp` endpoint + auth gate, lifespan, CLI (`--setup`, `--adduser`) |
| `app/oauth.py` | Full OAuth 2.0 flow: discovery, Dynamic Client Registration, authorize/login/token, revocation, rate limiting |
| `app/auth.py` | JWT verification |
| `app/users.py` | User accounts (argon2 password hashing), login attempt logging |
| `app/context.py` | `ContextVar` carrying the authenticated user into your tool handlers |
| `app/server.py` | MCP tool definitions — **this is where you add your own tools** |
| `app/config.py` | Config loader (`config.json` + env var overrides for secrets) |

## Why the auth gate is two checks, not one

`main.py`'s `/mcp` handler checks that the bearer token (1) has a valid JWT
signature, **and** (2) still exists in the `oauth_tokens` table. Both matter:
a token can have a perfectly valid signature and still not be a real,
currently-issued session — e.g. after you call `revoke_tokens_for_user()`,
the JWT itself doesn't change, but it's deleted from the DB, so it correctly
stops working. Skip the second check and revocation silently does nothing.

## Quick start

```bash
make dev          # creates app/.venv, installs deps, runs directly (no build)
```

On first run you'll get a "Config not found" error — run the setup wizard
first (creates `config.json`, a `SECRET_KEY`, and an admin user):

```bash
cd app && python3 main.py --setup
```

Then add this server as a connector in Claude.ai (Settings → Connectors →
Add custom connector) with the URL `http://localhost:8000/mcp`. Claude.ai
will discover the OAuth endpoints automatically, register itself as a
client, and prompt you to log in with the admin account you just created.

## Adding your own tools

Edit `app/server.py`: add one `Tool(...)` entry to `list_tools()` and a
matching `if name == "...":` branch in `call_tool()`. `current_user.get()`
is always populated by the time `call_tool()` runs — the auth gate rejects
the request before it reaches here otherwise.

```python
if name == "my_tool":
    return _ok({"result": do_something(arguments)})
```

## Testing

```bash
make test
```

87 tests, ~70% line coverage. `app/config.py` and the interactive CLI
wizard (`--setup`/`--adduser`) are the main gaps — they're either constants
or `input()`-driven, both low value to unit test.

## Deployment

```bash
make build-binary   # PyInstaller single-file binary
sudo make install   # installs + registers a systemd service
sudo make start
```

See `services/` for the systemd unit and env file template.

## What this deliberately leaves out

- **Multi-tenancy.** The JWT carries a `teams` claim and users have a
  `teams` column, but there's no tenant table or access-control gate built
  on top of it — most single-purpose MCP servers don't need one, and a
  half-built example is worse than none. If you need it, gate your tools on
  `current_user.get()["teams"]` yourself.
- **A skills/plugin system**, business logic, or any domain-specific
  tools — that's the whole point of `server.py` being ~60 lines.

## License

Not yet decided — add one before you publish this anywhere.
