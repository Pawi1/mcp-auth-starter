# Migrating from mcp 1.x to mcp 2.0

`main` now targets **mcp 2.0**, which shipped a breaking rewrite of the
low-level `Server` API: the `@server.list_tools()` / `@server.call_tool()`
decorators are gone. If you forked this repo (or copied `app/server.py`
into your own project) before this change, here's what to update.

If you're not ready to migrate yet, the [`legacy`](https://github.com/Pawi1/mcp-auth-starter/tree/legacy)
branch stays pinned to mcp 1.x indefinitely (v1.x still gets security/bug-fix
patches upstream), so you can keep building on it.

## What changed

mcp 1.x registered handlers by decorating functions after constructing the
server:

```python
mcp_server = Server(MCP_SERVER_NAME, instructions=SERVER_INSTRUCTIONS)

@mcp_server.list_tools()
async def list_tools() -> list[Tool]:
    return [Tool(name="whoami", ...)]

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    ...
```

mcp 2.0 passes the handlers into the `Server` constructor instead, and their
signature changed from `(name, arguments)` / `() ` to a uniform
`(ctx: ServerRequestContext, params) -> typed Result`:

```python
async def _on_list_tools(ctx, params: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=[Tool(name="whoami", ...)])

async def _on_call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
    ...

mcp_server = Server(
    MCP_SERVER_NAME,
    instructions=SERVER_INSTRUCTIONS,
    on_list_tools=_on_list_tools,
    on_call_tool=_on_call_tool,
)
```

Concretely:

- `list_tools()` must now return `types.ListToolsResult`, not a bare `list[Tool]`.
- `call_tool()` must now return `types.CallToolResult`, not a bare `list[TextContent]` — wrap your content list in `CallToolResult(content=...)`.
- Both handlers take `(ctx, params)`; `call_tool`'s tool name and arguments arrive as `params.name` / `params.arguments` (a `CallToolRequestParams`), not as two positional arguments.
- `mcp.types` (`Tool`, `TextContent`, etc.) still re-exports everything from the new `mcp_types` package, so those imports are unchanged.
- `mcp.server.streamable_http_manager.StreamableHTTPSessionManager` and its `app=`/`stateless=` constructor arguments are unchanged — `main.py` needs no changes for this migration.

## What this repo's migration actually did

See `app/server.py` on `main`: `list_tools()`/`call_tool()` kept their old,
simple `(name, arguments)` shape — easy to unit-test, and reused by
`tests/test_server.py` unchanged — with two thin adapters,
`_on_list_tools`/`_on_call_tool`, translating between that shape and what
the mcp 2.0 `Server` constructor requires. If you have more than one or two
tools, you likely want the same split: keep your tool logic in
plain, testable functions, and adapt them into the new handler shape at the
edge rather than rewriting every tool to take `(ctx, params)`.

Steps to migrate your own fork:

1. Bump `mcp` in `app/requirements.txt` to `>=2.0.0,<3.0.0`.
2. Drop the `@mcp_server.list_tools()` / `@mcp_server.call_tool()` decorators.
3. Wrap your `list_tools()` return value in `ListToolsResult(tools=...)`, and
   your `call_tool()` return value in `CallToolResult(content=...)`.
4. Add `_on_list_tools`/`_on_call_tool` adapters (or rewrite your handlers
   directly to the `(ctx, params)` signature, if you don't need them
   independently testable).
5. Construct `Server(...)` with `on_list_tools=`/`on_call_tool=` instead of
   decorating after construction.
6. Run your test suite — if it calls `list_tools()`/`call_tool()` directly
   (as this repo's does) rather than through `Server`'s dispatch, it should
   need no changes beyond what's already covered above.

## A gotcha worth knowing about, not fixing

mcp 2.0's dispatcher runs each inbound request's handler using the async
context captured from whichever task *sent* that message onto the session's
stream — not the context of the long-lived per-session task that's actually
consuming it. In practice this means a `ContextVar` you set per-HTTP-request
(like this repo's `context.current_user`, set in `main.py`'s `/mcp` handler)
still reaches your tool handler correctly on every request, even though the
handler technically executes inside a persistent per-session task that
outlives any single request. Nothing to change here — just don't be
surprised if you go looking for where that's wired up.
