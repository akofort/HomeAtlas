"""HomeAtlas as an MCP server -- the household's own tool set, reachable by an external LLM client.

This exposes exactly `tools.TOOL_DEFINITIONS`/`tools.dispatch`: the same tools the in-app chat
assistant already has (see `tools.py`'s own module docstring) -- read-only facts/diagnostics, plus
the one deliberate write exception, `set_switch` (turn a Shelly relay or a Home Assistant switch/
light entity on or off). Nothing here widens that surface; it only adds a second way to reach it,
for clients like Claude Desktop that speak the Model Context Protocol instead of HomeAtlas's own
chat API -- which also means any holder of an admin-issued Bearer token can flip a switch this
way, same as any household member already can from in-app chat. `apiTokens` carries no role/scope
column, so there is no narrower gate available here; that is the explicit trade-off the "every
role, every client" scope decision made (see `main.py`'s module docstring, `tools.py`'s).

Auth is a flat Bearer token (`apiTokens` in db.py), checked by `_BearerAuth` before a request ever
reaches the MCP session manager. Deliberately not the MCP SDK's own `TokenVerifier`/`AuthSettings`
machinery -- that models a full OAuth resource server (mandatory `issuer_url`,
`resource_server_url`, discovery endpoints) for dynamic client registration, which is more than a
single self-issued, pre-shared token needs. Tokens are created only by an admin, in Settings.

Transport is Streamable HTTP, stateless: every tool call here is already a fast, independent, read
-only round trip (see `tools.py`), so there is nothing worth keeping session state for between
calls.
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from . import db, tools

server = Server("homeatlas")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return [
        types.Tool(name=d["name"], description=d["description"], inputSchema=d["inputSchema"])
        for d in tools.TOOL_DEFINITIONS
    ]


@server.call_tool()
async def _call_tool(name: str, arguments: dict) -> list[types.ContentBlock]:
    # tools.dispatch never raises -- failures already come back as a {"error": ...} JSON string,
    # so this is a straight pass-through with no extra error handling needed here.
    result = await tools.dispatch(name, arguments)
    return [types.TextContent(type="text", text=result)]


session_manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)


class _BearerAuth:
    """Checks `Authorization: Bearer <token>` against `apiTokens` before letting a request reach
    the MCP transport. A plain ASGI middleware rather than the SDK's auth hooks -- see module
    docstring for why."""

    def __init__(self, app):
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        token = auth_header[7:] if auth_header.lower().startswith("bearer ") else ""
        if not token or db.touch_api_token(token) is None:
            response = JSONResponse(
                {"error": "Kein gültiges MCP-Token. Siehe Einstellungen -> MCP-Server."},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="homeatlas-mcp"'},
            )
            await response(scope, receive, send)
            return
        await self._app(scope, receive, send)


async def _mcp_asgi(scope: Scope, receive: Receive, send: Send) -> None:
    await session_manager.handle_request(scope, receive, send)


asgi_app = Starlette(routes=[Mount("/", app=_BearerAuth(_mcp_asgi))])
