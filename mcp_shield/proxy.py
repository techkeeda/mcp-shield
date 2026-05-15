"""MCP Proxy — intercepts all MCP traffic between agent and upstream servers."""

import asyncio
import json
import logging
import subprocess
import sys
from typing import Any

from .gates.discovery import DiscoveryGate
from .gates.invocation import InvocationGate
from .gates.response import ResponseGate
from .policy import Action
from .baseline import BaselineEngine
from .supply_chain import SupplyChainMonitor
from .audit import AuditLog

logger = logging.getLogger(__name__)


class UpstreamServer:
    """Manages a connection to an upstream MCP server via stdio."""

    def __init__(self, name: str, command: str, args: list[str], env: dict | None = None):
        self.name = name
        self.command = command
        self.args = args
        self.env = env
        self._process: subprocess.Popen | None = None
        self._request_id = 0

    async def start(self) -> None:
        self._process = subprocess.Popen(
            [self.command] + self.args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
        )
        logger.info("Started upstream server '%s'", self.name)

    async def send_request(self, method: str, params: dict | None = None) -> dict:
        """Send a JSON-RPC request to the upstream server."""
        self._request_id += 1
        request = {"jsonrpc": "2.0", "id": self._request_id, "method": method}
        if params:
            request["params"] = params

        data = json.dumps(request) + "\n"
        self._process.stdin.write(data.encode())
        self._process.stdin.flush()

        line = self._process.stdout.readline()
        return json.loads(line)

    def stop(self) -> None:
        if self._process:
            self._process.terminate()


class MCPProxy:
    """Main proxy that sits between the AI agent and upstream MCP servers."""

    def __init__(
        self,
        upstream_configs: dict,
        discovery_gate: DiscoveryGate,
        invocation_gate: InvocationGate,
        response_gate: ResponseGate,
        baseline: BaselineEngine,
        supply_chain: SupplyChainMonitor,
        audit: AuditLog,
    ):
        self.upstreams: dict[str, UpstreamServer] = {}
        self.discovery_gate = discovery_gate
        self.invocation_gate = invocation_gate
        self.response_gate = response_gate
        self.baseline = baseline
        self.supply_chain = supply_chain
        self.audit = audit
        self._tool_to_server: dict[str, str] = {}

        for name, cfg in upstream_configs.items():
            self.upstreams[name] = UpstreamServer(
                name=name,
                command=cfg["command"],
                args=cfg.get("args", []),
                env=cfg.get("env"),
            )

    async def start(self) -> None:
        for server in self.upstreams.values():
            await server.start()
        await self._discover_tools()

    async def _discover_tools(self) -> None:
        """Discover tools from all upstream servers, filtering through discovery gate."""
        for name, server in self.upstreams.items():
            resp = await server.send_request("tools/list")
            tools = resp.get("result", {}).get("tools", [])

            # Supply chain check
            changes = self.supply_chain.fingerprint_server(name, tools)
            if changes:
                self.audit.log_event("supply_chain_alert", server=name, changes=changes)

            # Discovery gate
            verdicts = self.discovery_gate.inspect_batch(tools)
            for tool, verdict in zip(tools, verdicts):
                if verdict.safe:
                    self._tool_to_server[tool["name"]] = name
                else:
                    self.audit.log_event(
                        "tool_blocked_discovery",
                        tool=verdict.tool_name,
                        server=name,
                        threats=verdict.threats,
                    )

            safe_count = sum(1 for v in verdicts if v.safe)
            logger.info("Server '%s': %d/%d tools passed discovery gate", name, safe_count, len(tools))

    async def handle_tool_call(self, tool_name: str, arguments: dict) -> dict[str, Any]:
        """Handle a tool call from the AI agent — the core enforcement path."""
        # Invocation gate
        action, reason = self.invocation_gate.validate(tool_name, arguments)
        self.audit.log_event("invocation_check", tool=tool_name, action=action.value, reason=reason, arguments=arguments)

        if action == Action.DENY:
            logger.warning("DENIED: %s — %s", tool_name, reason)
            return {"error": f"Blocked by MCP Shield: {reason}"}

        if action == Action.ASK:
            logger.info("ASK: %s — %s (auto-allowing in proxy mode)", tool_name, reason)

        # Baseline anomaly check
        anomalous, anomaly_reason = self.baseline.is_anomalous(tool_name, arguments)
        if anomalous:
            self.audit.log_event("anomaly_detected", tool=tool_name, reason=anomaly_reason)
            logger.warning("ANOMALY: %s — %s", tool_name, anomaly_reason)

        # Forward to upstream
        server_name = self._tool_to_server.get(tool_name)
        if not server_name:
            return {"error": f"Unknown tool: {tool_name}"}

        server = self.upstreams[server_name]
        resp = await server.send_request("tools/call", {"name": tool_name, "arguments": arguments})
        result = resp.get("result", {})
        response_text = json.dumps(result)

        # Response gate
        safe, issues = self.response_gate.scan(tool_name, response_text)
        if not safe:
            self.audit.log_event("response_blocked", tool=tool_name, issues=issues)
            return {"error": f"Response blocked by MCP Shield: {'; '.join(issues)}"}

        # Record for baseline learning
        self.baseline.record(tool_name, arguments)
        self.audit.log_event("tool_call_success", tool=tool_name, response=response_text[:500])

        return result

    async def handle_stdio(self) -> None:
        """Main loop — reads JSON-RPC from stdin, processes, writes to stdout."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                request = json.loads(line)
                response = await self._handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                continue

    async def _handle_request(self, request: dict) -> dict:
        """Route a JSON-RPC request."""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})

        if method == "tools/list":
            # Return only safe tools
            tools = [
                {"name": name} for name in self._tool_to_server
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

        elif method == "tools/call":
            result = await self.handle_tool_call(params.get("name", ""), params.get("arguments", {}))
            if "error" in result:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -1, "message": result["error"]}}
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}

    def stop(self) -> None:
        for server in self.upstreams.values():
            server.stop()
