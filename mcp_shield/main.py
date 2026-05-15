"""Entry point for MCP Shield."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

import yaml

from .threat_db import ThreatDB
from .policy import PolicyEngine
from .gates.discovery import DiscoveryGate
from .gates.invocation import InvocationGate
from .gates.response import ResponseGate
from .baseline import BaselineEngine
from .supply_chain import SupplyChainMonitor
from .updater import Updater
from .audit import AuditLog
from .proxy import MCPProxy

logger = logging.getLogger("mcp_shield")
THREAT_DB_PATH = Path("/var/mcp-shield/threat_db.json")
BASELINE_PATH = Path("/var/mcp-shield/baseline.json")


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def run(config: dict) -> None:
    # Initialize threat DB
    threat_db = ThreatDB()
    threat_db.load(THREAT_DB_PATH)

    # Pull latest threats from mothership
    updater = Updater(config.get("mothership", {}), threat_db)
    await updater.update()

    # Initialize components
    policy = PolicyEngine(config.get("policies", {}))
    discovery_gate = DiscoveryGate(config.get("discovery", {}), threat_db)
    invocation_gate = InvocationGate(config.get("invocation", {}), policy)
    response_gate = ResponseGate(config.get("response", {}))
    baseline = BaselineEngine(BASELINE_PATH)
    supply_chain = SupplyChainMonitor()
    audit = AuditLog(config.get("audit", {}))

    # Start proxy
    proxy = MCPProxy(
        upstream_configs=config.get("upstream_servers", {}),
        discovery_gate=discovery_gate,
        invocation_gate=invocation_gate,
        response_gate=response_gate,
        baseline=baseline,
        supply_chain=supply_chain,
        audit=audit,
    )

    await proxy.start()
    logger.info("MCP Shield active — proxying %d upstream servers", len(proxy.upstreams))

    # Schedule periodic updates
    async def periodic_update():
        while True:
            await asyncio.sleep(updater.interval)
            await updater.update()
            threat_db.save(THREAT_DB_PATH)

    update_task = asyncio.create_task(periodic_update())

    try:
        await proxy.handle_stdio()
    finally:
        update_task.cancel()
        proxy.stop()
        baseline.save(BASELINE_PATH)


def main() -> None:
    config_path = "config.yaml"
    if "--config" in sys.argv:
        config_path = sys.argv[sys.argv.index("--config") + 1]

    config = load_config(config_path)
    logging.basicConfig(
        level=getattr(logging, config.get("logging", {}).get("level", "INFO")),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,  # Logs to stderr, stdout is for MCP protocol
    )

    loop = asyncio.new_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, loop.stop)
    try:
        loop.run_until_complete(run(config))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
