"""Supply chain monitor — detects when a previously-safe server changes behavior."""

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

FINGERPRINT_PATH = Path("/var/mcp-shield/fingerprints.json")


@dataclass
class ServerFingerprint:
    server_name: str
    tool_names: list[str]
    description_hash: str
    schema_hash: str


class SupplyChainMonitor:
    def __init__(self):
        self.fingerprints: dict[str, ServerFingerprint] = {}
        self._load()

    def fingerprint_server(self, server_name: str, tools: list[dict]) -> list[str]:
        """Fingerprint a server's tools. Returns list of changes detected."""
        tool_names = sorted(t.get("name", "") for t in tools)
        desc_blob = "".join(t.get("description", "") for t in tools)
        schema_blob = json.dumps([t.get("inputSchema", {}) for t in tools], sort_keys=True)

        new_fp = ServerFingerprint(
            server_name=server_name,
            tool_names=tool_names,
            description_hash=hashlib.sha256(desc_blob.encode()).hexdigest()[:16],
            schema_hash=hashlib.sha256(schema_blob.encode()).hexdigest()[:16],
        )

        changes: list[str] = []
        old_fp = self.fingerprints.get(server_name)

        if old_fp:
            # Detect changes
            added = set(new_fp.tool_names) - set(old_fp.tool_names)
            removed = set(old_fp.tool_names) - set(new_fp.tool_names)
            if added:
                changes.append(f"new tools added: {added}")
            if removed:
                changes.append(f"tools removed: {removed}")
            if new_fp.description_hash != old_fp.description_hash:
                changes.append("tool descriptions changed")
            if new_fp.schema_hash != old_fp.schema_hash:
                changes.append("tool schemas changed")

            if changes:
                logger.warning("SUPPLY CHAIN ALERT for '%s': %s", server_name, changes)

        self.fingerprints[server_name] = new_fp
        self._save()
        return changes

    def _load(self) -> None:
        if FINGERPRINT_PATH.exists():
            data = json.loads(FINGERPRINT_PATH.read_text())
            for name, fp in data.items():
                self.fingerprints[name] = ServerFingerprint(**fp)

    def _save(self) -> None:
        FINGERPRINT_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            name: {
                "server_name": fp.server_name,
                "tool_names": fp.tool_names,
                "description_hash": fp.description_hash,
                "schema_hash": fp.schema_hash,
            }
            for name, fp in self.fingerprints.items()
        }
        FINGERPRINT_PATH.write_text(json.dumps(data, indent=2))
