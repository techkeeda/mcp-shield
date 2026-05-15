"""Threat database — known-bad servers, hashes, and attack patterns."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ThreatEntry:
    id: str
    server_name: str
    threat_type: str  # poisoning, exfiltration, supply_chain, rce
    severity: str  # low, medium, high, critical
    pattern: str  # detection pattern
    description: str


@dataclass
class ThreatDB:
    entries: list[ThreatEntry] = field(default_factory=list)
    blocked_server_hashes: set[str] = field(default_factory=set)
    known_bad_descriptions: list[str] = field(default_factory=list)
    version: str = "0.0.0"

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text())
        self.version = data.get("version", self.version)
        self.blocked_server_hashes = set(data.get("blocked_server_hashes", []))
        self.known_bad_descriptions = data.get("known_bad_descriptions", [])
        self.entries = [ThreatEntry(**e) for e in data.get("entries", [])]
        logger.info("Loaded threat DB v%s (%d entries)", self.version, len(self.entries))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": self.version,
            "blocked_server_hashes": list(self.blocked_server_hashes),
            "known_bad_descriptions": self.known_bad_descriptions,
            "entries": [
                {"id": e.id, "server_name": e.server_name, "threat_type": e.threat_type,
                 "severity": e.severity, "pattern": e.pattern, "description": e.description}
                for e in self.entries
            ],
        }
        path.write_text(json.dumps(data, indent=2))

    def is_server_blocked(self, server_hash: str) -> bool:
        return server_hash in self.blocked_server_hashes

    def match_description(self, description: str) -> ThreatEntry | None:
        """Check if a tool description matches known-bad patterns."""
        desc_lower = description.lower()
        for entry in self.entries:
            if entry.pattern.lower() in desc_lower:
                return entry
        return None
