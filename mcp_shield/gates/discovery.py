"""Discovery Gate — inspects tool listings for poisoning and hidden instructions."""

import logging
import re

from ..threat_db import ThreatDB

logger = logging.getLogger(__name__)

# Patterns that indicate prompt injection in tool descriptions
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE),
    re.compile(r"<\s*IMPORTANT\s*>", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"secretly", re.IGNORECASE),
    re.compile(r"override\s+(your|all|the)", re.IGNORECASE),
    re.compile(r"hidden\s+instruction", re.IGNORECASE),
    re.compile(r"\\u[0-9a-fA-F]{4}", re.IGNORECASE),  # Unicode escapes hiding text
]


@dataclass
class DiscoveryVerdict:
    tool_name: str
    safe: bool
    threats: list[str]


from dataclasses import dataclass


@dataclass
class DiscoveryVerdict:
    tool_name: str
    safe: bool
    threats: list[str]


class DiscoveryGate:
    def __init__(self, config: dict, threat_db: ThreatDB):
        self.config = config
        self.threat_db = threat_db
        self.max_desc_length = config.get("max_description_length", 2000)
        # Add user-configured patterns
        extra = config.get("suspicious_patterns", [])
        self.extra_patterns = [re.compile(re.escape(p), re.IGNORECASE) for p in extra]

    def inspect_tool(self, tool: dict) -> DiscoveryVerdict:
        """Inspect a single tool definition for threats."""
        name = tool.get("name", "unknown")
        description = tool.get("description", "")
        schema = str(tool.get("inputSchema", {}))
        threats: list[str] = []

        # Check description length (overly long = hiding content)
        if len(description) > self.max_desc_length:
            threats.append(f"description exceeds {self.max_desc_length} chars ({len(description)})")

        # Check for injection patterns
        combined = f"{description} {schema}"
        for pattern in INJECTION_PATTERNS + self.extra_patterns:
            if pattern.search(combined):
                threats.append(f"injection pattern detected: '{pattern.pattern}'")

        # Check against known-bad descriptions in threat DB
        match = self.threat_db.match_description(description)
        if match:
            threats.append(f"matches known threat: {match.id} ({match.threat_type})")

        # Check for invisible/zero-width characters (hiding instructions)
        invisible = re.findall(r"[\u200b\u200c\u200d\u2060\ufeff]", combined)
        if invisible:
            threats.append(f"contains {len(invisible)} invisible characters")

        return DiscoveryVerdict(tool_name=name, safe=len(threats) == 0, threats=threats)

    def inspect_batch(self, tools: list[dict]) -> list[DiscoveryVerdict]:
        """Inspect all tools from a server listing."""
        results = []
        for tool in tools:
            verdict = self.inspect_tool(tool)
            if not verdict.safe:
                logger.warning("BLOCKED tool '%s': %s", verdict.tool_name, verdict.threats)
            results.append(verdict)
        return results
