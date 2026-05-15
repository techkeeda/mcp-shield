"""Response Gate — scans tool responses for data leakage and injected prompts."""

import logging
import re

logger = logging.getLogger(__name__)

# Prompt injection in responses (tool trying to manipulate the AI)
RESPONSE_INJECTION = [
    re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"you\s+must\s+now", re.IGNORECASE),
    re.compile(r"<\s*IMPORTANT\s*>", re.IGNORECASE),
    re.compile(r"ASSISTANT:\s", re.IGNORECASE),
    re.compile(r"SYSTEM:\s", re.IGNORECASE),
]


class ResponseGate:
    def __init__(self, config: dict):
        self.config = config
        self.scan_injection = config.get("scan_for_injection", True)
        self.scan_leakage = config.get("scan_for_data_leakage", True)
        self.sensitive_patterns = [
            re.compile(p) for p in config.get("sensitive_patterns", [])
        ]

    def scan(self, tool_name: str, response: str) -> tuple[bool, list[str]]:
        """Scan a tool response. Returns (safe, list of issues)."""
        issues: list[str] = []

        if self.scan_injection:
            for pattern in RESPONSE_INJECTION:
                if pattern.search(response):
                    issues.append(f"prompt injection in response: '{pattern.pattern}'")

        if self.scan_leakage:
            for pattern in self.sensitive_patterns:
                matches = pattern.findall(response)
                if matches:
                    issues.append(f"sensitive data leak ({len(matches)} matches): {pattern.pattern}")

        if issues:
            logger.warning("Response from '%s' flagged: %s", tool_name, issues)

        return len(issues) == 0, issues
