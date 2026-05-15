"""Audit logger — full trace of every tool discovery, call, and response."""

import json
import logging
from pathlib import Path
from time import time

logger = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.log_args = config.get("log_arguments", True)
        self.log_responses = config.get("log_responses", True)
        self._path = Path(config.get("file", "/var/log/mcp-shield/audit.jsonl"))
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event_type: str, **kwargs) -> None:
        if not self.enabled:
            return
        entry = {"timestamp": time(), "event": event_type, **kwargs}
        if not self.log_args:
            entry.pop("arguments", None)
        if not self.log_responses:
            entry.pop("response", None)
        with self._path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
