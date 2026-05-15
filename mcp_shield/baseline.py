"""Behavioral baseline — learns normal tool usage and flags anomalies."""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from time import time

logger = logging.getLogger(__name__)


@dataclass
class ToolProfile:
    call_count: int = 0
    avg_args_length: float = 0.0
    typical_arg_keys: set[str] = field(default_factory=set)
    last_seen: float = 0.0


class BaselineEngine:
    def __init__(self, path: Path | None = None):
        self.profiles: dict[str, ToolProfile] = defaultdict(ToolProfile)
        self._learning = True
        self._min_samples = 20  # Learn for at least 20 calls before flagging
        if path and path.exists():
            self._load(path)

    def record(self, tool_name: str, arguments: dict) -> None:
        """Record a tool call for baseline learning."""
        p = self.profiles[tool_name]
        p.call_count += 1
        args_len = len(str(arguments))
        p.avg_args_length = (p.avg_args_length * (p.call_count - 1) + args_len) / p.call_count
        p.typical_arg_keys.update(arguments.keys())
        p.last_seen = time()

    def is_anomalous(self, tool_name: str, arguments: dict) -> tuple[bool, str]:
        """Check if a call deviates from learned baseline."""
        p = self.profiles.get(tool_name)
        if not p or p.call_count < self._min_samples:
            return False, ""  # Not enough data yet

        issues = []
        # Unusual argument length (3x average)
        args_len = len(str(arguments))
        if args_len > p.avg_args_length * 3:
            issues.append(f"args length {args_len} vs avg {p.avg_args_length:.0f}")

        # Unknown argument keys
        unknown_keys = set(arguments.keys()) - p.typical_arg_keys
        if unknown_keys:
            issues.append(f"unexpected args: {unknown_keys}")

        if issues:
            return True, "; ".join(issues)
        return False, ""

    def _load(self, path: Path) -> None:
        data = json.loads(path.read_text())
        for name, profile in data.items():
            self.profiles[name] = ToolProfile(
                call_count=profile["call_count"],
                avg_args_length=profile["avg_args_length"],
                typical_arg_keys=set(profile["typical_arg_keys"]),
                last_seen=profile["last_seen"],
            )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            name: {
                "call_count": p.call_count,
                "avg_args_length": p.avg_args_length,
                "typical_arg_keys": list(p.typical_arg_keys),
                "last_seen": p.last_seen,
            }
            for name, p in self.profiles.items()
        }
        path.write_text(json.dumps(data, indent=2))
