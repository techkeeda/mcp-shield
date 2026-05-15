"""Policy engine — declarative YAML rules for allow/deny/ask per tool."""

import logging
from dataclasses import dataclass
from enum import Enum
from fnmatch import fnmatch

logger = logging.getLogger(__name__)


class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass
class ToolPolicy:
    action: Action
    constraints: dict
    log: bool = True


class PolicyEngine:
    def __init__(self, config: dict):
        self.default_action = Action(config.get("default", {}).get("action", "ask"))
        self.default_log = config.get("default", {}).get("log", True)
        self.tool_policies: dict[str, ToolPolicy] = {}

        for name, rule in config.get("tools", {}).items():
            self.tool_policies[name] = ToolPolicy(
                action=Action(rule["action"]),
                constraints=rule.get("constraints", {}),
                log=rule.get("log", True),
            )

    def evaluate(self, tool_name: str, arguments: dict) -> tuple[Action, str]:
        """Evaluate policy for a tool call. Returns (action, reason)."""
        policy = self.tool_policies.get(tool_name)
        if not policy:
            return self.default_action, "no explicit policy"

        if policy.action == Action.DENY:
            return Action.DENY, f"tool '{tool_name}' is denied by policy"

        # Check constraints
        reason = self._check_constraints(tool_name, arguments, policy.constraints)
        if reason:
            return Action.DENY, reason

        return policy.action, "policy allows"

    def _check_constraints(self, tool_name: str, arguments: dict, constraints: dict) -> str | None:
        """Check argument constraints. Returns denial reason or None."""
        # Path blocking
        blocked_paths = constraints.get("blocked_paths", [])
        for key in ("path", "file_path", "filename", "directory"):
            if key in arguments:
                for pattern in blocked_paths:
                    if fnmatch(arguments[key], pattern):
                        return f"path '{arguments[key]}' matches blocked pattern '{pattern}'"

        # BCC blocking (supply chain attack prevention)
        if constraints.get("block_bcc") and "bcc" in arguments:
            return "BCC field blocked (supply chain attack prevention)"

        return None
