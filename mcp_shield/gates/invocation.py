"""Invocation Gate — validates tool calls against policy, blocks dangerous arguments."""

import logging
import re
from time import time
from collections import defaultdict

from ..policy import PolicyEngine, Action

logger = logging.getLogger(__name__)

# Shell injection patterns
SHELL_INJECTION = re.compile(r"[;&|`$]|\b(rm|chmod|chown|curl|wget|nc|bash|sh|python|eval)\b", re.IGNORECASE)
# Path traversal
PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\")
# Credential patterns
CREDENTIAL_PATTERNS = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}|"
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----)",
    re.IGNORECASE,
)


class InvocationGate:
    def __init__(self, config: dict, policy_engine: PolicyEngine):
        self.config = config
        self.policy = policy_engine
        self.block_shell = config.get("block_shell_injection", True)
        self.block_traversal = config.get("block_path_traversal", True)
        self.block_creds = config.get("block_credential_patterns", True)
        # Rate limiting
        rate_cfg = config.get("rate_limit", {})
        self.max_per_min = rate_cfg.get("max_calls_per_minute", 30)
        self.max_per_tool_min = rate_cfg.get("max_calls_per_tool_per_minute", 10)
        self._call_times: list[float] = []
        self._tool_call_times: dict[str, list[float]] = defaultdict(list)

    def validate(self, tool_name: str, arguments: dict) -> tuple[Action, str]:
        """Validate a tool invocation. Returns (action, reason)."""
        # Rate limit check
        now = time()
        self._call_times = [t for t in self._call_times if now - t < 60]
        if len(self._call_times) >= self.max_per_min:
            return Action.DENY, "global rate limit exceeded"
        self._tool_call_times[tool_name] = [t for t in self._tool_call_times[tool_name] if now - t < 60]
        if len(self._tool_call_times[tool_name]) >= self.max_per_tool_min:
            return Action.DENY, f"rate limit exceeded for tool '{tool_name}'"

        # Argument scanning
        args_str = str(arguments)

        if self.block_shell and SHELL_INJECTION.search(args_str):
            return Action.DENY, "shell injection detected in arguments"

        if self.block_traversal and PATH_TRAVERSAL.search(args_str):
            return Action.DENY, "path traversal detected in arguments"

        if self.block_creds and CREDENTIAL_PATTERNS.search(args_str):
            return Action.DENY, "credential/secret detected in arguments"

        # Policy check
        action, reason = self.policy.evaluate(tool_name, arguments)

        # Record call time if allowed
        if action != Action.DENY:
            self._call_times.append(now)
            self._tool_call_times[tool_name].append(now)

        return action, reason
