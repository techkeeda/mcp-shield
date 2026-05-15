"""Network Egress Monitor — watches MCP server processes for unauthorized outbound connections."""

import logging
from dataclasses import dataclass

import psutil

logger = logging.getLogger(__name__)

# Default allowed destinations (localhost, common package registries)
DEFAULT_ALLOWED = {
    "127.0.0.1",
    "::1",
    "registry.npmjs.org",
    "pypi.org",
}


@dataclass
class EgressViolation:
    server_name: str
    pid: int
    remote_ip: str
    remote_port: int
    process_name: str


class EgressMonitor:
    def __init__(self, allowed_hosts: set[str] | None = None):
        self.allowed_hosts = allowed_hosts or DEFAULT_ALLOWED
        self._tracked_pids: dict[int, str] = {}  # pid -> server_name

    def track_process(self, pid: int, server_name: str) -> None:
        """Register an upstream MCP server process for monitoring."""
        self._tracked_pids[pid] = server_name

    def scan(self) -> list[EgressViolation]:
        """Scan tracked processes for unauthorized outbound connections."""
        violations: list[EgressViolation] = []

        for pid, server_name in list(self._tracked_pids.items()):
            try:
                proc = psutil.Process(pid)
                # Also check child processes (npx spawns node)
                pids_to_check = [pid] + [c.pid for c in proc.children(recursive=True)]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            for check_pid in pids_to_check:
                try:
                    conns = psutil.Process(check_pid).net_connections(kind="inet")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                for conn in conns:
                    if not conn.raddr:
                        continue
                    remote_ip = conn.raddr.ip
                    if remote_ip not in self.allowed_hosts and not self._is_private(remote_ip):
                        v = EgressViolation(
                            server_name=server_name,
                            pid=check_pid,
                            remote_ip=remote_ip,
                            remote_port=conn.raddr.port,
                            process_name=psutil.Process(check_pid).name(),
                        )
                        violations.append(v)
                        logger.critical(
                            "EGRESS VIOLATION: server '%s' (pid %d) connecting to %s:%d",
                            server_name, check_pid, remote_ip, conn.raddr.port,
                        )

        return violations

    @staticmethod
    def _is_private(ip: str) -> bool:
        """Check if IP is in a private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return ip.startswith("fe80") or ip == "::1"
        first = int(parts[0])
        return (
            first == 10
            or (first == 172 and 16 <= int(parts[1]) <= 31)
            or (first == 192 and int(parts[1]) == 168)
        )
