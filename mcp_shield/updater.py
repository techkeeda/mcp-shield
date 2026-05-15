"""Mothership updater — auto-pulls latest threat intelligence."""

import hashlib
import logging

import aiohttp

from .threat_db import ThreatDB, ThreatEntry

logger = logging.getLogger(__name__)


class Updater:
    def __init__(self, config: dict, threat_db: ThreatDB):
        self.url = config.get("url", "")
        self.interval = config.get("update_interval_seconds", 3600)
        self.threat_db = threat_db

    async def update(self) -> bool:
        """Pull latest threat data from mothership."""
        if not self.url:
            return False
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"X-DB-Version": self.threat_db.version}
                async with session.get(
                    f"{self.url}/threats",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 304:
                        logger.info("Threat DB up to date (v%s)", self.threat_db.version)
                        return True
                    if resp.status != 200:
                        logger.error("Mothership returned %d", resp.status)
                        return False
                    data = await resp.json()

            self.threat_db.version = data["version"]
            self.threat_db.blocked_server_hashes.update(data.get("blocked_server_hashes", []))
            self.threat_db.known_bad_descriptions.extend(data.get("known_bad_descriptions", []))
            for e in data.get("entries", []):
                self.threat_db.entries.append(ThreatEntry(**e))

            logger.info("Updated to v%s (%d entries)", self.threat_db.version, len(self.threat_db.entries))
            return True
        except Exception as e:
            logger.error("Update failed: %s", e)
            return False
