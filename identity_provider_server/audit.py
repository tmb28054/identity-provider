"""Access audit log for the identity provider.

Records all authentication attempts (success and failure) as structured
JSON lines to a dedicated audit log file. Each entry includes:
- timestamp (ISO 8601)
- username (or empty for anonymous)
- ip address
- service/path being accessed
- result (success, failure, session_reuse)
- reason (for failures: invalid_credentials, invalid_mfa, rate_limited, etc.)
- protocol (saml, oauth, admin, user_settings)
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

AUDIT_LOG_FILENAME = "audit.log"


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: str = ""
    username: str = ""
    ip: str = ""
    service: str = ""
    protocol: str = ""
    result: str = ""  # "success", "failure", "session_reuse"
    reason: str = ""  # failure reason or empty
    user_agent: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class AuditLogger:
    """Writes structured audit log entries to a JSON-lines file."""

    def __init__(self, data_dir: str | Path) -> None:
        self._log_path = Path(data_dir) / AUDIT_LOG_FILENAME
        # Ensure the file exists
        self._log_path.touch(exist_ok=True)

    @property
    def log_path(self) -> Path:
        """Return the path to the audit log file."""
        return self._log_path

    def log(
        self,
        *,
        username: str = "",
        ip: str = "",
        service: str = "",
        protocol: str = "",
        result: str = "",
        reason: str = "",
        user_agent: str = "",
    ) -> None:
        """Write an audit entry to the log file.

        Args:
            username: Authenticated or attempted username.
            ip: Client IP address.
            service: Service path or target (e.g. 'aws', 'admin', 'user').
            protocol: Protocol type (saml, oauth, admin, user_settings).
            result: Outcome (success, failure, session_reuse).
            reason: Failure reason (empty for success).
            user_agent: Client user-agent string.
        """
        entry = AuditEntry(
            username=username,
            ip=ip,
            service=service,
            protocol=protocol,
            result=result,
            reason=reason,
            user_agent=user_agent,
        )
        line = json.dumps(asdict(entry), separators=(",", ":"))
        try:
            with self._log_path.open("a") as f:
                f.write(line + "\n")
        except OSError:
            logger.warning("Failed to write audit log entry")

    def read_recent(self, count: int = 100) -> list[dict]:
        """Read the most recent audit entries.

        Args:
            count: Maximum number of entries to return.

        Returns:
            List of audit entry dicts, newest first.
        """
        try:
            lines = self._log_path.read_text().strip().splitlines()
        except OSError:
            return []
        entries = []
        for line in reversed(lines[-count:]):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
