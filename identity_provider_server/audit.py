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

import hashlib
import hmac
import json
import logging
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

AUDIT_LOG_FILENAME = "audit.log"

# Genesis value for the per-record hash chain (first record's prev_hash).
_CHAIN_GENESIS = "0" * 64

# Keep only this many leading characters of a username in the stdout mirror.
_USERNAME_PREFIX_LEN = 3


def _redact_username(username: str) -> str:
    """Return a truncated, length-tagged form of ``username`` for stdout.

    Keeps the first few characters plus the total length so an operator can
    correlate entries without the full identifier being duplicated into the
    stdout sink. Empty input is passed through unchanged.

    Args:
        username: The full username from the on-disk record.

    Returns:
        A redacted form such as ``"ali…(5)"`` for ``"alice"``; ``""`` stays
        ``""``.
    """
    if not username:
        return ""
    if len(username) <= _USERNAME_PREFIX_LEN:
        return f"{username}…({len(username)})"
    return f"{username[:_USERNAME_PREFIX_LEN]}…({len(username)})"


def _hash_user_agent(user_agent: str) -> str:
    """Return a short sha256 digest of ``user_agent`` for stdout.

    The full User-Agent can carry identifying detail, so the stdout mirror
    records only a short digest (prefixed ``sha256:``) that still lets an
    operator group identical clients. Empty input is passed through unchanged.

    Args:
        user_agent: The full User-Agent string from the on-disk record.

    Returns:
        ``""`` for empty input, else ``"sha256:<first 12 hex chars>"``.
    """
    if not user_agent:
        return ""
    digest = hashlib.sha256(user_agent.encode()).hexdigest()
    return f"sha256:{digest[:12]}"


@dataclass
class AuditEntry:
    """A single audit log entry.

    ``seq`` and ``prev_hash`` form a tamper-evident hash chain: each record's
    ``entry_hash`` covers its own content plus the previous record's hash, so
    truncation or in-place rewriting of any line is detectable by re-walking
    the chain (finding idp-20261003 F9).
    """

    timestamp: str = ""
    username: str = ""
    ip: str = ""
    service: str = ""
    protocol: str = ""
    result: str = ""  # "success", "failure", "session_reuse"
    reason: str = ""  # failure reason or empty
    user_agent: str = ""
    seq: int = 0
    prev_hash: str = ""
    entry_hash: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class AuditLogger:
    """Writes structured audit log entries to a 0600 JSON-lines file.

    Beyond plain appends this logger:

    * creates the file mode 0600 so it is not world-readable (F8);
    * chains each record to the previous one with a keyed hash so tampering is
      detectable (F9);
    * mirrors each record to stdout, which the container/systemd platform
      collects off-host, so the local file is not the only copy (F9);
    * surfaces write failures loudly via an optional callback instead of
      silently swallowing them (F9).
    """

    def __init__(
        self,
        data_dir: str | Path,
        *,
        chain_key: str = "",
        failure_callback: Callable[[str], None] | None = None,
        mirror_stdout: bool = True,
    ) -> None:
        self._log_path = Path(data_dir) / AUDIT_LOG_FILENAME
        self._chain_key = chain_key.encode() if chain_key else b"idp-audit-chain"
        self._failure_callback = failure_callback
        self._mirror_stdout = mirror_stdout
        # Create the file 0600 if absent (never world-readable). If it already
        # exists, tighten its mode best-effort.
        if not self._log_path.exists():
            fd = os.open(self._log_path, os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
        else:
            try:
                self._log_path.chmod(0o600)
            except OSError:  # pragma: no cover - best effort on exotic FS
                logger.warning("Could not chmod 600 the audit log")
        self._seq, self._last_hash = self._resume_chain()

    def _resume_chain(self) -> tuple[int, str]:
        """Return the next sequence number and the last record's hash."""
        try:
            lines = self._log_path.read_text().strip().splitlines()
        except OSError:  # pragma: no cover - file just created
            return 0, _CHAIN_GENESIS
        for line in reversed(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            return int(rec.get("seq", -1)) + 1, rec.get("entry_hash", _CHAIN_GENESIS)
        return 0, _CHAIN_GENESIS

    def _compute_hash(self, payload: dict, prev_hash: str) -> str:
        """Keyed hash over the record body + previous hash (chain link)."""
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return hmac.new(
            self._chain_key, (prev_hash + body).encode(), hashlib.sha256
        ).hexdigest()

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
            seq=self._seq,
            prev_hash=self._last_hash,
        )
        payload = asdict(entry)
        # Hash covers everything except the entry_hash field itself.
        payload_for_hash = {k: v for k, v in payload.items() if k != "entry_hash"}
        entry.entry_hash = self._compute_hash(payload_for_hash, self._last_hash)
        payload["entry_hash"] = entry.entry_hash
        line = json.dumps(payload, separators=(",", ":"))
        try:
            with self._log_path.open("a") as f:
                f.write(line + "\n")
            # Advance the chain only after a durable write.
            self._seq += 1
            self._last_hash = entry.entry_hash
        except OSError as exc:
            # Do NOT swallow — a logging blackout must be loud (F9).
            logger.error("Failed to write audit log entry: %s", exc)
            if self._failure_callback is not None:
                try:
                    self._failure_callback(f"audit log write failed: {exc}")
                except Exception:  # noqa: BLE001 - callback must never raise into caller  # pragma: no cover - defensive
                    logger.exception("Audit failure callback raised")
            return
        # Mirror off-host via stdout (collected by the container/systemd layer)
        # so the local file is not the only copy. The stdout mirror is REDACTED
        # (User-Agent hashed, username truncated) to avoid duplicating full PII
        # into a second, often less-protected sink; the on-disk record above and
        # the hash chain are byte-for-byte unchanged (F4).
        if self._mirror_stdout:
            redacted = dict(payload)
            redacted["username"] = _redact_username(entry.username)
            redacted["user_agent"] = _hash_user_agent(entry.user_agent)
            mirror_line = json.dumps(redacted, separators=(",", ":"))
            try:
                sys.stdout.write("AUDIT " + mirror_line + "\n")
                sys.stdout.flush()
            except (OSError, ValueError):  # pragma: no cover - stdout closed
                pass

    def verify_chain(self) -> bool:
        """Re-walk the on-disk hash chain; return True if intact.

        Detects truncation (gap in ``seq``) and any in-place rewrite (a record
        whose recomputed hash no longer matches the stored ``entry_hash`` or
        the following record's ``prev_hash``).
        """
        try:
            lines = self._log_path.read_text().strip().splitlines()
        except OSError:  # pragma: no cover - defensive
            return False
        prev = _CHAIN_GENESIS
        for expected_seq, line in enumerate(lines):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False
            if int(rec.get("seq", -1)) != expected_seq:
                return False
            if rec.get("prev_hash") != prev:
                return False
            stored = rec.get("entry_hash", "")
            body = {k: v for k, v in rec.items() if k != "entry_hash"}
            if self._compute_hash(body, prev) != stored:
                return False
            prev = stored
        return True

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
