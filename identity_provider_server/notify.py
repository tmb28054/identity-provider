"""Outbound incident/operational notifications.

A single, optional outbound channel so the workload can actually reach an
operator when something security-relevant happens (a backup failure, an
``idpadmin`` grant, a restore) rather than relying on someone opening the admin
panel. The channel is a webhook configured via the ``IDP_NOTIFY_WEBHOOK``
environment variable; when it is unset, notifications are a no-op.

Design notes:

* Best effort — a notification failure must never break the operation that
  triggered it, so every send is wrapped and swallows transport errors.
* No secrets in payloads — callers pass a short event name and a human message,
  never credentials or token material.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request

logger = logging.getLogger(__name__)

NOTIFY_WEBHOOK_ENV = "IDP_NOTIFY_WEBHOOK"
_TIMEOUT_SECONDS = 5


def is_configured() -> bool:
    """True if an outbound notification channel is configured."""
    return bool(os.environ.get(NOTIFY_WEBHOOK_ENV))


def notify(event: str, message: str, *, severity: str = "info") -> bool:
    """Send a best-effort notification. Returns True if a send was attempted.

    Args:
        event: Short machine-readable event name (e.g. ``backup_failed``).
        message: Human-readable description (no secrets).
        severity: ``info`` | ``warning`` | ``critical``.

    Returns:
        True if a webhook POST was attempted, False if no channel is configured.
    """
    url = os.environ.get(NOTIFY_WEBHOOK_ENV)
    if not url:
        return False
    if not url.startswith("https://"):
        logger.warning("Refusing to send notification to non-HTTPS webhook")
        return False
    payload = json.dumps(
        {"event": event, "severity": severity, "message": message}
    ).encode()
    # The URL is validated to be https:// above, so the blacklisted-scheme
    # concern (file:/custom schemes) does not apply here.
    req = urllib.request.Request(  # nosec B310
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS):  # nosec B310
            pass
    except (OSError, ValueError) as exc:  # pragma: no cover - transport error path
        logger.warning("Notification send failed for event=%s: %s", event, exc)
    return True
