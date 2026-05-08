from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from ._version import __version__
from .app import create_app

DEFAULT_DATA_DIR = Path(__file__).parent.parent / "data"


def _configure_logging(verbosity: int) -> None:
    """Configure structured logging based on verbosity level."""
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        fmt='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root = logging.getLogger("identity_provider_server")
    root.setLevel(level)
    root.addHandler(handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Identity Provider Server")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Directory containing users.json, idp.crt, and idp.key (default: ./data)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--provider-name",
        default="local-idp",
        help="SAML provider name registered in AWS IAM (default: local-idp)",
    )
    parser.add_argument(
        "--session-duration",
        type=int,
        default=1,
        help="SAML assertion validity in hours, 1-12 (default: 1)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    args = parser.parse_args()

    _configure_logging(args.verbose)

    app = create_app(
        args.data_dir,
        host=args.host,
        port=args.port,
        provider_name=args.provider_name,
        session_duration_hours=args.session_duration,
    )
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
