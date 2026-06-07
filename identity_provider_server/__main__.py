from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from ._version import __version__
from .app import create_app
from .config import load_config

DEFAULT_DATA_DIR = Path(__file__).parent.parent / "data"


def _configure_logging(level_str: str, verbosity: int) -> None:
    """Configure structured logging based on config level and verbosity override."""
    # CLI verbosity takes precedence over config file level
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = getattr(logging, level_str.upper(), logging.WARNING)

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
        help="Directory containing config.yaml, users.json, idp.crt, and idp.key (default: ./data)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to config.yaml (default: <data-dir>/config.yaml)",
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--debug", action="store_true", default=None)
    parser.add_argument(
        "--provider-name",
        default=None,
        help="SAML provider name registered in AWS IAM",
    )
    parser.add_argument(
        "--session-duration",
        type=int,
        default=None,
        help="SAML assertion validity in hours, 1-12",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "--adfs-config",
        default=None,
        help="Path to ADFS config YAML file. Enables ADFS/LDAP authentication mode. "
        "If the file does not exist, you will be prompted for connection details.",
    )
    parser.add_argument(
        "--skip-ldap-ssl-verify",
        action="store_true",
        default=False,
        help=(
            "Disable TLS certificate verification for LDAP connections "
            "(not recommended for production)"
        ),
    )
    parser.add_argument(
        "--init",
        action="store_true",
        default=False,
        help=(
            "Initialize a new deployment: generate certificates, "
            "create config and example files, then exit."
        ),
    )
    args = parser.parse_args()

    # Handle --init before anything else
    if args.init:
        from .init_project import run_init

        run_init(args.data_dir)
        sys.exit(0)

    # Load config from file + env, then apply CLI overrides
    config = load_config(args.data_dir, config_path=args.config)

    # CLI arguments override config values (only if explicitly provided)
    if args.host is not None:
        config.server.host = args.host
    if args.port is not None:
        config.server.port = args.port
    if args.debug is not None:
        config.server.debug = args.debug
    if args.provider_name is not None:
        config.saml.provider_name = args.provider_name
    if args.session_duration is not None:
        config.saml.session_duration_hours = args.session_duration

    _configure_logging(config.logging.level, args.verbose)

    # Load ADFS config if specified
    adfs_cfg = None
    group_role_map = None
    if args.adfs_config:
        from .adfs import load_adfs_config, load_group_role_map

        adfs_cfg = load_adfs_config(args.adfs_config)
        group_role_map = load_group_role_map(config.data_dir)

    app = create_app(
        config.data_dir,
        host=config.server.host,
        port=config.server.port,
        provider_name=config.saml.provider_name,
        session_duration_hours=config.saml.session_duration_hours,
        secret_key=config.security.secret_key or None,
        rate_limit_max_attempts=config.security.rate_limit_max_attempts,
        rate_limit_window_seconds=config.security.rate_limit_window_seconds,
        users_file=config.data.users_file,
        certificate_file=config.data.certificate_file,
        private_key_file=config.data.private_key_file,
        adfs_config=adfs_cfg,
        group_role_map=group_role_map,
        skip_ldap_ssl_verify=args.skip_ldap_ssl_verify,
    )
    app.run(host=config.server.host, port=config.server.port, debug=config.server.debug)


if __name__ == "__main__":
    main()
