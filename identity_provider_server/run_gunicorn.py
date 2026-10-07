"""Production entry point using gunicorn.

Provides the `run-idp` command which accepts all the same arguments as
`identity-provider-server` but runs the app under gunicorn instead of
the Flask development server.
"""

from __future__ import annotations

import argparse
import sys

from .__main__ import DEFAULT_DATA_DIR, INIT_DATA_DIR, _configure_logging
from ._version import __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identity Provider Server (gunicorn production mode)"
    )
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
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help=(
            "Number of gunicorn worker processes (default: 1). The rate limiter "
            "and single-use MFA/captcha/WebAuthn nonce stores are per-process; "
            "running more than one worker requires a shared store, or those "
            "controls weaken proportionally to the worker count."
        ),
    )
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
        help="Path to ADFS config YAML file. Enables ADFS/LDAP authentication mode.",
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

        data_dir = args.data_dir
        if data_dir == str(DEFAULT_DATA_DIR):
            data_dir = str(INIT_DATA_DIR)
        run_init(data_dir)
        sys.exit(0)

    from .config import load_config

    # Load config from file + env, then apply CLI overrides
    config = load_config(args.data_dir, config_path=args.config)

    if args.host is not None:
        config.server.host = args.host
    if args.port is not None:
        config.server.port = args.port
    if args.provider_name is not None:
        config.saml.provider_name = args.provider_name
    if args.session_duration is not None:
        config.saml.session_duration_hours = args.session_duration

    _configure_logging(config.logging.level, args.verbose)

    # Load ADFS config if specified
    adfs_cfg = None
    group_role_map = None
    skip_ssl = args.skip_ldap_ssl_verify
    if args.adfs_config:
        from .adfs import load_adfs_config, load_group_role_map

        adfs_cfg = load_adfs_config(args.adfs_config)
        group_role_map = load_group_role_map(config.data_dir)
        # Allow skip_ssl_verify from the adfs config file
        if adfs_cfg.get("skip_ssl_verify"):
            skip_ssl = True

    from .app import create_app

    app = create_app(
        config.data_dir,
        host=config.server.host,
        port=config.server.port,
        provider_name=config.saml.provider_name,
        session_duration_hours=config.saml.session_duration_hours,
        secret_key=config.security.secret_key or None,
        audit_chain_key=config.security.audit_chain_key,
        rate_limit_max_attempts=config.security.rate_limit_max_attempts,
        rate_limit_window_seconds=config.security.rate_limit_window_seconds,
        users_file=config.data.users_file,
        certificate_file=config.data.certificate_file,
        private_key_file=config.data.private_key_file,
        adfs_config=adfs_cfg,
        group_role_map=group_role_map,
        skip_ldap_ssl_verify=skip_ssl,
        trust_proxy=config.server.trust_proxy,
        webauthn_enabled=config.webauthn.enabled,
        webauthn_rp_id=config.webauthn.rp_id,
        webauthn_rp_name=config.webauthn.rp_name,
        webauthn_expected_origin=config.webauthn.expected_origin,
    )

    bind = f"{config.server.host}:{config.server.port}"

    from gunicorn.app.base import BaseApplication

    class _IdpApplication(BaseApplication):  # type: ignore[misc]
        def __init__(self, flask_app, options=None):  # type: ignore[no-untyped-def]
            self.flask_app = flask_app
            self.options = options or {}
            super().__init__()

        def load_config(self):  # type: ignore[no-untyped-def]
            for key, value in self.options.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key.lower(), value)

        def load(self):  # type: ignore[no-untyped-def]
            return self.flask_app

    options = {
        "bind": bind,
        "workers": args.workers,
        "accesslog": "-",
        "errorlog": "-",
    }

    _IdpApplication(app, options).run()


if __name__ == "__main__":
    main()
