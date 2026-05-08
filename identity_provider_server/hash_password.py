"""CLI utility to hash passwords for use in users.json."""
from __future__ import annotations

import argparse
import getpass
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hash a password for use in users.json (bcrypt)"
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to hash (omit to be prompted securely)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=12,
        help="bcrypt cost factor (default: 12)",
    )
    args = parser.parse_args()

    try:
        import bcrypt
    except ImportError:
        print("Error: bcrypt is not installed. Run: pip install identity-provider-server", file=sys.stderr)
        sys.exit(1)

    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if password != confirm:
            print("Error: passwords do not match", file=sys.stderr)
            sys.exit(1)

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=args.rounds))
    print(hashed.decode())


if __name__ == "__main__":
    main()
