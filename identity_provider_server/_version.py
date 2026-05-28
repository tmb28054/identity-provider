import re
from pathlib import Path

_VERSION_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)

_PACKAGE_DIR = Path(__file__).parent


def _read_version() -> str:
    # Try CHANGELOG.md in the source tree (editable installs and build time)
    changelog = _PACKAGE_DIR.parent / "CHANGELOG.md"
    if changelog.is_file():
        match = _VERSION_RE.search(changelog.read_text())
        if match:
            return match.group(1)

    # Fallback: read from installed package metadata (pip install from wheel)
    try:
        from importlib.metadata import version
        return version("identity-provider-server")
    except Exception:  # nosec B110
        pass

    raise RuntimeError(
        "No version found — CHANGELOG.md missing and package metadata unavailable"
    )


__version__ = _read_version()
