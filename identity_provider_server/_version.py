import re
from pathlib import Path

_CHANGELOG = Path(__file__).parent.parent / "CHANGELOG.md"
_VERSION_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\]", re.MULTILINE)


def _read_version() -> str:
    match = _VERSION_RE.search(_CHANGELOG.read_text())
    if not match:
        raise RuntimeError("No version found in CHANGELOG.md")
    return match.group(1)


__version__ = _read_version()
