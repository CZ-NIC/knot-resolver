from pathlib import Path

from knot_resolver import __version__


def test_version() -> None:
    with Path("PROJECT_VERSION").open() as version_file:
        version = version_file.read().strip()

    assert __version__ == version
