from knot_resolver import __version__


def test_version() -> None:
    with open("VERSION", "r") as version_file:
        version = version_file.read().strip()

    assert __version__ == version
