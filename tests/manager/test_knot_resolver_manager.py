import toml

from knot_resolver import __version__


def test_version():

    with open("pyproject.toml", "r") as f:
        pyproject = toml.load(f)

    version = pyproject["tool"]["poetry"]["version"]
    assert __version__ == version
