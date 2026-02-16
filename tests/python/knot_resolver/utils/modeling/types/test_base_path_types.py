from pathlib import Path
from typing import Any

import pytest

from knot_resolver.utils.modeling.context import Context, Strictness
from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.base_path_types import BasePath

context_default = Context(strictness=Strictness.BASIC)
base_path = Path("/base/path/prefix")


@pytest.mark.parametrize(
    "value",
    [
        "relative/path/to/dir",
        "relative/path/to/file.txt",
        "/absolute/path/to/dir",
        "/absolute/path/to/file.txt",
    ],
)
def test_base_path(value: str):
    obj = BasePath(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", [1, 1.1, True, False])
def test_base_path_invalid(value: Any):
    obj = BasePath(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)
