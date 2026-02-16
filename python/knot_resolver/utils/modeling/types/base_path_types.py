from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from knot_resolver.logging import get_logger
from knot_resolver.utils.modeling.context import Strictness
from knot_resolver.utils.modeling.errors import DataTypeError

from .base_custom_type import BaseCustomType

if TYPE_CHECKING:
    from knot_resolver.utils.modeling.context import Context

logger = get_logger(__name__)


class BasePath(BaseCustomType):
    """Base class to work with pathlib.Path value."""

    _path: Path
    _path_absolute: Path

    def _validate(self, context: Context) -> None:
        if context.strictness > Strictness.PERMISSIVE and not isinstance(self._value, str):
            msg = (
                f"Unexpected value for '{type(self)}'"
                f" Expected string, got '{self._value}' with type '{type(self._value)}'"
            )
            raise DataTypeError(msg)
        self._path = Path(self._value)
        self._path_absolute = self._path if self._path.is_absolute() else self._base_path / self._path

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "string"}
