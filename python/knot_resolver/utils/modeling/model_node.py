from __future__ import annotations

from pathlib import Path
from typing import Any


class ModelNode:
    """"""

    def __init__(self, source: dict[Any, Any], tree_path: str = "/", base_path: Path = Path()):
        self._source = source if source else {}
        self._tree_path = tree_path
        self._base_path = base_path

    def validate(self) -> None:
        pass

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        raise NotImplementedError
