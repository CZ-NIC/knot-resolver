from __future__ import annotations

from asyncio import Lock
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .parsing import try_to_parse_file

if TYPE_CHECKING:
    from .data_model import DataModel


class DataStore:
    """Used to load, store and manage a data.

    Attributes:
        files (list[str | Path]):
            A list of configuration files from which the configuration should be loaded.

    """

    def __init__(self, files: list[str | Path], model: type[DataModel]) -> None:
        self._model = model
        self._files = files

        # self._verifier: list[Any] = []
        # self._callbacks: list[Any] = []
        self._lock: Lock = Lock()

    def load_files(self) -> None:
        data: DataModel = self._model()
        for file in self._files:
            file_path = Path(file)
            file_parsed_data = try_to_parse_file(file_path)

            base_path = file_path.parent
            file_data: DataModel = self._model(file_parsed_data, base_path=base_path)
            # combined_data.append(file_data)

        raise ValueError
        # config.validate()
