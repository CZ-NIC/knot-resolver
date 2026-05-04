from pathlib import Path

import pytest

from knot_resolver.utils.modeling import DataModel, DataStore

base_path = Path(__file__).parent


class TestModel(DataModel):
    pass


# def test_data_store_load_files() -> None:
#     files = [
#         base_path / "config.test.yaml",
#         base_path / "config.test.json",
#     ]
#     data_store = DataStore(files, TestModel)
#     data_store.load_files()
