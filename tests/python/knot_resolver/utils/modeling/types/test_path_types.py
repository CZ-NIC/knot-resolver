from pathlib import Path
from typing import Any

import pytest

from knot_resolver.utils.modeling.context import Context, Strictness
from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.path_types import (
    Directory,
    File,
    FilePath,
    ReadableFile,
    WritableDirectory,
    WritableFilePath,
)

context_default = Context(strictness=Strictness.STRICT)
base_path = Path(__file__).parent / "path_testing"

readable_dirs = [
    "readable_dir",  # relative
    str(base_path) + "/readable_dir",  # absolute
]

unreadable_dirs = [
    "unreadable_dir",
    str(base_path) + "/unreadable_dir",
]

writable_dirs = [
    "writable_dir",
    str(base_path) + "/writable_dir",
]

unwritable_dirs = [
    "unwritable_dir",
    str(base_path) + "/unwritable_dir",
]

readable_files = [
    "readable.file",
    str(base_path) + "/readable.file",
]

unreadable_files = [
    "unreadable.file",
    str(base_path) + "/unreadable.file",
]

writable_files = [
    "writable.file",
    str(base_path) + "/writable.file",
]

unwritable_files = [
    "unwritable.file",
    str(base_path) + "/unwritable.file",
]

nonexisting_files = [
    "nonexisting.file",
    str(base_path) + "/nonexisting.file",
]


@pytest.mark.parametrize("value", readable_dirs + writable_dirs)
def test_directory(value: str):
    obj = Directory(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", readable_files + writable_files)
def test_directory_invalid(value: Any):
    obj = Directory(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)


@pytest.mark.parametrize("value", readable_files + writable_files)
def test_file(value: str):
    obj = File(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", readable_dirs + writable_dirs)
def test_file_invalid(value: Any):
    obj = File(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)


@pytest.mark.parametrize("value", readable_files + writable_files + nonexisting_files)
def test_filepath(value: str):
    obj = FilePath(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", readable_dirs + writable_dirs)
def test_filepath_invalid(value: Any):
    obj = File(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)


@pytest.mark.parametrize("value", readable_files)
def test_readablefile(value: str):
    obj = ReadableFile(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", unreadable_files + readable_dirs + writable_dirs)
def test_readablefile_invalid(value: Any):
    obj = ReadableFile(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)


@pytest.mark.parametrize("value", writable_dirs)
def test_writabledirectory(value: str):
    obj = WritableDirectory(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", readable_files + writable_files + readable_dirs + unwritable_dirs)
def test_writabledirectory_invalid(value: Any):
    obj = WritableDirectory(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)


@pytest.mark.parametrize("value", writable_files + nonexisting_files)
def test_writablefilepath(value: str):
    obj = WritableFilePath(value, base_path=base_path)
    obj.validate(context_default)
    assert obj._path() == Path(value)
    assert obj._path_absolute() == Path(value) if value.startswith("/") else base_path / value


@pytest.mark.parametrize("value", readable_files + readable_dirs + writable_dirs)
def test_writablefilepath_invalid(value: Any):
    obj = WritableFilePath(value, base_path=base_path)
    with pytest.raises(DataModelingError):
        obj.validate(context_default)
