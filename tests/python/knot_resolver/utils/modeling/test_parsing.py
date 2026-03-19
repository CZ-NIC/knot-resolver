from pathlib import Path

import pytest

from knot_resolver.utils.modeling.errors import DataParsingError
from knot_resolver.utils.modeling.parsing import ParsedDataWrapper, parse_json_file, parse_yaml_file, try_to_parse_file

base_path = Path(__file__).parent / "test_parsing"


result_dict = {
    "none": None,
    "boolean": False,
    "number": 2026,
    "string": "this is string",
    "object": {
        "number": 5000,
        "string": "this is object string",
    },
    "array": [
        "item1",
        "item2",
        "item3",
    ],
}


@pytest.mark.parametrize("file", ["data.json"])
def test_parse_json_file(file: str) -> None:
    file_path = base_path / file
    wrapped_data = parse_json_file(file_path)
    assert wrapped_data.file == file_path
    assert wrapped_data.data == result_dict


@pytest.mark.parametrize("file", ["data.json", "data.yaml"])
def test_parse_yaml_file(file: str) -> None:
    file_path = base_path / file
    wrapped_data = parse_yaml_file(file_path)
    assert wrapped_data.file == file_path
    assert wrapped_data.data == result_dict


@pytest.mark.parametrize("file", ["duplicity.json", "duplicity.inner.json"])
def test_parse_json_file_duplicity(file: str) -> None:
    file_path = base_path / file
    with pytest.raises(DataParsingError):
        parse_json_file(file_path)


@pytest.mark.parametrize(
    "file",
    [
        "duplicity.json",
        "duplicity.inner.json",
        "duplicity.yaml",
        "duplicity.inner.yaml",
    ],
)
def test_parse_yaml_file_duplicity(file: str) -> None:
    file_path = base_path / file
    with pytest.raises(DataParsingError):
        parse_yaml_file(file_path)


@pytest.mark.parametrize("file", ["data.json", "data.yaml"])
def test_try_to_parse_file(file: str) -> None:
    file_path = base_path / file
    wrapped_data = try_to_parse_file(file_path)
    assert wrapped_data.file == file_path
    assert wrapped_data.data == result_dict


@pytest.mark.parametrize("file", ["include.root.yaml"])
def test_try_to_parse_file_yaml_include_tag(file: str) -> None:
    file_path = base_path / file
    wrapped_data = try_to_parse_file(file_path)
    assert wrapped_data.file == file_path
    assert wrapped_data.data.file.parent == base_path
    assert wrapped_data.data.data == result_dict


@pytest.mark.parametrize("file", ["include.inner.yaml"])
def test_try_to_parse_file_yaml_include_tag_inner(file: str) -> None:
    file_path = base_path / file
    wrapped_data = try_to_parse_file(file_path)
    assert wrapped_data.file == file_path
    assert wrapped_data.data["object"].data == result_dict["object"]


@pytest.mark.parametrize("file", ["include-key.yaml"])
def test_try_to_parse_file_yaml_include_key(file: str) -> None:
    file_path = base_path / file
    wrapped_data = try_to_parse_file(file_path)
    assert wrapped_data.file == file_path
    for key in ["none", "boolean", "number", "string"]:
        assert wrapped_data.data[key] == result_dict[key]
    for include in wrapped_data.data["include"]:
        print(include.data)
        assert isinstance(include, ParsedDataWrapper)
        data = include.data
        if "object" in data:
            assert data["object"] == result_dict["object"]
        elif "array" in data:
            assert data["array"] == result_dict["array"]
        else:
            assert False
