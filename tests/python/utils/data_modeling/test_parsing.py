import pytest

from knot_resolver.utils.data_modeling.errors import DataParsingError
from knot_resolver.utils.data_modeling.parsing import parse_json, parse_yaml, try_to_parse

json_data = """
{
    "none": null,
    "boolean": false,
    "number": 2026,
    "string": "this is string",
    "object": {
        "number": 5000,
        "string": "this is object string"
    },
    "array": [
        "item1",
        "item2",
        "item3"
    ]
}
"""

json_data_duplicates = """
{
    "duplicity-key": 1,
    "duplicity-key": 2
}
"""

json_data_duplicates_inner = """
{
    "object": {
        "duplicity-key": 1,
        "duplicity-key": 2
    }
}
"""

yaml_data = """
none: null
boolean: false
number: 2026
string: this is string
object:
  number: 5000
  string: this is object string
array:
  - item1
  - item2
  - item3
"""

yaml_data_duplicates = """
duplicity-key: 1
duplicity-key: 2
"""

yaml_data_duplicates_inner = """
object:
    duplicity-key: 1
    duplicity-key: 2
"""

data_dict = {
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


def test_parse_json() -> None:
    data = parse_json(json_data)
    assert data == data_dict


@pytest.mark.parametrize("data", [json_data, yaml_data])
def test_parse_yaml(data: str) -> None:
    data = parse_yaml(data)
    assert data == data_dict


@pytest.mark.parametrize(
    "data",
    [
        json_data_duplicates,
        json_data_duplicates_inner,
    ],
)
def test_parse_json_duplicates(data: str) -> None:
    with pytest.raises(DataParsingError):
        parse_json(data)


@pytest.mark.parametrize(
    "data",
    [
        json_data_duplicates,
        json_data_duplicates_inner,
        yaml_data_duplicates,
        yaml_data_duplicates_inner,
    ],
)
def test_parse_yaml_duplicates(data: str) -> None:
    with pytest.raises(DataParsingError):
        parse_yaml(data)


@pytest.mark.parametrize("data", [json_data, yaml_data])
def test_try_to_parse(data: str) -> None:
    data = try_to_parse(data)
    assert data == data_dict
