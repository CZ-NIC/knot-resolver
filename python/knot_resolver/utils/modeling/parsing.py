from __future__ import annotations

import json
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

import yaml
from yaml.constructor import ConstructorError

from knot_resolver.utils.modeling.errors import DataParsingError

if TYPE_CHECKING:
    from yaml.nodes import MappingNode


def _json_raise_duplicates(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    """
    JSON hook used in 'json.loads()' that detects duplicate keys in the parsed data.

    The code for this hook was highly inspired by: https://stackoverflow.com/q/14902299/12858520
    """
    mapping: dict[Any, Any] = {}
    for key, value in pairs:
        if key in mapping:
            msg = f"duplicate key detected: {key}"
            raise DataParsingError(msg)
        mapping[key] = value
    return mapping


class _YAMLRaiseDuplicatesLoader(yaml.SafeLoader):
    """
    YAML loader used in 'yaml.loads()' that detects duplicate keys in the parsed data.

    The code for this loader was highly inspired by: https://gist.github.com/pypt/94d747fe5180851196eb
    The loader extends yaml.SafeLoader, so it should be safe, even though the linter reports unsafe-yaml-load (S506).
    More about safe loader: https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
    """

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            # we need to check, that the key object can be used in a hash table
            try:
                _ = hash(key)
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found unacceptable key ({exc})",
                    key_node.start_mark,
                ) from exc

            # check for duplicate keys
            if key in mapping:
                msg = f"duplicate key detected: {key_node.start_mark}"
                raise DataParsingError(msg)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


class DataFormat(Enum):
    YAML = auto()
    JSON = auto()

    def loads(self, text: str) -> dict[Any, Any]:
        """Load data from string in data format and return the data in dictionary."""
        if self is DataFormat.YAML:
            return yaml.load(text, Loader=_YAMLRaiseDuplicatesLoader)  # noqa: S506
        if self is DataFormat.JSON:
            return json.loads(text, object_pairs_hook=_json_raise_duplicates)
        msg = f"parsing data from '{self}' format is not implemented"
        raise NotImplementedError(msg)

    def dumps(self, data: dict[Any, Any], indent: int | None = None) -> str:
        """Dump dictionary data to string in required data format."""
        if self is DataFormat.YAML:
            return yaml.safe_dump(data, indent=indent)
        if self is DataFormat.JSON:
            return json.dumps(data, indent=indent)
        msg = f"exporting data to '{self}' format is not implemented"
        raise NotImplementedError(msg)


def parse_yaml(data: str) -> dict[Any, Any]:
    """Parse YAML string and return the data in dictionary."""
    return DataFormat.YAML.loads(data)


def parse_json(data: str) -> dict[Any, Any]:
    """Parse JSON string and return the data in dictionary."""
    return DataFormat.JSON.loads(data)


def try_to_parse(data: str) -> dict[Any, Any]:
    """Attempt to parse data string as a JSON or YAML and return it's dictionary."""
    try:
        return parse_json(data)
    except json.JSONDecodeError:
        try:
            return parse_yaml(data)
        except yaml.YAMLError as e:
            # YAML parsing error should be sufficient because the JSON can be parsed by the YAML parser.
            # We should receive a helpful error message for JSON as well.
            raise DataParsingError(e) from e
