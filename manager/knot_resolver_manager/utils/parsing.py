import copy
import json
import re
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from knot_resolver_manager.exceptions import DataException, ParsingException
from knot_resolver_manager.utils.types import is_internal_field_name


class ParsedTree:
    """
    Simple wrapper for parsed data. Changes internal naming convention (snake case)
    to external (dashes) on the fly.

    IMMUTABLE, DO NOT MODIFY
    """

    @staticmethod
    def _convert_internal_field_name_to_external(name: Any) -> Any:
        if isinstance(name, str):
            return name.replace("_", "-")
        return name

    @staticmethod
    def _convert_external_field_name_to_internal(name: Any) -> Any:
        if isinstance(name, str):
            return name.replace("-", "_")
        return name

    def __init__(self, data: Union[Dict[str, Any], str, int, bool]):
        self._data = data

    def to_raw(self) -> Union[Dict[str, Any], str, int, bool]:
        return self._data

    def __getitem__(self, key: str) -> Any:
        assert isinstance(self._data, dict)
        return self._data[ParsedTree._convert_internal_field_name_to_external(key)]

    def __contains__(self, key: str) -> bool:
        assert isinstance(self._data, dict)
        return ParsedTree._convert_internal_field_name_to_external(key) in self._data

    def __str__(self) -> str:
        return json.dumps(self._data, sort_keys=False, indent=2)

    def keys(self) -> Set[Any]:
        assert isinstance(self._data, dict)
        return {ParsedTree._convert_external_field_name_to_internal(key) for key in self._data.keys()}

    _SUBTREE_MUTATION_PATH_PATTERN = re.compile(r"^(/[^/]+)*/?$")

    def update(self, path: str, data: "ParsedTree") -> "ParsedTree":

        # prepare and validate the path object
        path = path[:-1] if path.endswith("/") else path
        if re.match(ParsedTree._SUBTREE_MUTATION_PATH_PATTERN, path) is None:
            raise ParsingException("Provided object path for mutation is invalid.")
        if "_" in path:
            raise ParsingException("Provided object path contains character '_', which is illegal")
        # Note: mutation happens on the internal dict only, therefore we are working with external
        # naming only. That means, there are '-' in between words.
        path = path[1:] if path.startswith("/") else path

        # now, the path variable should contain '/' separated field names

        # check if we should mutate whole object
        if path == "":
            return data

        # find the subtree we will replace in a copy of the original object
        to_mutate = copy.deepcopy(self.to_raw())
        obj = to_mutate
        parent = None

        for segment in path.split("/"):
            assert isinstance(obj, dict)

            if segment == "":
                raise ParsingException(f"Unexpectedly empty segment in path '{path}'")
            elif is_internal_field_name(segment):
                raise ParsingException(
                    "No, changing internal fields (starting with _) is not allowed. Nice try though."
                )
            elif segment in obj:
                parent = obj
                obj = obj[segment]
            elif segment not in obj:
                parent = obj
                obj = {}
                parent[segment] = obj
        assert parent is not None

        # assign the subtree
        last_name = path.split("/")[-1]
        parent[last_name] = data.to_raw()

        return ParsedTree(to_mutate)


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def _json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise DataException(f"Duplicate attribute key detected: {key}")
        dict_out[key] = val
    return dict_out


# custom loader for 'yaml.load()' to detect duplicate keys in data
# source: https://gist.github.com/pypt/94d747fe5180851196eb
class _RaiseDuplicatesLoader(yaml.SafeLoader):
    def construct_mapping(self, node: Union[MappingNode, Any], deep: bool = False) -> Dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, f"expected a mapping node, but found {node.id}", node.start_mark)
        mapping: Dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)  # type: ignore
            # we need to check, that the key object can be used in a hash table
            try:
                _ = hash(key)  # type: ignore
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found unacceptable key ({exc})",
                    key_node.start_mark,
                )

            # check for duplicate keys
            if key in mapping:
                raise DataException(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


class _Format(Enum):
    YAML = auto()
    JSON = auto()

    def parse_to_dict(self, text: str) -> ParsedTree:
        if self is _Format.YAML:
            # RaiseDuplicatesLoader extends yaml.SafeLoader, so this should be safe
            # https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
            return ParsedTree(yaml.load(text, Loader=_RaiseDuplicatesLoader))  # type: ignore
        elif self is _Format.JSON:
            return ParsedTree(json.loads(text, object_pairs_hook=_json_raise_duplicates))
        else:
            raise NotImplementedError(f"Parsing of format '{self}' is not implemented")

    def dict_dump(self, data: Dict[str, Any]) -> str:
        if self is _Format.YAML:
            return yaml.safe_dump(data)  # type: ignore
        elif self is _Format.JSON:
            return json.dumps(data)
        else:
            raise NotImplementedError(f"Exporting to '{self}' format is not implemented")

    @staticmethod
    def from_mime_type(mime_type: str) -> "_Format":
        formats = {
            "application/json": _Format.JSON,
            "application/octet-stream": _Format.JSON,  # default in aiohttp
            "text/vnd.yaml": _Format.YAML,
        }
        if mime_type not in formats:
            raise DataException("Unsupported MIME type")
        return formats[mime_type]


def parse(data: str, mime_type: str) -> ParsedTree:
    return _Format.from_mime_type(mime_type).parse_to_dict(data)


def parse_yaml(data: str) -> ParsedTree:
    return _Format.YAML.parse_to_dict(data)


def parse_json(data: str) -> ParsedTree:
    return _Format.JSON.parse_to_dict(data)
