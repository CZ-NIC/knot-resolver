import json
import os
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from .exceptions import DataParsingError, DataValidationError
from .renaming import Renamed, renamed

_include_key = "!include"


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def _json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise DataParsingError(f"Duplicate attribute key detected: {key}")
        dict_out[key] = val
    return dict_out


class _RaiseDuplicatesIncludeLoader(yaml.SafeLoader):
    """
    Custom YAML Loader for 'yaml.load()'.
    - detects duplicate keys in the data
    - detects '!include' keys in the data
    """

    def __init__(self, stream: Any) -> None:
        self.add_constructor(_include_key, construct_include)
        super().__init__(stream)

    # custom constructor to detect duplicate keys in data
    # source: https://gist.github.com/pypt/94d747fe5180851196eb
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
                ) from exc

            # check for duplicate keys
            if key in mapping:
                raise DataParsingError(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


# custom constructor for to detect '!include' keys in the data
# source: https://gist.github.com/joshbode/569627ced3076931b02f
def construct_include(loader: _RaiseDuplicatesIncludeLoader, node: Any) -> Any:
    try:
        root = os.path.split(loader.stream.name)[0]  # type: ignore
    except AttributeError:
        root = os.path.curdir

    file_path = os.path.abspath(os.path.join(root, loader.construct_scalar(node)))
    extension = os.path.splitext(file_path)[1].lstrip(".")

    with open(file_path, "r") as file:
        if extension in ("yaml", "yml"):
            return yaml.load(file, Loader=_RaiseDuplicatesIncludeLoader)
        if extension in ("json",):
            return json.load(file)
        return "".join(file.readlines())


class DataFormat(Enum):
    YAML = auto()
    JSON = auto()

    def parse_to_dict(self, text: str) -> Any:
        if self is DataFormat.YAML:
            # _RaiseDuplicatesIncludeLoader extends yaml.SafeLoader, so this should be safe
            # https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
            return renamed(yaml.load(text, Loader=_RaiseDuplicatesIncludeLoader))  # type: ignore
        if self is DataFormat.JSON:
            return renamed(json.loads(text, object_pairs_hook=_json_raise_duplicates))
        raise NotImplementedError(f"Parsing of format '{self}' is not implemented")

    def dict_dump(self, data: Union[Dict[str, Any], Renamed], indent: Optional[int] = None) -> str:
        if isinstance(data, Renamed):
            data = data.original()

        if self is DataFormat.YAML:
            return yaml.safe_dump(data, indent=indent)  # type: ignore
        if self is DataFormat.JSON:
            return json.dumps(data, indent=indent)
        raise NotImplementedError(f"Exporting to '{self}' format is not implemented")


def parse_yaml(data: str) -> Any:
    return DataFormat.YAML.parse_to_dict(data)


def parse_json(data: str) -> Any:
    return DataFormat.JSON.parse_to_dict(data)


def try_to_parse(data: str) -> Any:
    """Attempt to parse the data as a JSON or YAML string."""

    try:
        return parse_json(data)
    except json.JSONDecodeError as je:
        try:
            return parse_yaml(data)
        except yaml.YAMLError as ye:
            # We do not raise-from here because there are two possible causes
            # and we may not know which one is the actual one.
            raise DataParsingError(  # pylint: disable=raise-missing-from
                f"failed to parse data, JSON: {je}, YAML: {ye}"
            ) from ye


def data_combine(data: Dict[Any, Any], additional_data: Dict[Any, Any], object_path: str = "") -> Dict[Any, Any]:
    """Combine dictionaries data"""
    for key in additional_data:
        if key in data:
            # if both are dictionaries we can try to combine them deeper
            if isinstance(data[key], (Dict, dict)) and isinstance(additional_data[key], (Dict, dict)):
                data[key] = data_combine(data[key], additional_data[key], f"{object_path}/{key}").copy()
                continue
            # otherwise we cannot combine them
            raise DataValidationError(f"duplicity key '{key}' with value in data", object_path)
        val = additional_data[key]
        data[key] = val.copy() if hasattr(val, "copy") else val
    return data
