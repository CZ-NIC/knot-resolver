from __future__ import annotations

import json
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Hashable, List, Union

import yaml
from yaml.constructor import ConstructorError

from knot_resolver.utils.modeling.errors import DataParsingError, DataReadingError, DataTypeError

if TYPE_CHECKING:
    from yaml.nodes import MappingNode

_YAML_INCLUDE_KEY = "include"
_YAML_INCLUDE_TAG = "!include"


class ParsedDataWrapper:
    """A wrapper for included files and their data.

    Attributes:
        data (ParsedData): Data that has been read and parsed from the file.
        file (str | Path): The path to the file containing the data.

    """

    def __init__(self, data: ParsedData, file: str | Path):
        self.data = data
        self.file = Path(file)


ParsedData = Union[Dict[str, "ParsedData"], List["ParsedData"], ParsedDataWrapper, str, int, float, bool, None]


def _yaml_include_constructor(self: _YAMLRaiseDuplicatesIncludeLoader, node: MappingNode) -> ParsedDataWrapper:
    """Construct include wrapper for detected '!include' keys.

    The code for this constructor was highly inspired by:
    https://gist.github.com/joshbode/569627ced3076931b02f
    """
    file_path = Path(self.construct_scalar(node))
    if not file_path.is_absolute() and self.stream_path:
        file_path = self.stream_path.parent / file_path
    return try_to_parse_file(file_path)


class _YAMLRaiseDuplicatesIncludeLoader(yaml.SafeLoader):
    """Custom YAML loader used in 'yaml.loads()'.

    The loader detects duplicate keys in the parsed data.
    It also detects '!include' keys and loads data from included files.

    The code for this loader was highly inspired by: https://gist.github.com/pypt/94d747fe5180851196eb
    The loader extends yaml.SafeLoader, so it should be safe, even though the linter reports unsafe-yaml-load (S506).
    More about safe loader: https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
    """

    def __init__(self, stream: str, stream_path: str | Path | None = None) -> None:
        self.stream_path = Path(stream_path) if stream_path else None
        self.add_constructor(_YAML_INCLUDE_TAG, _yaml_include_constructor)
        super().__init__(stream)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        mapping: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            # we need to check, that the key object can be used in a hash table
            try:
                _ = hash(key)
            except TypeError as exc:
                msg = f"while constructing a mapping {node.start_mark}"
                f"found unacceptable key ({exc}) {key_node.start_mark}"
                raise ConstructorError(msg) from exc

            # check for duplicate keys
            if key in mapping:
                msg = f"duplicate key detected: {key_node.start_mark}"
                raise DataParsingError(msg)
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


def _json_raise_duplicates(pairs: list[tuple[str, ParsedData]]) -> dict[str, ParsedData]:
    """JSON hook used in 'json.loads()' that detects duplicate keys in the parsed data.

    The code for this hook was highly inspired by: https://stackoverflow.com/q/14902299/12858520
    """
    mapping: dict[str, ParsedData] = {}
    for key, value in pairs:
        if key in mapping:
            msg = f"duplicate key detected: {key}"
            raise DataParsingError(msg)
        mapping[key] = value
    return mapping


def _include_key_root(parsed_data: ParsedDataWrapper) -> ParsedDataWrapper:
    data = parsed_data.data
    base_path = parsed_data.file.parent

    if isinstance(data, ParsedDataWrapper):
        parsed_data.data = _include_key_root(data)

    elif isinstance(data, dict) and _YAML_INCLUDE_KEY in data:
        files = data[_YAML_INCLUDE_KEY]
        parsed_files: list[ParsedData] = []

        if isinstance(files, str):
            file_path = Path(files)
            if not file_path.is_absolute():
                file_path = base_path / file_path
            parsed_files.append(try_to_parse_file(file_path))

        elif isinstance(files, list):
            for file in files:
                if isinstance(file, str):
                    file_path = Path(file)
                    if not file_path.is_absolute():
                        file_path = base_path / file_path
                    parsed_files.append(try_to_parse_file(file_path))
                else:
                    msg = ""
                    pointer = f"{parsed_data.file}:/{_YAML_INCLUDE_KEY}"
                    raise DataTypeError(msg, pointer)

        else:
            msg = f"expected string or list, got {type(files)}"
            pointer = f"{parsed_data.file}:/{_YAML_INCLUDE_KEY}"
            raise DataTypeError(msg, pointer)

        data[_YAML_INCLUDE_KEY] = parsed_files

    return parsed_data


class DataFormat(Enum):
    YAML = auto()
    JSON = auto()

    def load_file(self, file: str | Path) -> ParsedData:
        """Read and parse data from file in data format and return the data in dictionary."""
        file_path = Path(file)
        text = file_path.read_text()
        if self is DataFormat.YAML:
            loader = _YAMLRaiseDuplicatesIncludeLoader(text, file)
            try:
                return loader.get_single_data()
            finally:
                loader.dispose()
        return self.load_str(text)

    def load_str(self, text: str) -> ParsedData:
        """Load data from string in data format and return the data in dictionary."""
        if self is DataFormat.YAML:
            return yaml.load(text, Loader=_YAMLRaiseDuplicatesIncludeLoader)  # noqa: S506
        if self is DataFormat.JSON:
            return json.loads(text, object_pairs_hook=_json_raise_duplicates)
        msg = f"parsing data from '{self}' format is not implemented"
        raise NotImplementedError(msg)

    # def dump_str(self, data: ParsedData, indent: int | None = None) -> str:
    #     """Dump the parsed(dict) data into a string in the required format."""
    #     if self is DataFormat.YAML:
    #         return yaml.safe_dump(data, indent=indent)
    #     if self is DataFormat.JSON:
    #         return json.dumps(data, indent=indent)
    #     msg = f"exporting data to '{self}' format is not implemented"
    #     raise NotImplementedError(msg)


def parse_json_str(data: str) -> ParsedData:
    """Parse the JSON string, and return its parsed(dict) data."""
    return DataFormat.JSON.load_str(data)


def parse_json_file(file: str | Path) -> ParsedDataWrapper:
    """Read the JSON file, parse its data string, and return its parsed(dict) data."""
    data = DataFormat.JSON.load_file(file)
    return ParsedDataWrapper(data, file)


def parse_yaml_file(file: str | Path) -> ParsedDataWrapper:
    """Read the YAML file, parse its data string, and return its parsed(dict) data."""
    data = DataFormat.YAML.load_file(file)
    return _include_key_root(ParsedDataWrapper(data, file))


def try_to_parse_file(file: str | Path) -> ParsedDataWrapper:
    """Attempt to read the file and parse its data string as JSON or YAML, then return its parsed(dict) data."""
    try:
        return parse_json_file(file)
    except OSError as e:
        raise DataReadingError(str(e), str(file)) from e
    except json.JSONDecodeError:
        try:
            return parse_yaml_file(file)
        except yaml.YAMLError as e:
            # YAML parsing error should be sufficient because the JSON can be parsed by the YAML parser.
            # We should receive a helpful error message for JSON as well.
            raise DataParsingError(str(e), str(file)) from e
