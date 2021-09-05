import copy
import inspect
import json
import re
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from knot_resolver_manager.utils.custom_types import CustomValueType
from knot_resolver_manager.utils.exceptions import DataParsingException
from knot_resolver_manager.utils.types import (
    get_attr_type,
    get_generic_type_argument,
    get_generic_type_arguments,
    is_dict,
    is_list,
    is_literal,
    is_none_type,
    is_tuple,
    is_union,
)


def is_internal_field(field_name: str) -> bool:
    return field_name.startswith("_")


def is_obj_type(obj: Any, types: Union[type, Tuple[Any, ...], Tuple[type, ...]]) -> bool:
    # To check specific type we are using 'type()' instead of 'isinstance()'
    # because for example 'bool' is instance of 'int', 'isinstance(False, int)' returns True.
    # pylint: disable=unidiomatic-typecheck
    if isinstance(types, Tuple):
        return type(obj) in types
    return type(obj) == types


def _to_primitive(obj: Any) -> Any:
    """
    Convert our custom values into primitive variants for dumping.
    """

    # CustomValueType instances
    if isinstance(obj, CustomValueType):
        return str(obj)

    # nested DataParser class instances
    elif isinstance(obj, DataParser):
        return obj.to_dict()

    # otherwise just return, what we were given
    else:
        return obj


def _validated_object_type(cls: Type[Any], obj: Any, default: Any = ..., use_default: bool = False) -> Any:
    """
    Given an expected type `cls` and a value object `obj`, validate the type of `obj` and return it
    """

    # Disabling these checks, because I think it's much more readable as a single function
    # and it's not that large at this point. If it got larger, then we should definitely split it
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements

    # default values
    if obj is None and use_default:
        return default

    # NoneType
    elif is_none_type(cls):
        if obj is None:
            return None
        else:
            raise DataParsingException(f"Expected None, found '{obj}'.")

    # Union[*variants] (handles Optional[T] due to the way the typing system works)
    elif is_union(cls):
        variants = get_generic_type_arguments(cls)
        for v in variants:
            try:
                return _validated_object_type(v, obj)
            except DataParsingException:
                pass
        raise DataParsingException(f"Union {cls} could not be parsed - parsing of all variants failed.")

    # after this, there is no place for a None object
    elif obj is None:
        raise DataParsingException(f"Unexpected None value for type {cls}")

    # int
    elif cls == int:
        # we don't want to make an int out of anything else than other int
        # except for CustomValueType class instances
        if is_obj_type(obj, int) or isinstance(obj, CustomValueType):
            return int(obj)
        raise DataParsingException(f"Expected int, found {type(obj)}")

    # str
    elif cls == str:
        # we are willing to cast any primitive value to string, but no compound values are allowed
        if is_obj_type(obj, (str, float, int)) or isinstance(obj, CustomValueType):
            return str(obj)
        elif is_obj_type(obj, bool):
            raise DataParsingException(
                "Expected str, found bool. Be careful, that YAML parsers consider even"
                ' "no" and "yes" as a bool. Search for the Norway Problem for more'
                " details. And please use quotes explicitly."
            )
        else:
            raise DataParsingException(
                f"Expected str (or number that would be cast to string), but found type {type(obj)}"
            )

    # bool
    elif cls == bool:
        if is_obj_type(obj, bool):
            return obj
        else:
            raise DataParsingException(f"Expected bool, found {type(obj)}")

    # float
    elif cls == float:
        raise NotImplementedError(
            "Floating point values are not supported in the parser."
            " Please implement them and be careful with type coercions"
        )

    # Literal[T]
    elif is_literal(cls):
        expected = get_generic_type_argument(cls)
        if obj == expected:
            return obj
        else:
            raise DataParsingException(f"Literal {cls} is not matched with the value {obj}")

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        try:
            return {
                _validated_object_type(key_type, key): _validated_object_type(val_type, val) for key, val in obj.items()
            }
        except AttributeError as e:
            raise DataParsingException(
                f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", e
            )

    # List[T]
    elif is_list(cls):
        inner_type = get_generic_type_argument(cls)
        return [_validated_object_type(inner_type, val) for val in obj]

    # Tuple[A,B,C,D,...]
    elif is_tuple(cls):
        types = get_generic_type_arguments(cls)
        return tuple(_validated_object_type(typ, val) for typ, val in zip(types, obj))

    # CustomValueType subclasses
    elif inspect.isclass(cls) and issubclass(cls, CustomValueType):
        # no validation performed, the implementation does it in the constuctor
        return cls(obj)

    # nested DataParser subclasses
    elif inspect.isclass(cls) and issubclass(cls, DataParser):
        # we should return DataParser, we expect to be given a dict,
        # because we can construct a DataParser from it
        if isinstance(obj, dict):
            return cls(obj)  # type: ignore
        raise DataParsingException(f"Expected '{dict}' object, found '{type(obj)}'")

    # nested DataValidator subclasses
    elif inspect.isclass(cls) and issubclass(cls, DataValidator):
        # we should return DataValidator, we expect to be given a DataParser,
        # because we can construct a DataValidator from it
        if isinstance(obj, DataParser):
            return cls(obj)
        raise DataParsingException(f"Expected instance of '{DataParser}' class, found '{type(obj)}'")

    # default error handler
    else:
        raise DataParsingException(
            f"Type {cls} cannot be parsed. This is a implementation error. "
            "Please fix your types in the class or improve the parser/validator."
        )


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise DataParsingException(f"Duplicate attribute key detected: {key}")
        dict_out[key] = val
    return dict_out


# custom loader for 'yaml.load()' to detect duplicate keys in data
# source: https://gist.github.com/pypt/94d747fe5180851196eb
class RaiseDuplicatesLoader(yaml.SafeLoader):
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
                raise DataParsingException(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


class Format(Enum):
    YAML = auto()
    JSON = auto()

    def parse_to_dict(self, text: str) -> Any:
        if self is Format.YAML:
            # RaiseDuplicatesLoader extends yaml.SafeLoader, so this should be safe
            # https://python.land/data-processing/python-yaml#PyYAML_safe_load_vs_load
            return yaml.load(text, Loader=RaiseDuplicatesLoader)  # type: ignore
        elif self is Format.JSON:
            return json.loads(text, object_pairs_hook=json_raise_duplicates)
        else:
            raise NotImplementedError(f"Parsing of format '{self}' is not implemented")

    def dict_dump(self, data: Dict[str, Any]) -> str:
        if self is Format.YAML:
            return yaml.safe_dump(data)  # type: ignore
        elif self is Format.JSON:
            return json.dumps(data)
        else:
            raise NotImplementedError(f"Exporting to '{self}' format is not implemented")

    @staticmethod
    def from_mime_type(mime_type: str) -> "Format":
        formats = {
            "application/json": Format.JSON,
            "application/octet-stream": Format.JSON,  # default in aiohttp
            "text/vnd.yaml": Format.YAML,
        }
        if mime_type not in formats:
            raise DataParsingException("Unsupported MIME type")
        return formats[mime_type]


_T = TypeVar("_T", bound="DataParser")


_SUBTREE_MUTATION_PATH_PATTERN = re.compile(r"^(/[^/]+)*/?$")


class DataParser:
    def __init__(self, obj: Optional[Dict[Any, Any]] = None):
        cls = self.__class__
        annot = cls.__dict__.get("__annotations__", {})

        used_keys: List[str] = []
        for name, python_type in annot.items():
            if is_internal_field(name):
                continue

            val = None
            dash_name = name.replace("_", "-")
            if obj and dash_name in obj:
                val = obj[dash_name]
                used_keys.append(dash_name)

            use_default = hasattr(cls, name)
            default = getattr(cls, name, ...)
            value = _validated_object_type(python_type, val, default, use_default)
            setattr(self, name, value)

        # check for unused keys
        if obj:
            for key in obj:
                if key not in used_keys:
                    raise DataParsingException(f"Unknown attribute key '{key}'.")

    @classmethod
    def parse_from(cls: Type[_T], fmt: Format, text: str):
        data_dict = fmt.parse_to_dict(text)
        config: _T = cls(data_dict)
        return config

    @classmethod
    def from_yaml(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.YAML, text)

    @classmethod
    def from_json(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.JSON, text)

    def to_dict(self) -> Dict[str, Any]:
        cls = self.__class__
        anot = cls.__dict__.get("__annotations__", {})
        dict_obj: Dict[str, Any] = {}
        for name in anot:
            if is_internal_field(name):
                continue

            value = getattr(self, name)
            dash_name = str(name).replace("_", "-")
            dict_obj[dash_name] = _to_primitive(value)
        return dict_obj

    def dump(self, fmt: Format) -> str:
        dict_data = self.to_dict()
        return fmt.dict_dump(dict_data)

    def dump_to_yaml(self) -> str:
        return self.dump(Format.YAML)

    def dump_to_json(self) -> str:
        return self.dump(Format.JSON)

    def copy_with_changed_subtree(self: _T, fmt: Format, path: str, text: str) -> _T:
        cls = self.__class__

        # prepare and validate the path object
        path = path[:-1] if path.endswith("/") else path
        if re.match(_SUBTREE_MUTATION_PATH_PATTERN, path) is None:
            raise DataParsingException("Provided object path for mutation is invalid.")
        path = path[1:] if path.startswith("/") else path

        # now, the path variable should contain '/' separated field names

        # check if we should mutate whole object
        if path == "":
            return cls.parse_from(fmt, text)

        # find the subtree we will replace in a copy of the original object
        to_mutate = copy.deepcopy(self)
        obj = to_mutate
        parent = None

        for dash_segment in path.split("/"):
            segment = dash_segment.replace("-", "_")

            if segment == "":
                raise DataParsingException(f"Unexpectedly empty segment in path '{path}'")
            elif is_internal_field(segment):
                raise DataParsingException("No, changing internal fields (starting with _) is not allowed. Nice try.")
            elif hasattr(obj, segment):
                parent = obj
                obj = getattr(parent, segment)
            else:
                raise DataParsingException(
                    f"Path segment '{dash_segment}' does not match any field on the provided parent object"
                )
        assert parent is not None

        # assign the subtree
        last_name = path.split("/")[-1].replace("-", "_")
        data = fmt.parse_to_dict(text)
        tp = get_attr_type(parent, last_name)
        parsed_value = _validated_object_type(tp, data)
        setattr(parent, last_name, parsed_value)

        return to_mutate


class DataValidator:
    def __init__(self, obj: DataParser):
        cls = self.__class__
        anot = cls.__dict__.get("__annotations__", {})

        for attr_name, attr_type in anot.items():
            if is_internal_field(attr_name):
                continue

            # use transformation function if available
            if hasattr(self, f"_{attr_name}"):
                value = getattr(self, f"_{attr_name}")(obj)
            elif hasattr(obj, attr_name):
                value = getattr(obj, attr_name)
            else:
                raise DataParsingException(f"DataParser object {obj} is missing '{attr_name}' attribute.")

            setattr(self, attr_name, _validated_object_type(attr_type, value))

        self._validate()

    def validate(self) -> None:
        for field_name in dir(self):
            if is_internal_field(field_name):
                continue

            field = getattr(self, field_name)
            if isinstance(field, DataValidator):
                field.validate()
        self._validate()

    def _validate(self) -> None:
        raise NotImplementedError(f"Validation function is not implemented in class {type(self).__name__}")
