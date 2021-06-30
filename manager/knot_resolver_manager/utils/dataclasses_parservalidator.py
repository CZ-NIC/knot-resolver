import copy
import json
import re
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from knot_resolver_manager.exceptions import SchemaValidationException
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

from ..compat.dataclasses import is_dataclass


def _from_dictlike_obj(cls: Any, obj: Any, default: Any, use_default: bool) -> Any:
    # Disabling these checks, because I think it's much more readable as a single function
    # and it's not that large at this point. If it got larger, then we should definitely split
    # it
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements

    # default values
    if obj is None and use_default:
        return default

    # NoneType
    elif is_none_type(cls):
        if obj is None:
            return None
        else:
            raise SchemaValidationException(f"Expected None, found {obj}")

    # Union[*variants] (handles Optional[T] due to the way the typing system works)
    elif is_union(cls):
        variants = get_generic_type_arguments(cls)
        for v in variants:
            try:
                return _from_dictlike_obj(v, obj, ..., False)
            except SchemaValidationException:
                pass
        raise SchemaValidationException(f"Union {cls} could not be parsed - parsing of all variants failed")

    # after this, there is no place for a None object
    elif obj is None:
        raise SchemaValidationException(f"Unexpected None value for type {cls}")

    # int
    elif cls == int:
        # we don't want to make an int out of anything else than other int
        if isinstance(obj, int):
            return int(obj)
        else:
            raise SchemaValidationException(f"Expected int, found {type(obj)}")

    # str
    elif cls == str:
        # we are willing to cast any primitive value to string, but no compound values are allowed
        if isinstance(obj, (str, float, int)):
            return str(obj)
        elif isinstance(obj, bool):
            raise SchemaValidationException(
                "Expected str, found bool. Be careful, that YAML parsers consider even"
                ' "no" and "yes" as a bool. Search for the Norway Problem for more'
                " details. And please use quotes explicitly."
            )
        else:
            raise SchemaValidationException(
                f"Expected str (or number that would be cast to string), but found type {type(obj)}"
            )

    # bool
    elif cls == bool:
        if isinstance(obj, bool):
            return obj
        else:
            raise SchemaValidationException(f"Expected bool, found {type(obj)}")

    # float
    elif cls == float:
        raise NotImplementedError(
            "Floating point values are not supported in the parser validator."
            " Please implement them and be careful with type coercions"
        )

    # Literal[T]
    elif is_literal(cls):
        expected = get_generic_type_argument(cls)
        if obj == expected:
            return obj
        else:
            raise SchemaValidationException(f"Literal {cls} is not matched with the value {obj}")

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        try:
            return {
                _from_dictlike_obj(key_type, key, ..., False): _from_dictlike_obj(val_type, val, ..., False)
                for key, val in obj.items()
            }
        except AttributeError as e:
            raise SchemaValidationException(
                f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", e
            )

    # List[T]
    elif is_list(cls):
        inner_type = get_generic_type_argument(cls)
        return [_from_dictlike_obj(inner_type, val, ..., False) for val in obj]

    # Tuple[A,B,C,D,...]
    elif is_tuple(cls):
        types = get_generic_type_arguments(cls)
        return tuple(_from_dictlike_obj(typ, val, ..., False) for typ, val in zip(types, obj))

    # nested dataclass
    elif is_dataclass(cls):
        anot = cls.__dict__.get("__annotations__", {})
        kwargs = {}
        for name, python_type in anot.items():
            # skip internal fields
            if name.startswith("_"):
                continue

            value = obj[name] if name in obj else None
            use_default = hasattr(cls, name)
            default = getattr(cls, name, ...)
            kwargs[name] = _from_dictlike_obj(python_type, value, default, use_default)
        return cls(**kwargs)

    # default error handler
    else:
        raise SchemaValidationException(
            f"Type {cls} cannot be parsed. This is a implementation error. "
            "Please fix your types in the dataclass or improve the parser/validator."
        )


# custom hook for 'json.loads()' to detect duplicate keys in data
# source: https://stackoverflow.com/q/14902299/12858520
def json_raise_duplicates(pairs: List[Tuple[Any, Any]]) -> Optional[Any]:
    dict_out: Dict[Any, Any] = {}
    for key, val in pairs:
        if key in dict_out:
            raise SchemaValidationException(f"duplicate key detected: {key}")
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
                raise SchemaValidationException(f"duplicate key detected: {key_node.start_mark}")
            value = self.construct_object(value_node, deep=deep)  # type: ignore
            mapping[key] = value
        return mapping


_T = TypeVar("_T", bound="DataclassParserValidatorMixin")


_SUBTREE_MUTATION_PATH_PATTERN = re.compile(r"^(/[^/]+)*/?$")


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

    @staticmethod
    def from_mime_type(mime_type: str) -> "Format":
        formats = {
            "application/json": Format.JSON,
            "application/octet-stream": Format.JSON,  # default in aiohttp
            "text/vnd.yaml": Format.YAML,
        }
        if mime_type not in formats:
            raise SchemaValidationException("Unsupported MIME type")
        return formats[mime_type]


class DataclassParserValidatorMixin:
    def __init__(self, *args: Any, **kwargs: Any):
        """
        This constructor is useless except for typechecking. It makes sure that the dataclasses can be created with
        any arguments whatsoever.
        """

    def validate(self) -> None:
        for field_name in dir(self):
            # skip internal fields
            if field_name.startswith("_"):
                continue

            field = getattr(self, field_name)
            if is_dataclass(field):
                if not isinstance(field, DataclassParserValidatorMixin):
                    raise SchemaValidationException(
                        f"Nested dataclass in the field {field_name} does not include the ParserValidatorMixin"
                    )
                field.validate()

        self._validate()

    def _validate(self) -> None:
        raise NotImplementedError(f"Validation function is not implemented in class {type(self).__name__}")

    @classmethod
    def parse_from(cls: Type[_T], fmt: Format, text: str):
        data = fmt.parse_to_dict(text)
        config: _T = _from_dictlike_obj(cls, data, ..., False)
        config.validate()
        return config

    @classmethod
    def from_yaml(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.YAML, text)

    @classmethod
    def from_json(cls: Type[_T], text: str) -> _T:
        return cls.parse_from(Format.JSON, text)

    def copy_with_changed_subtree(self: _T, fmt: Format, path: str, text: str) -> _T:
        cls = self.__class__

        # prepare and validate the path object
        path = path[:-1] if path.endswith("/") else path
        if re.match(_SUBTREE_MUTATION_PATH_PATTERN, path) is None:
            raise SchemaValidationException("Provided object path for mutation is invalid.")
        path = path[1:] if path.startswith("/") else path

        # now, the path variable should contain '/' separated field names

        # check if we should mutate whole object
        if path == "":
            return cls.parse_from(fmt, text)

        # find the subtree we will replace in a copy of the original object
        to_mutate = copy.deepcopy(self)
        obj = to_mutate
        parent = None
        for segment in path.split("/"):
            if segment == "":
                raise SchemaValidationException(f"Unexpectedly empty segment in path '{path}'")
            elif segment.startswith("_"):
                raise SchemaValidationException(
                    "No, changing internal fields (starting with _) is not allowed. Nice try."
                )
            elif hasattr(obj, segment):
                parent = obj
                obj = getattr(parent, segment)
            else:
                raise SchemaValidationException(
                    f"Path segment '{segment}' does not match any field on the provided parent object"
                )
        assert parent is not None

        # assign the subtree
        last_name = path.split("/")[-1]
        data = fmt.parse_to_dict(text)
        tp = get_attr_type(parent, last_name)
        parsed_value = _from_dictlike_obj(tp, data, ..., False)
        setattr(parent, last_name, parsed_value)

        to_mutate.validate()

        return to_mutate
