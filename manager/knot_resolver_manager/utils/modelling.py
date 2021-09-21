import inspect
from typing import Any, Dict, List, Optional, Set, Tuple, Type, Union

from knot_resolver_manager.exceptions import DataException, SchemaException
from knot_resolver_manager.utils.custom_types import CustomValueType
from knot_resolver_manager.utils.parsing import ParsedTree
from knot_resolver_manager.utils.types import (
    NoneType,
    get_generic_type_argument,
    get_generic_type_arguments,
    is_dict,
    is_enum,
    is_internal_field_name,
    is_list,
    is_literal,
    is_none_type,
    is_optional,
    is_tuple,
    is_union,
)


def is_obj_type(obj: Any, types: Union[type, Tuple[Any, ...], Tuple[type, ...]]) -> bool:
    # To check specific type we are using 'type()' instead of 'isinstance()'
    # because for example 'bool' is instance of 'int', 'isinstance(False, int)' returns True.
    # pylint: disable=unidiomatic-typecheck
    if isinstance(types, Tuple):
        return type(obj) in types
    return type(obj) == types


def _validated_object_type(
    cls: Type[Any], obj: Any, default: Any = ..., use_default: bool = False, object_path: str = "/"
) -> Any:
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
            raise SchemaException(f"Expected None, found '{obj}'.", object_path)

    # Union[*variants] (handles Optional[T] due to the way the typing system works)
    elif is_union(cls):
        variants = get_generic_type_arguments(cls)
        for v in variants:
            try:
                return _validated_object_type(v, obj, object_path=object_path)
            except SchemaException:
                pass
        raise SchemaException(f"Union {cls} could not be parsed - parsing of all variants failed.", object_path)

    # after this, there is no place for a None object
    elif obj is None:
        raise SchemaException(f"Unexpected None value for type {cls}", object_path)

    # int
    elif cls == int:
        # we don't want to make an int out of anything else than other int
        # except for CustomValueType class instances
        if is_obj_type(obj, int) or isinstance(obj, CustomValueType):
            return int(obj)
        raise SchemaException(f"Expected int, found {type(obj)}", object_path)

    # str
    elif cls == str:
        # we are willing to cast any primitive value to string, but no compound values are allowed
        if is_obj_type(obj, (str, float, int)) or isinstance(obj, CustomValueType):
            return str(obj)
        elif is_obj_type(obj, bool):
            raise SchemaException(
                "Expected str, found bool. Be careful, that YAML parsers consider even"
                ' "no" and "yes" as a bool. Search for the Norway Problem for more'
                " details. And please use quotes explicitly.",
                object_path,
            )
        else:
            raise SchemaException(
                f"Expected str (or number that would be cast to string), but found type {type(obj)}", object_path
            )

    # bool
    elif cls == bool:
        if is_obj_type(obj, bool):
            return obj
        else:
            raise SchemaException(f"Expected bool, found {type(obj)}", object_path)

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
            raise SchemaException(f"Literal {cls} is not matched with the value {obj}", object_path)

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        try:
            return {
                _validated_object_type(key_type, key, object_path=f"{object_path} @ key {key}"): _validated_object_type(
                    val_type, val, object_path=f"{object_path} @ value for key {key}"
                )
                for key, val in obj.items()
            }
        except AttributeError as e:
            raise SchemaException(
                f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", object_path
            ) from e

    # any Enums (probably used only internally in DataValidator)
    elif is_enum(cls):
        if isinstance(obj, cls):
            return obj
        else:
            raise SchemaException(f"Unexpected value '{obj}' for enum '{cls}'", object_path)

    # List[T]
    elif is_list(cls):
        inner_type = get_generic_type_argument(cls)
        return [_validated_object_type(inner_type, val, object_path=f"{object_path}[]") for val in obj]

    # Tuple[A,B,C,D,...]
    elif is_tuple(cls):
        types = get_generic_type_arguments(cls)
        return tuple(_validated_object_type(typ, val, object_path=object_path) for typ, val in zip(types, obj))

    # CustomValueType subclasses
    elif inspect.isclass(cls) and issubclass(cls, CustomValueType):
        if isinstance(obj, cls):
            # if we already have a custom value type, just pass it through
            return obj
        else:
            # no validation performed, the implementation does it in the constuctor
            return cls(obj, object_path=object_path)

    # nested SchemaNode subclasses
    elif inspect.isclass(cls) and issubclass(cls, SchemaNode):
        # we should return DataParser, we expect to be given a dict,
        # because we can construct a DataParser from it
        if isinstance(obj, (dict, SchemaNode)):
            return cls(obj, object_path=object_path)  # type: ignore
        raise SchemaException(f"Expected 'dict' or 'SchemaNode' object, found '{type(obj)}'", object_path)

    # if the object matches, just pass it through
    elif inspect.isclass(cls) and isinstance(obj, cls):
        return obj

    # default error handler
    else:
        raise SchemaException(
            f"Type {cls} cannot be parsed. This is a implementation error. "
            "Please fix your types in the class or improve the parser/validator.",
            object_path,
        )


TSource = Union[NoneType, ParsedTree, "SchemaNode", Dict[str, Any]]


class SchemaNode:
    _PREVIOUS_SCHEMA: Optional[Type["SchemaNode"]] = None

    def _assign_default_fields(self) -> Set[str]:
        cls = self.__class__
        annot = cls.__dict__.get("__annotations__", {})

        used_keys: Set[str] = set()
        for name in annot:
            val = getattr(cls, name, ...)
            if val is not ...:
                setattr(self, name, val)
                used_keys.add(name)

        return used_keys

    def _assign_field(self, name: str, python_type: Any, value: Any, object_path: str):
        cls = self.__class__
        use_default = hasattr(cls, name)
        default = getattr(cls, name, ...)
        value = _validated_object_type(python_type, value, default, use_default, object_path=f"{object_path}/{name}")
        setattr(self, name, value)

    def _assign_fields(self, source: Union[ParsedTree, "SchemaNode", NoneType], object_path: str) -> Set[str]:
        """
        Order of assignment:
          1. all direct assignments
          2. assignments with conversion method
        """
        cls = self.__class__
        annot = cls.__dict__.get("__annotations__", {})

        used_keys: Set[str] = set()
        deffered: List[Tuple[str, Any]] = []
        for name, python_type in annot.items():
            if is_internal_field_name(name):
                continue

            # populate field
            if not source:
                self._assign_field(name, python_type, None, object_path)

            # we have a way how to create the value
            elif hasattr(self, f"_{name}"):
                deffered.append((name, python_type))

            # source just contains the value
            elif name in source:
                val = source[name]
                used_keys.add(name)
                self._assign_field(name, python_type, val, object_path)

            # there is a default value and in the source, the value is missing
            elif getattr(self, name, ...) is not ...:
                self._assign_field(name, python_type, None, object_path)

            # the value is optional and there is nothing
            elif is_optional(python_type):
                self._assign_field(name, python_type, None, object_path)

            # we expected a value but it was not there
            else:
                raise SchemaException(f"Missing attribute '{name}'.", object_path)

        for name, python_type in deffered:
            val = self._get_converted_value(name, source, object_path)
            used_keys.add(name)  # the field might not exist, but that won't break anything
            self._assign_field(name, python_type, val, object_path)

        return used_keys

    def __init__(self, source: TSource = None, object_path: str = "/"):
        # construct lower level schema node first if configured to do so
        if self._PREVIOUS_SCHEMA is not None:
            source = self._PREVIOUS_SCHEMA(source, object_path=object_path)  # pylint: disable=not-callable

        # make sure that all raw data checks passed on the source object
        if isinstance(source, dict):
            source = ParsedTree(source)

        # assign fields
        used_keys = self._assign_default_fields()
        used_keys.update(self._assign_fields(source, object_path))

        # check for unused keys in the source object
        if source and not isinstance(source, SchemaNode):
            unused = source.keys() - used_keys
            if len(unused) > 0:
                raise SchemaException(
                    f"Keys {unused} in your configuration object are not part of the configuration schema."
                    " Are you using '-' instead of '_'?",
                    object_path,
                )

        # validate the constructed value
        self._validate()

    def _get_converted_value(self, key: str, source: TSource, object_path: str) -> Any:
        try:
            return getattr(self, f"_{key}")(source)
        except (ValueError, DataException) as e:
            if len(e.args) > 0 and isinstance(e.args[0], str):
                msg = e.args[0]
            else:
                msg = "Failed to validate value type"
            raise SchemaException(msg, object_path) from e

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise RuntimeError(f"Object '{self}' of type '{type(self)}' does not have field named '{key}'")
        return getattr(self, key)

    def __contains__(self, item: Any) -> bool:
        return hasattr(self, item)

    def _validate(self) -> None:
        pass
