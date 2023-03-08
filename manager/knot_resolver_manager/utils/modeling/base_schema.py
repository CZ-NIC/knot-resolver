import enum
import inspect
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union, cast

import yaml

from knot_resolver_manager.utils.functional import all_matches

from .base_value_type import BaseValueType
from .exceptions import AggregateDataValidationError, DataDescriptionError, DataValidationError
from .renaming import Renamed, renamed
from .types import (
    NoneType,
    get_generic_type_argument,
    get_generic_type_arguments,
    get_optional_inner_type,
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


T = TypeVar("T")


def is_obj_type(obj: Any, types: Union[type, Tuple[Any, ...], Tuple[type, ...]]) -> bool:
    # To check specific type we are using 'type()' instead of 'isinstance()'
    # because for example 'bool' is instance of 'int', 'isinstance(False, int)' returns True.
    # pylint: disable=unidiomatic-typecheck
    if isinstance(types, tuple):
        return type(obj) in types
    return type(obj) == types


class Serializable(ABC):
    """
    An interface for making classes serializable to a dictionary (and in turn into a JSON).
    """

    @abstractmethod
    def to_dict(self) -> Dict[Any, Any]:
        raise NotImplementedError(f"...for class {self.__class__.__name__}")

    @staticmethod
    def is_serializable(typ: Type[Any]) -> bool:
        return (
            typ in {str, bool, int, float}
            or is_none_type(typ)
            or is_literal(typ)
            or is_dict(typ)
            or is_list(typ)
            or (inspect.isclass(typ) and issubclass(typ, Serializable))
            or (inspect.isclass(typ) and issubclass(typ, BaseValueType))
            or (inspect.isclass(typ) and issubclass(typ, BaseSchema))
            or (is_optional(typ) and Serializable.is_serializable(get_optional_inner_type(typ)))
            or (is_union(typ) and all_matches(Serializable.is_serializable, get_generic_type_arguments(typ)))
        )

    @staticmethod
    def serialize(obj: Any) -> Any:
        if isinstance(obj, Serializable):
            return obj.to_dict()

        elif isinstance(obj, BaseValueType):
            return obj.serialize()

        elif isinstance(obj, list):
            res: List[Any] = [Serializable.serialize(i) for i in cast(List[Any], obj)]
            return res

        return obj


def _split_docstring(docstring: str) -> Tuple[str, Optional[str]]:
    """
    Splits docstring into description of the class and description of attributes
    """

    if "---" not in docstring:
        return ("\n".join([s.strip() for s in docstring.splitlines()]).strip(), None)

    doc, attrs_doc = docstring.split("---", maxsplit=1)
    return (
        "\n".join([s.strip() for s in doc.splitlines()]).strip(),
        attrs_doc,
    )


def _parse_attrs_docstrings(docstring: str) -> Optional[Dict[str, str]]:
    """
    Given a docstring of a BaseSchema, return a dict with descriptions of individual attributes.
    """

    _, attrs_doc = _split_docstring(docstring)
    if attrs_doc is None:
        return None

    # try to parse it as yaml:
    data = yaml.safe_load(attrs_doc)
    assert isinstance(data, dict), "Invalid format of attribute description"
    return cast(Dict[str, str], data)


def _get_properties_schema(typ: Type[Any]) -> Dict[Any, Any]:
    schema: Dict[Any, Any] = {}
    annot: Dict[str, Any] = typ.__dict__.get("__annotations__", {})
    docstring: str = typ.__dict__.get("__doc__", "") or ""
    attribute_documentation = _parse_attrs_docstrings(docstring)
    for field_name, python_type in annot.items():
        name = field_name.replace("_", "-")
        schema[name] = _describe_type(python_type)

        # description
        if attribute_documentation is not None:
            if field_name not in attribute_documentation:
                raise DataDescriptionError(f"The docstring does not describe field '{field_name}'", str(typ))
            schema[name]["description"] = attribute_documentation[field_name]
            del attribute_documentation[field_name]

        # default value
        if hasattr(typ, field_name):
            assert Serializable.is_serializable(
                python_type
            ), f"Type '{python_type}' does not appear to be JSON serializable"
            schema[name]["default"] = Serializable.serialize(getattr(typ, field_name))

    if attribute_documentation is not None and len(attribute_documentation) > 0:
        raise DataDescriptionError(
            f"The docstring describes attributes which are not present - {tuple(attribute_documentation.keys())}",
            str(typ),
        )

    return schema


def _describe_type(typ: Type[Any]) -> Dict[Any, Any]:
    # pylint: disable=too-many-branches

    if inspect.isclass(typ) and issubclass(typ, BaseSchema):
        return typ.json_schema(include_schema_definition=False)

    elif inspect.isclass(typ) and issubclass(typ, BaseValueType):
        return typ.json_schema()

    elif is_none_type(typ):
        return {"type": "null"}

    elif typ == int:
        return {"type": "integer"}

    elif typ == bool:
        return {"type": "boolean"}

    elif typ == str:
        return {"type": "string"}

    elif is_literal(typ):
        lit = get_generic_type_arguments(typ)
        return {"type": "string", "enum": lit}

    elif is_optional(typ):
        desc = _describe_type(get_optional_inner_type(typ))
        if "type" in desc:
            desc["type"] = [desc["type"], "null"]
            return desc
        else:
            return {"anyOf": [{"type": "null"}, desc]}

    elif is_union(typ):
        variants = get_generic_type_arguments(typ)
        return {"anyOf": [_describe_type(v) for v in variants]}

    elif is_list(typ):
        return {"type": "array", "items": _describe_type(get_generic_type_argument(typ))}

    elif is_dict(typ):
        key, val = get_generic_type_arguments(typ)

        if inspect.isclass(key) and issubclass(key, BaseValueType):
            assert (
                key.__str__ is not BaseValueType.__str__
            ), "To support derived 'BaseValueType', __str__ must be implemented."
        else:
            assert key == str, "We currently do not support any other keys then strings"

        return {"type": "object", "additionalProperties": _describe_type(val)}

    elif inspect.isclass(typ) and issubclass(typ, enum.Enum):  # same as our is_enum(typ), but inlined for type checker
        return {"type": "string", "enum": [str(v) for v in typ]}

    raise NotImplementedError(f"Trying to get JSON schema for type '{typ}', which is not implemented")


TSource = Union[None, "NoRenameBaseSchema", Dict[str, Any]]


def _create_untouchable(name: str) -> object:
    class _Untouchable:
        def __getattribute__(self, item_name: str) -> Any:
            raise RuntimeError(f"You are not supposed to access object '{name}'.")

        def __setattr__(self, item_name: str, value: Any) -> None:
            raise RuntimeError(f"You are not supposed to access object '{name}'.")

    return _Untouchable()


class Mapper:
    def _validated_tuple(self, tp: Type[Any], obj: Tuple[Any, ...], object_path: str) -> Tuple[Any, ...]:
        types = get_generic_type_arguments(tp)
        errs: List[DataValidationError] = []
        res: List[Any] = []
        for i, (t, val) in enumerate(zip(types, obj)):
            try:
                res.append(self.validated_object_type(t, val, object_path=f"{object_path}[{i}]"))
            except DataValidationError as e:
                errs.append(e)
        if len(errs) == 1:
            raise errs[0]
        elif len(errs) > 1:
            raise AggregateDataValidationError(object_path, child_exceptions=errs)
        return tuple(res)

    def _validated_dict(self, tp: Type[Any], obj: Dict[Any, Any], object_path: str) -> Dict[Any, Any]:
        key_type, val_type = get_generic_type_arguments(tp)
        try:
            errs: List[DataValidationError] = []
            res: Dict[Any, Any] = {}
            for key, val in obj.items():
                try:
                    nkey = self.validated_object_type(key_type, key, object_path=f"{object_path}[{key}]")
                    nval = self.validated_object_type(val_type, val, object_path=f"{object_path}[{key}]")
                    res[nkey] = nval
                except DataValidationError as e:
                    errs.append(e)
            if len(errs) == 1:
                raise errs[0]
            elif len(errs) > 1:
                raise AggregateDataValidationError(object_path, child_exceptions=errs)
            return res
        except AttributeError as e:
            raise DataValidationError(
                f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", object_path
            ) from e

    def _validated_list(self, tp: Type[Any], obj: List[Any], object_path: str) -> List[Any]:
        inner_type = get_generic_type_argument(tp)
        errs: List[DataValidationError] = []
        res: List[Any] = []
        for i, val in enumerate(obj):
            try:
                res.append(self.validated_object_type(inner_type, val, object_path=f"{object_path}[{i}]"))
            except DataValidationError as e:
                errs.append(e)
        if len(errs) == 1:
            raise errs[0]
        elif len(errs) > 1:
            raise AggregateDataValidationError(object_path, child_exceptions=errs)
        return res

    def validated_object_type(
        self,
        tp: Type[Any],
        obj: Any,
        default: Any = ...,
        use_default: bool = False,
        object_path: str = "/",
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
        elif is_none_type(tp):
            if obj is None:
                return None
            else:
                raise DataValidationError(f"expected None, found '{obj}'.", object_path)

        # Optional[T]  (could be technically handled by Union[*variants], but this way we have better error reporting)
        elif is_optional(tp):
            inner: Type[Any] = get_optional_inner_type(tp)
            if obj is None:
                return None
            else:
                return self.validated_object_type(inner, obj, object_path=object_path)

        # Union[*variants]
        elif is_union(tp):
            variants = get_generic_type_arguments(tp)
            errs: List[DataValidationError] = []
            for v in variants:
                try:
                    return self.validated_object_type(v, obj, object_path=object_path)
                except DataValidationError as e:
                    errs.append(e)

            raise DataValidationError(
                "could not parse any of the possible variants", object_path, child_exceptions=errs
            )

        # after this, there is no place for a None object
        elif obj is None:
            raise DataValidationError(f"unexpected value 'None' for type {tp}", object_path)

        # int
        elif tp == int:
            # we don't want to make an int out of anything else than other int
            # except for BaseValueType class instances
            if is_obj_type(obj, int) or isinstance(obj, BaseValueType):
                return int(obj)
            raise DataValidationError(f"expected int, found {type(obj)}", object_path)

        # str
        elif tp == str:
            # we are willing to cast any primitive value to string, but no compound values are allowed
            if is_obj_type(obj, (str, float, int)) or isinstance(obj, BaseValueType):
                return str(obj)
            elif is_obj_type(obj, bool):
                raise DataValidationError(
                    "Expected str, found bool. Be careful, that YAML parsers consider even"
                    ' "no" and "yes" as a bool. Search for the Norway Problem for more'
                    " details. And please use quotes explicitly.",
                    object_path,
                )
            else:
                raise DataValidationError(
                    f"expected str (or number that would be cast to string), but found type {type(obj)}", object_path
                )

        # bool
        elif tp == bool:
            if is_obj_type(obj, bool):
                return obj
            else:
                raise DataValidationError(f"expected bool, found {type(obj)}", object_path)

        # float
        elif tp == float:
            raise NotImplementedError(
                "Floating point values are not supported in the parser."
                " Please implement them and be careful with type coercions"
            )

        # Literal[T]
        elif is_literal(tp):
            expected = get_generic_type_arguments(tp)
            if obj in expected:
                return obj
            else:
                raise DataValidationError(f"'{obj}' does not match any of the expected values {expected}", object_path)

        # Dict[K,V]
        elif is_dict(tp):
            return self._validated_dict(tp, obj, object_path)

        # any Enums (probably used only internally in DataValidator)
        elif is_enum(tp):
            if isinstance(obj, tp):
                return obj
            else:
                raise DataValidationError(f"unexpected value '{obj}' for enum '{tp}'", object_path)

        # List[T]
        elif is_list(tp):
            if isinstance(obj, str):
                raise DataValidationError("expected list, got string", object_path)
            return self._validated_list(tp, obj, object_path)

        # Tuple[A,B,C,D,...]
        elif is_tuple(tp):
            return self._validated_tuple(tp, obj, object_path)

        # type of obj and cls type match
        elif is_obj_type(obj, tp):
            return obj

        # when the specified type is Any, just return the given value
        # (pylint does something weird on the following line and it happens only on python 3.10)
        elif tp == Any:  # pylint: disable=comparison-with-callable
            return obj

        # BaseValueType subclasses
        elif inspect.isclass(tp) and issubclass(tp, BaseValueType):
            return self.construct_value_type(tp, obj, object_path)

        # nested BaseSchema subclasses
        elif inspect.isclass(tp) and issubclass(tp, NoRenameBaseSchema):
            return self.construct_base_schema(tp, obj, object_path)

        # if the object matches, just pass it through
        elif inspect.isclass(tp) and isinstance(obj, tp):
            return obj

        # default error handler
        else:
            raise DataValidationError(
                f"Type {tp} cannot be parsed. This is a implementation error. "
                "Please fix your types in the class or improve the parser/validator.",
                object_path,
            )

    def construct_base_schema(self, tp: Type[Any], obj: Any, object_path: str) -> "NoRenameBaseSchema":
        if isinstance(obj, (dict, NoRenameBaseSchema)):
            return tp(obj, object_path=object_path)  # type: ignore
        raise DataValidationError(
            f"expected 'dict' or 'NoRenameBaseSchema' object, found '{type(obj)}'", object_path
        )

    def construct_value_type(self, tp: Type[Any], obj: Any, object_path: str) -> "BaseValueType":
        if isinstance(obj, tp):
            # if we already have a custom value type, just pass it through
            return obj
        else:
            # no validation performed, the implementation does it in the constuctor
            try:
                return tp(obj, object_path=object_path)
            except ValueError as e:
                if len(e.args) > 0 and isinstance(e.args[0], str):
                    msg = e.args[0]
                else:
                    msg = f"Failed to validate value against {tp} type"
                raise DataValidationError(msg, object_path) from e

    def load(self, clazz: Type[T], obj: Any, default: Any = ..., use_default: bool = False) -> T:
        return self.validated_object_type(clazz, obj, default, use_default)

    @classmethod
    def is_obj_type_valid(cls, obj: Any, tp: Type[Any]) -> bool:
        """
        Runtime type checking. Validate, that a given object is of a given type.
        """

        try:
            cls().validated_object_type(tp, obj)
            return True
        except (DataValidationError, ValueError):
            return False

    def _assign_default(self, obj: Any, name: str, python_type: Any, object_path: str) -> None:
        cls = obj.__class__
        default = getattr(cls, name, None)
        value = self.validated_object_type(python_type, default, object_path=f"{object_path}/{name}")
        setattr(obj, name, value)

    def _assign_field(self, obj: Any, name: str, python_type: Any, value: Any, object_path: str) -> None:
        value = self.validated_object_type(python_type, value, object_path=f"{object_path}/{name}")
        setattr(obj, name, value)

    def _assign_fields(self, obj: Any, source: Union[Dict[str, Any], "NoRenameBaseSchema", None], object_path: str) -> Set[str]:
        """
        Order of assignment:
          1. all direct assignments
          2. assignments with conversion method
        """
        cls = obj.__class__
        annot = cls.__dict__.get("__annotations__", {})
        errs: List[DataValidationError] = []

        used_keys: Set[str] = set()
        for name, python_type in annot.items():
            try:
                if is_internal_field_name(name):
                    continue

                # populate field
                if source is None:
                    self._assign_default(obj, name, python_type, object_path)

                # check for invalid configuration with both transformation function and default value
                elif hasattr(obj, f"_{name}") and hasattr(obj, name):
                    raise RuntimeError(
                        f"Field '{obj.__class__.__name__}.{name}' has default value and transformation function at"
                        " the same time. That is now allowed. Store the default in the transformation function."
                    )

                # there is a transformation function to create the value
                elif hasattr(obj, f"_{name}") and callable(getattr(obj, f"_{name}")):
                    val = self._get_converted_value(obj, name, source, object_path)
                    self._assign_field(obj, name, python_type, val, object_path)
                    used_keys.add(name)

                # source just contains the value
                elif name in source:
                    val = source[name]
                    self._assign_field(obj, name, python_type, val, object_path)
                    used_keys.add(name)

                # there is a default value, or the type is optional => store the default or null
                elif hasattr(obj, name) or is_optional(python_type):
                    self._assign_default(obj, name, python_type, object_path)

                # we expected a value but it was not there
                else:
                    errs.append(DataValidationError(f"missing attribute '{name}'.", object_path))
            except DataValidationError as e:
                errs.append(e)

        if len(errs) == 1:
            raise errs[0]
        elif len(errs) > 1:
            raise AggregateDataValidationError(object_path, errs)
        return used_keys

    def _get_converted_value(self, obj: Any, key: str, source: TSource, object_path: str) -> Any:
        """
        Get a value of a field by invoking appropriate transformation function.
        """
        try:
            func = getattr(obj.__class__, f"_{key}")
            argc = len(inspect.signature(func).parameters)
            if argc == 1:
                # it is a static method
                return func(source)
            elif argc == 2:
                # it is a instance method
                return func(_create_untouchable("obj"), source)
            else:
                raise RuntimeError("Transformation function has wrong number of arguments")
        except ValueError as e:
            if len(e.args) > 0 and isinstance(e.args[0], str):
                msg = e.args[0]
            else:
                msg = "Failed to validate value type"
            raise DataValidationError(msg, object_path) from e

    def object_constructor(self, obj: Any, source: TSource, object_path: str) -> None:
        # make sure that all raw data checks passed on the source object
        if source is None:
            source = {}

        if not isinstance(source, (NoRenameBaseSchema, dict)):
            raise DataValidationError(f"expected dict-like object, found '{type(source)}'", object_path)

        # save source (2 underscores should invoke Python's build-in mangling and we wont hopefully have collistions with data fields)
        obj.__source: Union[Dict[str, Any], NoRenameBaseSchema] = source  # type: ignore

        # construct lower level schema first if configured to do so
        if obj._LAYER is not None:
            source = obj._LAYER(source, object_path=object_path)  # pylint: disable=not-callable

        # assign fields
        used_keys = self._assign_fields(obj, source, object_path)

        # check for unused keys in the source object
        if source and not isinstance(source, NoRenameBaseSchema):
            unused = source.keys() - used_keys
            if len(unused) > 0:
                keys = ", ".join((f"'{u}'" for u in unused))
                raise DataValidationError(
                    f"unexpected extra key(s) {keys}",
                    object_path,
                )

        # validate the constructed value
        try:
            obj._validate()
        except ValueError as e:
            raise DataValidationError(e.args[0] if len(e.args) > 0 else "Validation error", object_path) from e


class NoRenameBaseSchema(Serializable):
    """
    Base class for modeling configuration schema. It somewhat resembles standard dataclasses with additional
    functionality:

    * type validation
    * data conversion

    To create an instance of this class, you have to provide source data in the form of dict-like object.
    Generally, raw dict or another `BaseSchema` instance. The provided data object is traversed, transformed
    and validated before assigned to the appropriate fields (attributes).

    Fields (attributes)
    ===================

    The fields (or attributes) of the class are defined the same way as in a dataclass by creating a class-level
    type-annotated fields. An example of that is:

    class A(BaseSchema):
        awesome_number: int

    If your `BaseSchema` instance has a field with type of a BaseSchema, its value is recursively created
    from the nested input data. This way, you can specify a complex tree of BaseSchema's and use the root
    BaseSchema to create instance of everything.

    Transformation
    ==============

    You can provide the BaseSchema class with a field and a function with the same name, but starting with
    underscore ('_'). For example, you could have field called `awesome_number` and function called
    `_awesome_number(self, source)`. The function takes one argument - the source data (optionally with self,
    but you are not supposed to touch that). It can read any data from the source object and return a value of
    an appropriate type, which will be assigned to the field `awesome_number`. If you want to report an error
    during validation, raise a `ValueError` exception.

    Using this, you can convert any input values into any type and field you want. To make the conversion easier
    to write, you could also specify a special class variable called `_LAYER` pointing to another
    BaseSchema class. This causes the source object to be first parsed as the specified additional layer of BaseSchema and after that
    used a source for this class. This therefore allows nesting of transformation functions.

    Validation
    ==========

    All assignments to fields during object construction are checked at runtime for proper types. This means,
    you are free to use an untrusted source object and turn it into a data structure, where you are sure what
    is what.

    You can also define a `_validate` method, which will be called once the whole data structure is built. You
    can validate the data in there and raise a `ValueError`, if they are invalid.

    Default values
    ==============

    If you create a field with a value, it will be used as a default value whenever the data in source object
    are not present. As a special case, default value for Optional type is None if not specified otherwise. You
    are not allowed to have a field with a default value and a transformation function at once.

    Example
    =======

    See tests/utils/test_modelling.py for example usage.
    """

    _LAYER: Optional[Type["NoRenameBaseSchema"]] = None
    _MAPPER: Mapper = Mapper()

    def __init__(self, source: TSource = None, object_path: str = ""):
        self._MAPPER.object_constructor(self, source, object_path)
        self.__source: Union[Dict[str, Any], NoRenameBaseSchema]

    def get_unparsed_data(self) -> Dict[str, Any]:
        if isinstance(self.__source, NoRenameBaseSchema):
            return self.__source.get_unparsed_data()
        elif isinstance(self.__source, Renamed):
            return self.__source.original()
        else:
            return self.__source

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise RuntimeError(f"Object '{self}' of type '{type(self)}' does not have field named '{key}'")
        return getattr(self, key)

    def __contains__(self, item: Any) -> bool:
        return hasattr(self, item)

    def _validate(self) -> None:
        """
        Validation procedure called after all field are assigned. Should throw a ValueError in case of failure.
        """

    def __eq__(self, o: object) -> bool:
        cls = self.__class__
        if not isinstance(o, cls):
            return False

        annot = cls.__dict__.get("__annotations__", {})
        for name in annot.keys():
            if getattr(self, name) != getattr(o, name):
                return False

        return True

    @classmethod
    def json_schema(cls: Type["NoRenameBaseSchema"], include_schema_definition: bool = True) -> Dict[Any, Any]:
        if cls._LAYER is not None:
            return cls._LAYER.json_schema(include_schema_definition=include_schema_definition)

        schema: Dict[Any, Any] = {}
        if include_schema_definition:
            schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        if cls.__doc__ is not None:
            schema["description"] = _split_docstring(cls.__doc__)[0]
        schema["type"] = "object"
        schema["properties"] = _get_properties_schema(cls)

        return schema

    def to_dict(self) -> Dict[Any, Any]:
        res: Dict[Any, Any] = {}
        cls = self.__class__
        annot = cls.__dict__.get("__annotations__", {})

        for name in annot:
            res[name] = Serializable.serialize(getattr(self, name))
        return res


class RenamedMapper(Mapper):
    def _validated_dict(self, tp: Type[Any], obj: Dict[Any, Any], object_path: str) -> Dict[Any, Any]:
        if isinstance(obj, Renamed):
            obj = obj.original()
        return super()._validated_dict(tp, obj, object_path)

    def construct_base_schema(self, tp: Type[Any], obj: Any, object_path: str) -> "NoRenameBaseSchema":
        if isinstance(obj, dict):
            obj = renamed(obj)
        return super().construct_base_schema(tp, obj, object_path)

    def object_constructor(self, obj: Any, source: TSource, object_path: str) -> None:
        if isinstance(source, dict):
            source = renamed(source)
        return super().object_constructor(obj, source, object_path)


# export as a standalone functions for backwards compatibility
load = RenamedMapper().load
is_obj_type_valid = RenamedMapper.is_obj_type_valid


class BaseSchema(NoRenameBaseSchema):
    """
    In Knot Resolver Manager, we need renamed keys most of the time, as we are using the modelling
    tools mostly for configuration schema. That's why the normal looking name BaseSchema does renaming
    and NoRenameBaseSchema is the opposite.
    """

    _MAPPER: Mapper = RenamedMapper()
