from typing import Any, Dict, List, Tuple, Type, TypeVar, Union

import strictyaml
from strictyaml import YAML, EmptyDict, FixedSeq, Float, Int, Map, MapPattern, Seq, Str, load


class _DummyType:
    pass


NoneType = type(None)


_TYPE_MAP = {
    int: Int,
    str: Str,
    float: Float,
    List: Seq,
    Dict: MapPattern,
    Tuple: FixedSeq,
    Union: _DummyType,
}

_SCHEMA_FIELD_NAME = "STRICTYAML_SCHEMA"


class StrictYAMLSchemaGenerationError(Exception):
    pass


class StrictYAMLValueMappingError(Exception):
    pass


def _get_strictyaml_type(python_type):
    # another already processed class
    if hasattr(python_type, _SCHEMA_FIELD_NAME):
        return getattr(python_type, _SCHEMA_FIELD_NAME)

    # compount types like List
    elif (
        hasattr(python_type, "__origin__")
        and hasattr(python_type, "__args__")
        and getattr(python_type, "__origin__") in _TYPE_MAP
    ):
        origin = getattr(python_type, "__origin__")
        args = getattr(python_type, "__args__")

        # special case for Optional[T]
        if origin == Union and len(args) == 2 and args[1] == NoneType:
            # for some weird reason, the optional wrapper is on the key, not on the value type
            return _get_strictyaml_type(args[0])

        type_constructor = _TYPE_MAP[origin]
        type_arguments = [_get_strictyaml_type(a) for a in args]
        print(type_constructor, type_arguments)

        # special case for Tuple
        if origin == Tuple:
            return type_constructor(type_arguments)

        # default behaviour
        return type_constructor(*type_arguments)

    # error handlers for non existent primitive types
    elif python_type not in _TYPE_MAP:
        raise StrictYAMLSchemaGenerationError(f"Type {python_type} is not supported for YAML schema generation")

    # remaining primitive and untyped types
    else:
        return _TYPE_MAP[python_type]()


def dataclass_strictyaml_schema(cls):
    anot = cls.__dict__.get("__annotations__", {})

    if len(anot) == 0:
        schema = EmptyDict()
    else:
        fields = {}
        for name, python_type in anot.items():
            # special case for Optional[T], because it's weird
            # https://hitchdev.com/strictyaml/using/alpha/compound/optional-keys-with-defaults/
            if (
                hasattr(python_type, "__origin__")
                and hasattr(python_type, "__args__")
                and getattr(python_type, "__origin__") == Union
                and len(getattr(python_type, "__args__")) == 2
                and getattr(python_type, "__args__")[1] == NoneType
            ):
                name = strictyaml.Optional(name)
            fields[name] = _get_strictyaml_type(python_type)
        schema = Map(fields)

    setattr(cls, _SCHEMA_FIELD_NAME, schema)

    return cls


def _yamlobj_to_dataclass(cls, obj: YAML) -> Any:
    # native values recursion helper
    if cls in (int, float):
        return cls(obj)
    if cls == str:
        return str(obj.text)
    # compount types
    if (
        hasattr(cls, "__origin__")
        and hasattr(cls, "__args__")
        and getattr(cls, "__origin__") in (Union, Dict, List, Tuple)
    ):
        origin = getattr(cls, "__origin__")
        args = getattr(cls, "__args__")

        # Optional[T]
        if origin == Union and len(args) == 2 and args[1] == NoneType:
            return _yamlobj_to_dataclass(args[0], obj) if obj is not None else None

        # Dict[K, V]
        elif origin == Dict and len(args) == 2:
            return {
                _yamlobj_to_dataclass(args[0], key): _yamlobj_to_dataclass(args[1], val) for key, val in obj.items()
            }

        # List[T]
        elif origin == List and len(args) == 1:
            return [_yamlobj_to_dataclass(args[0], val) for val in obj]

        # Tuple
        elif origin == Tuple:
            return tuple(_yamlobj_to_dataclass(typ, val) for typ, val in zip(args, obj))

    # ^ that's full list of native types
    # the remaining code handles cases when cls is a dataclasses

    # assert that no weird class without schema gets here
    if not hasattr(cls, _SCHEMA_FIELD_NAME):
        raise Exception(
            f"{str(cls)} does not have a schema field and is not primitive - don't know how to parse. "
            + "Did you forget to add @dataclass_strictyaml_schema to nested dataclass?"
        )

    anot = cls.__dict__.get("__annotations__", {})
    kwargs = {}
    for name, python_type in anot.items():
        kwargs[name] = _yamlobj_to_dataclass(python_type, obj[name] if name in obj else None)
    return cls(**kwargs)


def _from_yaml(cls, text: str):
    schema = getattr(cls, _SCHEMA_FIELD_NAME)

    yamlobj = load(text, schema)
    return _yamlobj_to_dataclass(cls, yamlobj)


def dataclass_strictyaml(cls):
    if not hasattr(cls, _SCHEMA_FIELD_NAME):
        cls = dataclass_strictyaml_schema(cls)

    setattr(cls, "from_yaml", classmethod(_from_yaml))
    return cls


_T = TypeVar("_T", bound="StrictyamlParser")


class StrictyamlParser:
    @classmethod
    def from_yaml(cls: Type[_T], text: str) -> _T:
        if not hasattr(cls, _SCHEMA_FIELD_NAME):
            dataclass_strictyaml_schema(cls)

        return _from_yaml(cls, text)
