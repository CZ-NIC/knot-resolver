from typing import List, Dict, Tuple, Union
from strictyaml import Map, Str, EmptyDict, Int, Float, Seq, MapPattern, FixedSeq
import strictyaml


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
            return strictyaml.Optional(_get_strictyaml_type(args[0]))

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
        raise StrictYAMLSchemaGenerationError(
            f"Type {python_type} is not supported for YAML schema generation"
        )

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
            fields[name] = _get_strictyaml_type(python_type)
        schema = Map(fields)

    setattr(cls, _SCHEMA_FIELD_NAME, schema)

    return cls
