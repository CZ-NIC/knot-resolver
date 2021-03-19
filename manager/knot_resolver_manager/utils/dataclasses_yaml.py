from typing import List, Dict, Tuple
from strictyaml import Map, Str, EmptyDict, Int, Float, Seq, MapPattern, FixedSeq

_TYPE_MAP = {
    int: Int,
    str: Str,
    float: Float,
    List: Seq,
    Dict: MapPattern,
    Tuple: FixedSeq,
}

_FIELD_NAME = "STRICTYAML_SCHEMA"


class StrictYAMLSchemaGenerationError(Exception):
    pass


def _get_strictyaml_type(python_type):
    if hasattr(python_type, _FIELD_NAME):
        return getattr(python_type, _FIELD_NAME)

    elif (
        hasattr(python_type, "__origin__")
        and hasattr(python_type, "__args__")
        and getattr(python_type, "__origin__") in _TYPE_MAP
    ):
        origin = getattr(python_type, "__origin__")
        args = getattr(python_type, "__args__")

        type_constructor = _TYPE_MAP[origin]
        type_arguments = [_get_strictyaml_type(a) for a in args]
        print(type_constructor, type_arguments)
        if origin == Tuple:
            return type_constructor(type_arguments)
        else:
            return type_constructor(*type_arguments)

    elif python_type not in _TYPE_MAP:
        raise StrictYAMLSchemaGenerationError(
            f"Type {python_type} is not supported for YAML schema generation"
        )

    else:
        return _TYPE_MAP[python_type]()


def dataclasses_strictyaml_schema(cls):
    anot = cls.__dict__.get("__annotations__", {})

    if len(anot) == 0:
        schema = EmptyDict()
    else:
        fields = {}
        for name, python_type in anot.items():
            fields[name] = _get_strictyaml_type(python_type)
        schema = Map(fields)

    setattr(cls, _FIELD_NAME, schema)

    return cls
