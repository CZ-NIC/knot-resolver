from typing import List, Dict, Tuple, Union
from strictyaml import (
    Map,
    Str,
    EmptyDict,
    Int,
    Float,
    Seq,
    MapPattern,
    FixedSeq,
    load,
    YAML,
)
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


def _yamlobj_to_dataclass(cls, obj: YAML):
    # primitive values recursion helper
    if cls in (str, int, float):
        return cls(obj)

    # assert that no other weird class gets here
    assert hasattr(cls, _SCHEMA_FIELD_NAME)

    anot = cls.__dict__.get("__annotations__", {})

    kwargs = {}
    for name, python_type in anot.items():
        # another dataclass
        if hasattr(python_type, _SCHEMA_FIELD_NAME):
            kwargs[name] = _yamlobj_to_dataclass(python_type, obj[name])

        # string
        elif python_type == str:
            kwargs[name] = obj[name].text

        # numbers
        elif python_type in (int, float):
            kwargs[name] = obj[name]

        # compound generic types
        elif (
            hasattr(python_type, "__origin__")
            and hasattr(python_type, "__args__")
            and getattr(python_type, "__origin__") in (Union, Dict, List, Tuple)
        ):
            origin = getattr(python_type, "__origin__")
            args = getattr(python_type, "__args__")

            # Optional[T]
            if origin == Union and len(args) == 2 and args[1] == NoneType:
                kwargs[name] = obj[name] if name in obj else None

            # Dict[K, V]
            elif origin == Dict and len(args) == 2:
                kwargs[name] = {
                    _yamlobj_to_dataclass(args[0], key): _yamlobj_to_dataclass(
                        args[1], val
                    )
                    for key, val in obj[name].items()
                }

            # List[T]
            elif origin == List and len(args) == 1:
                kwargs[name] = [
                    _yamlobj_to_dataclass(args[0], val)
                    for val in obj[name]
                    if print(args[0], val) is None
                ]

            # Tuple
            elif origin == Tuple:
                kwargs[name] = tuple(
                    _yamlobj_to_dataclass(typ, val) for typ, val in zip(args, obj[name])
                )

            # unsupported compound type
            else:
                raise StrictYAMLValueMappingError(
                    f"Failed to map compound map field {name} <{python_type}> into {cls}"
                )

        # unsupported type
        else:
            raise StrictYAMLValueMappingError(
                f"Failed to map field {name} <{python_type}> into {cls}"
            )

    return cls(**kwargs)


def dataclass_strictyaml(cls):
    if not hasattr(cls, _SCHEMA_FIELD_NAME):
        cls = dataclass_strictyaml_schema(cls)

    def from_yaml(text: str) -> cls:
        schema = getattr(cls, _SCHEMA_FIELD_NAME)

        yamlobj = load(text, schema)
        return _yamlobj_to_dataclass(cls, yamlobj)

    setattr(cls, "from_yaml", from_yaml)
    return cls
