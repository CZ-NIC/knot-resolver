import json
from typing import Any, Type, TypeVar

import yaml

from knot_resolver_manager.utils.types import (
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


class ValidationException(Exception):
    pass


def _from_dictlike_obj(cls: Any, obj: Any, default: Any, use_default: bool) -> Any:
    # pylint: disable=too-many-branches,too-many-locals

    # default values
    if obj is None and use_default:
        return default

    # NoneType
    elif is_none_type(cls):
        if obj is None:
            return None
        else:
            raise ValidationException(f"Expected None, found {obj}")

    # Union[*variants] (handles Optional[T] due to the way the typing system works)
    elif is_union(cls):
        variants = get_generic_type_arguments(cls)
        for v in variants:
            try:
                return _from_dictlike_obj(v, obj, ..., False)
            except ValidationException:
                pass
        raise ValidationException(f"Union {cls} could not be parsed - parsing of all variants failed")

    # after this, there is no place for a None object
    elif obj is None:
        raise ValidationException(f"Unexpected None value for type {cls}")

    # primitive types
    if cls in (int, float, str):
        try:
            return cls(obj)
        except ValueError as e:
            raise ValidationException(f"Failed to parse primitive type {cls}, value {obj}", e)

    # Literal[T]
    elif is_literal(cls):
        expected = get_generic_type_argument(cls)
        if obj == expected:
            return obj
        else:
            raise ValidationException(f"Literal {cls} is not matched with the value {obj}")

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        try:
            return {
                _from_dictlike_obj(key_type, key, ..., False): _from_dictlike_obj(val_type, val, ..., False)
                for key, val in obj.items()
            }
        except AttributeError as e:
            raise ValidationException(
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
            value = obj[name] if name in obj else None
            use_default = hasattr(cls, name)
            default = getattr(cls, name, ...)
            kwargs[name] = _from_dictlike_obj(python_type, value, default, use_default)
        return cls(**kwargs)

    # default error handler
    else:
        raise ValidationException(
            f"Type {cls} cannot be parsed. This is a implementation error. "
            "Please fix your types in the dataclass or improve the parser/validator."
        )


_T = TypeVar("_T", bound="DataclassParserValidatorMixin")


class DataclassParserValidatorMixin:
    def validate_recursive(self) -> None:
        for field_name in dir(self):
            # skip internal fields
            if field_name.startswith("_"):
                continue

            field = getattr(self, field_name)
            if is_dataclass(field):
                if not isinstance(field, DataclassParserValidatorMixin):
                    raise ValidationException(
                        f"Nested dataclass in the field {field_name} does not include the ParserValidatorMixin"
                    )
                field.validate_recursive()

        self.validate()

    def validate(self) -> None:
        raise NotImplementedError(f"Validation function is not implemented in class {type(self).__name__}")

    @classmethod
    def from_yaml(cls: Type[_T], text: str, default: _T = ..., use_default: bool = False) -> _T:
        data = yaml.safe_load(text)
        config: _T = _from_dictlike_obj(cls, data, default, use_default)
        config.validate_recursive()
        return config

    @classmethod
    def from_json(cls: Type[_T], text: str, default: _T = ..., use_default: bool = False) -> _T:
        data = json.loads(text)
        config: _T = _from_dictlike_obj(cls, data, default, use_default)
        config.validate_recursive()
        return config
