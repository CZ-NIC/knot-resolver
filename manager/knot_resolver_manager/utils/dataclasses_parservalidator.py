import json
from typing import Any, Type, TypeVar

import yaml

from knot_resolver_manager.utils.types import (
    get_generic_type_argument,
    get_generic_type_arguments,
    get_optional_inner_type,
    is_dict,
    is_list,
    is_optional,
    is_tuple,
)

from ..compat.dataclasses import is_dataclass


class ValidationException(Exception):
    pass


def _from_dictlike_obj(cls: Any, obj: Any, default: Any, use_default: bool) -> Any:
    # default values
    if obj is None and use_default:
        return default

    # primitive types
    if cls in (int, float, str):
        return cls(obj)

    # Optional[T]
    if is_optional(cls):
        if obj is None:
            return None
        else:
            return _from_dictlike_obj(get_optional_inner_type(cls), obj, ..., False)

    # Dict[K,V]
    elif is_dict(cls):
        key_type, val_type = get_generic_type_arguments(cls)
        return {
            _from_dictlike_obj(key_type, key, ..., False): _from_dictlike_obj(val_type, val, ..., False)
            for key, val in obj.items()
        }

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
