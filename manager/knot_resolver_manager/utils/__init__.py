from .dataclasses_yaml import (
    dataclass_strictyaml_schema,
    dataclass_strictyaml,
    StrictyamlParser,
)


def ignore_exceptions(default, *exception):
    def decorator(func):
        def f(*nargs, **nkwargs):
            try:
                return func(*nargs, **nkwargs)
            except exception:
                return default

        return f

    return decorator


__all__ = [
    "dataclass_strictyaml_schema",
    "dataclass_strictyaml",
    "StrictyamlParser",
    "ignore_exceptions",
]
