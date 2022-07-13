from typing import Any, Dict, Type


class BaseCustomType:
    """
    Subclasses of this class can be used as type annotations in 'DataParser'. When a value
    is being parsed from a serialized format (e.g. JSON/YAML), an object will be created by
    calling the constructor of the appropriate type on the field value. The only limitation
    is that the value MUST NOT be `None`.

    There is no validation done on the wrapped value. The only condition is that
    it can't be `None`. If you want to perform any validation during creation,
    raise a `ValueError` in case of errors.
    """

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        pass

    def __int__(self) -> int:
        raise NotImplementedError(f" return 'int()' value for {type(self).__name__} is not implemented.")

    def __str__(self) -> str:
        raise NotImplementedError(f"return 'str()' value for {type(self).__name__} is not implemented.")

    def serialize(self) -> Any:
        """
        Every custom type should implement this. It is used for dumping configuration.

        It's not necessary to return the same structure that was given as an input. It only has
        to be the same semantically.
        """
        raise NotImplementedError(f"{type(self).__name__}'s' 'serialize()' not implemented.")

    @classmethod
    def json_schema(cls: Type["BaseCustomType"]) -> Dict[Any, Any]:
        raise NotImplementedError()
