from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from typing import Any, Dict, Type


class BaseTypeABC(ABC):
    @abstractmethod
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        pass

    @abstractmethod
    def __int__(self) -> int:
        raise NotImplementedError(f" return 'int()' value for {type(self).__name__} is not implemented.")

    @abstractmethod
    def __str__(self) -> str:
        raise NotImplementedError(f"return 'str()' value for {type(self).__name__} is not implemented.")

    @abstractmethod
    def serialize(self) -> Any:
        """
        Used for dumping configuration. Returns a JSON-serializable object from which the object
        can be recreated again using the constructor.

        It's not necessary to return the same structure that was given as an input. It only has
        to be the same semantically.
        """
        raise NotImplementedError(f"{type(self).__name__}'s' 'serialize()' not implemented.")


class BaseValueType(BaseTypeABC):
    """
    Subclasses of this class can be used as type annotations in 'DataParser'. When a value
    is being parsed from a serialized format (e.g. JSON/YAML), an object will be created by
    calling the constructor of the appropriate type on the field value. The only limitation
    is that the value MUST NOT be `None`.

    There is no validation done on the wrapped value. The only condition is that
    it can't be `None`. If you want to perform any validation during creation,
    raise a `ValueError` in case of errors.
    """

    @classmethod
    @abstractmethod
    def json_schema(cls: Type["BaseValueType"]) -> Dict[Any, Any]:
        raise NotImplementedError()
