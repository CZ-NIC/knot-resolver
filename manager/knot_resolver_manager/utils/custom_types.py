from typing import Any


class CustomValueType:
    """
    Subclasses of this class can be used as type annotations in 'DataParser'. When a value
    is being parsed from a serialized format (e.g. JSON/YAML), an object will be created by
    calling the constructor of the appropriate type on the field value. The only limitation
    is that the value MUST NOT be `None`.

    Example:
    ```
    class A(DataParser):
        field: MyCustomValueType

    A.from_json('{"field": "value"}') == A(field=MyCustomValueType("value"))
    ```

    There is no validation done on the wrapped value. The only condition is that
    it can't be `None`. If you want to perform any validation during creation,
    raise a `SchemaException` in case of errors.
    """

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        pass

    def __int__(self) -> int:
        raise NotImplementedError("CustomValueType return 'int()' value is not implemented.")

    def __str__(self) -> str:
        raise NotImplementedError("CustomValueType return 'str()' value is not implemented.")

    def serialize(self) -> Any:
        """
        Every custom type should implement this. It is used for dumping configuration.

        It's not necessary to return the same structure that was given as an input. It only has
        to be the same semantically.
        """
        raise NotImplementedError(f"{type(self).__name__}'s' 'to_dict()' not implemented.")
