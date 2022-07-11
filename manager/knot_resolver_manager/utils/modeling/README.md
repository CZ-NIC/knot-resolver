# Modeling utils

These utilities are used to model schemas for data stored in a python dictionary or YAML and JSON format.
The utilities also take care of parsing, validating and creating JSON schemas and basic documentation.

## Creating schema

Schema is created using `SchemaNode` class. Schema structure is specified using annotations.

```python
from .modeling import SchemaNode

class BasicSchema(SchemaNode):
    integer: int = 5    # a default value can be specified
    string: str
    boolean: bool
```
Even more complex types can be used in a schema. Schemas can be also nested.

```python
from typing import Any, Dict, List, Optional, Union

class ComplexSchema(SchemaNode):
    optional: Optional[str]     # this field is optional
    union: Union[int, str]      # integer and string are both valid
    list: List[int]             # list of integers
    dictionary: Dict[str, Any] = {"key": False}
    basic_schema: BasicSchema   # nested schema
```


### Additianal validation

If a some additional validation needs to be done, there is `_validate()` method for that.
`ValueError` exception should be raised in case of validation error.

```python
class FieldsSchema(SchemaNode):
    field1: int
    field2: int

    def _validate(self) -> None:
        if self.field1 > self.field2:
            raise ValueError("field1 is bigger than field2")
```


### Additional layer, transformation methods

It is possible to add layers to schema and use a transformation method between layers to process the value.
Transformation method must be named based on field (`value` in this example) with `_` underscore prefix.
In this example, the `Layer2Schema` is structure for input data and `Layer1Schema` is for result data.

```python
class Layer1Schema(SchemaNode):
    class Layer2Schema(SchemaNode):
        value: Union[str, int]

    _LAYER = Layer2Schema

    value: int

    def _value(self, obj: Layer2Schema) -> Any:
        if isinstance(str, obj.value):
            return len(obj.value)   # transform str values to int; this is just example
        return obj.value
```

### Documentation and JSON schema

Created schema can be documented using simple docstring. Json schema is created by calling `json_schema()` method on schema class. JSON schema includes description from docstring, defaults, etc.

```python
BasicSchema(SchemaNode):
    """
    This is description for BasicSchema itself.

    ---
    integer: description for integer field
    string: description for string field
    boolean: description for boolean field
    """

    integer: int = 5
    string: str
    boolean: bool

json_schema = BasicSchema.json_schema()
```


## Creating custom type

Custom types can be only using `CustomValueType` class which is integrated to parsing a validating process.
Use `DataValidationError` to rase exception during validation. `object_path` is used to track node in more complex/nested schemas and create useful logging message.

```python
from .modeling import CustomValueType
from .modeling.exceptions import DataValidationError

class IntNonNegative(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, int) and not isinstance(source_value, bool):
            if source_value < 0:
                raise DataValidationError(f"value {source_value} is negative number.", object_path)
            self._value = source_value
        else:
            raise DataValidationError(
                f"expected integer, got '{type(source_value)}'",
                object_path,
            )
```

For JSON schema you should implement `json_schema` method.
It should return [JSON schema representation](https://json-schema.org/understanding-json-schema/index.html) of the custom type.

```python
    @classmethod
    def json_schema(cls: Type["IntNonNegative"]) -> Dict[Any, Any]:
        return {"type": "integer", "minimum": 0}
```


## Parsing JSON/YAML

For example, YAML data for `BasicSchema` look like this.

```yaml
# data.yaml
integer: 55
string: this is string
boolean: false
```

To parse data from YAML format just use `parse_yaml` function or `parse_json` for JSON format.

```python
from .modeling import parse_yaml

# read data from file
with open("data.yaml") as f:
    str_data = f.read()

dict_data = parse_yaml(str_data)
validated_data = BasicSchema(dict_data)
```