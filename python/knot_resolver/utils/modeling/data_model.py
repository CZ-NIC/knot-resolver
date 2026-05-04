from __future__ import annotations

import enum
import inspect
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from .context import Context, Strictness
from .errors import DataDescriptionError
from .parsing import ParsedData, ParsedDataWrapper
from .types.base_custom_type import BaseCustomType
from .types.inspect import (
    get_annotations,
    get_base_generic_type_wrapper_argument,
    get_optional_inner_type,
    is_base_generic_type_wrapper,
    is_dict,
    is_list,
    is_literal,
    is_none_type,
    is_optional,
    is_union,
)

if TYPE_CHECKING:
    from .pointer import JSONPointer


# def _split_docstring(docstring: str) -> tuple[str, str] | None:
#     if "---" not in docstring:
#         return ("\n".join([s.strip() for s in docstring.splitlines()]).strip(), None)

#     doc, attrs_doc = docstring.split("---", maxsplit=1)
#     return (
#         "\n".join([s.strip() for s in doc.splitlines()]).strip(),
#         attrs_doc,
#     )


# def _describe_type(typ: type[Any]) -> dict[Any, Any]:
#     if is_none_type(typ):
#         return {"type": "null"}
#     if typ is int:
#         return {"type": "integer"}
#     if typ is bool:
#         return {"type": "boolean"}
#     if typ is str:
#         return {"type": "string"}

#     if inspect.isclass(typ) and issubclass(typ, DataModel):
#         return typ.json_schema()

#     if inspect.isclass(typ) and issubclass(typ, BaseCustomType):
#         return typ.json_schema()

#     if is_base_generic_type_wrapper(typ):
#         wrapped = get_base_generic_type_wrapper_argument(typ)
#         return _describe_type(wrapped)

#     if is_literal(typ):
#         lit: list[str] = []
#         args = inspect.get_args(typ)
#         for arg in args:
#             if is_literal(arg):
#                 lit += inspect.get_args(arg)
#             else:
#                 lit.append(arg)
#         return {"type": "string", "enum": lit}

#     if is_optional(typ):
#         desc = _describe_type(get_optional_inner_type(typ))
#         if "type" in desc:
#             desc["type"] = [desc["type"], "null"]
#             return desc
#         return {"anyOf": [{"type": "null"}, desc]}

#     if is_union(typ):
#         variants = inspect.get_args(typ)
#         return {"anyOf": [_describe_type(v) for v in variants]}

#     if is_list(typ):
#         return {"type": "array", "items": _describe_type(inspect.get_args(typ)[0])}

#     if is_dict(typ):
#         key, value = inspect.get_args(typ)

#         if inspect.isclass(key) and issubclass(key, BaseCustomType):
#             assert (
#                 key.__str__ is not BaseCustomType.__str__
#             ), "To support derived 'BaseValueType', __str__ must be implemented."
#         else:
#             assert key is str, "We currently do not support any other keys then strings"

#         return {"type": "object", "additionalProperties": _describe_type(value)}

#     msg = f"JSON schema for type '{typ}' is not implemented"
#     raise NotImplementedError(msg)


# def _get_attrs_docs(docstring: str) -> dict[str, str] | None:
#     attrs_docs = _split_docstring(docstring)[1]
#     if attrs_docs is None:
#         return None
#     return parse_yaml(attrs_docs)


def _get_json_schema_description(model_type: type[DataModel]) -> str:
    return ""


#     docstring = inspect.get_doc(node_type)
#     if not docstring:
#         msg = f"missing docstring for '{node_type}"
#         raise DataDescriptionError(msg, node_path)
#     return _split_docstring(docstring)[0]


def _get_json_schema_properties(model_type: type[DataModel]) -> dict[Any, Any]:
    return {}


#     schema: dict[str, Any] = {}

#     docstring = inspect.get_doc(model_type)
#     if not docstring:
#         msg = f"missing docstring for '{model_type}'"
#         raise DataDescriptionError(msg)
#     attrs_docs = _get_attrs_docs(docstring)

#     annotations: dict[str, Any] = get_annotations(model_type)
#     for attr_name, attr_type in annotations.items():
#         name = attr_name.replace("_", "-")
#         schema[name] = _describe_type(attr_type)

#         description = attrs_docs.pop(attr_name, None)
#         if description is None:
#             msg = f"missing description for '{attr_name}' in docstring for '{model_type}'"
#             raise DataDescriptionError(msg)
#         schema[name]["description"] = description

#         default = getattr(model_type, attr_name, None)
#         if default:
#             schema[name]["default"] = default

#     if attrs_docs:
#         msg = f"additional description in '{model_type}' docstring: {tuple(attrs_docs.keys())}"
#         raise DataDescriptionError(msg)

#     return schema


# def data_combine(data1: DataModel, data2: DataModel, *data: DataModel) -> DataModel:
#     result =

#     for arg in args:
#         data_combine()


def _assign_type():
    pass


def _assign_attributes(self: DataModel) -> None:
    source: ParsedData = self._source
    annot: dict[str, Any] = get_annotations(type(self))

    if isinstance(source, ParsedDataWrapper):
        base_path = source.file.parent
        source = source.data

    if isinstance(source, dict):


        for key, value in source.items():
            _key = key.replace("-", "_")

            if _key in annot:
                _type = annot[key]
                setattr(self, _key, _type(source[key]))



class DataModel:
    """Represents the data model and the source data.

    The source data is stored in its original form and is simply organized into the attributes of the data model.
    For advanced validation, first you need to assign_defaults() and then call the validate() method.

    Attributes:
        source (ParsedData | None): Source data in the dictionary.
        pointer (JSONPointer): A JSON pointer that indicates the current position in the data model subtree.
        base_path (str | Path): The base path for files and directories relative paths.

    """

    def __init__(
        self,
        source: ParsedData | None = None,
        pointer: JSONPointer = "/",
        base_path: str | Path = Path(),
    ) -> None:
        self._source = source or {}
        self._validated: bool = False
        self._pointer = pointer
        self._base_path = Path(base_path)
        _assign_attributes(self)

    # def append(self, additional_data: DataModel) -> None:
    #     def data_combine(data1: DataModel, data2: DataModel) -> None:
    #         if type(data1) is not type(data2):
    #             # error here
    #             pass

    #         annot: dict[str, Any] = get_annotations(type(self))
    #         for attr_name, attr_type in annot.items():
    #             name = attr_name.replace("_", "-")

    #             if not hasattr(self, attr_name) and hasattr(additional_data, attr_name):
    #                 attr_value = getattr(additional_data, attr_name)
    #                 setattr(self, attr_name, attr_value)

    #             if inspect.isclass(attr_type) and issubclass(attr_type, DataModel):
    #                 if hasattr(data1, attr_name) and hasattr(data2, attr_name):
    #                     data_combine(getattr(data1, attr_name), getattr(data2, attr_name))

    #     data_combine(self, additional_data)

    def assign_defaults(self) -> None:
        """Assign default values to missing attributes.

        A value is assigned if attribute is missing and default value is available for it.
        Without default values, data validation may fail even if the data is valid.
        """
        cls = type(self)
        annot: dict[str, Any] = get_annotations(cls)

        for key in annot:
            if not hasattr(key, key) and hasattr(cls, key):
                default = getattr(cls, key)
                setattr(self, key, default)

    def _validate_subtree(self, context: Context) -> None:
        for attr_value in vars(self).values():
            if isinstance(attr_value, BaseCustomType):
                attr_value.validate(context)

    def _validate(self, context: Context) -> None:
        """Validate all data under the node subtree.

        All validation should be done here.
        This method is automatically called during validation.
        """

    def validate(self, context: Context | None = None) -> None:
        """Validate all data under the node subtree.

        At least BASIC validation strictness is required
        for the data value to be considered valid.
        If validation is successful, no error is raised.

        Args:
            context (Context | None):
                Optional, validation context for the validation operations, e.g. validation strictness
                or username and groupname to check permissions on paths.
                If set to None, Context with STRICT validation strictness is used.

        Raises:
            DataTypeError: When input data type validation fails.
            DataValueError: When input data value validation fails.
            DataValidationError: When some other input data validation fails.

        """
        if context is None:
            # STRICT validation is used by default
            context = Context(strictness=Strictness.STRICT)

        self._validate_subtree(context)
        self._validate(context)
        if context.strictness > Strictness.NORMAL:
            self._validated = True

    @classmethod
    def json_schema_minimal(cls) -> dict[str, Any]:
        """Get minimal JSON schema without any additional metadata.

        Returns:
            Minimal JSON schema definition of the entire data model subtree without any additional metadata.

        """
        return {
            "type": "object",
            "description": _get_json_schema_description(cls),
            "properties": _get_json_schema_properties(cls),
        }

    @classmethod
    def json_schema(cls, schema_id: str, schema_title: str, schema_description: str) -> dict[str, Any]:
        """Get JSON schema with metadata.

        Args:
            schema_id (str):  Unique URI for the JSON schema.
            schema_title (str): Title for the JSON schema.
            schema_description (str): Description for the JSON schema.

        Returns:
            Proper JSON schema definition of the entire data model subtree
            with additional metadata ($schema, $id, title and description).

        """
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": schema_id,
            "title": schema_title,
            "type": "object",
            "description": schema_description,
            "properties": _get_json_schema_properties(cls),
        }
