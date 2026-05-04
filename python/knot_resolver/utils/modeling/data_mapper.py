from __future__ import annotations

from pathlib import Path
from typing import Any

from .data_mode_node import DataModelNode


class DataMapper:
    def _assign_field(self, obj: Any, name: str, python_type: Any, value: Any, object_path: str) -> None:
        value = self.map_object(python_type, value, object_path=f"{object_path}/{name}")
        setattr(obj, name, value)

    def _assign_fields(self, obj: Any, source: Union[Dict[str, Any], "BaseSchema", None], object_path: str) -> Set[str]:  # noqa: C901
        """
        Assign fields and values.

        Order of assignment:
          1. all direct assignments
          2. assignments with conversion method
        """
        cls = obj.__class__
        annot = get_annotations(cls)
        errs: List[DataValidationError] = []

        used_keys: Set[str] = set()
        for name, python_type in annot.items():
            try:
                if is_internal_field_name(name):
                    continue

                # populate field
                if source is None:
                    self._assign_default(obj, name, python_type, object_path)

                # check for invalid configuration with both transformation function and default value
                elif hasattr(obj, f"_{name}") and hasattr(obj, name):
                    raise RuntimeError(
                        f"Field '{obj.__class__.__name__}.{name}' has default value and transformation function at"
                        " the same time. That is now allowed. Store the default in the transformation function."
                    )

                # there is a transformation function to create the value
                elif hasattr(obj, f"_{name}") and callable(getattr(obj, f"_{name}")):
                    val = self._get_converted_value(obj, name, source, object_path)
                    self._assign_field(obj, name, python_type, val, object_path)
                    used_keys.add(name)

                # source just contains the value
                elif name in source:
                    val = source[name]
                    self._assign_field(obj, name, python_type, val, object_path)
                    used_keys.add(name)

                # there is a default value, or the type is optional => store the default or null
                elif hasattr(obj, name) or is_optional(python_type):
                    self._assign_default(obj, name, python_type, object_path)

                # we expected a value but it was not there
                else:
                    errs.append(DataValidationError(f"missing attribute '{name}'.", object_path))
            except DataValidationError as e:
                errs.append(e)

        if len(errs) == 1:
            raise errs[0]
        if len(errs) > 1:
            raise AggregateDataValidationError(object_path, errs)
        return used_keys

    def object_constructor(self, node: DataModelNode, source: dict[Any, Any], tree_path: str, base_path: Path) -> None:
        # assign fields
        used_keys = self._assign_fields(obj, source, object_path)

        # check for unused keys in the source object
        if source and not isinstance(source, BaseSchema):
            unused = source.keys() - used_keys
            if len(unused) > 0:
                keys = ", ".join(f"'{u}'" for u in unused)
                raise DataValidationError(
                    f"unexpected extra key(s) {keys}",
                    object_path,
                )

        # validate the constructed value
        try:
            obj._validate()  # noqa: SLF001
        except ValueError as e:
            raise DataValidationError(e.args[0] if len(e.args) > 0 else "Validation error", object_path or "/") from e

    # def _create_tuple(self, typ: Type[Any], obj: Tuple[Any, ...], object_path: str) -> Tuple[Any, ...]:
    #     types = get_generic_type_arguments(tp)
    #     errs: List[DataValidationError] = []
    #     res: List[Any] = []
    #     for i, (t, val) in enumerate(zip(types, obj)):
    #         try:
    #             res.append(self.map_object(t, val, object_path=f"{object_path}[{i}]"))
    #         except DataValidationError as e:
    #             errs.append(e)
    #     if len(errs) == 1:
    #         raise errs[0]
    #     if len(errs) > 1:
    #         raise AggregateDataValidationError(object_path, child_exceptions=errs)
    #     return tuple(res)

    # def _create_dict(self, tp: Type[Any], obj: Dict[Any, Any], object_path: str) -> Dict[Any, Any]:
    #     key_type, val_type = get_generic_type_arguments(tp)
    #     try:
    #         errs: List[DataValidationError] = []
    #         res: Dict[Any, Any] = {}
    #         for key, val in obj.items():
    #             try:
    #                 nkey = self.map_object(key_type, key, object_path=f"{object_path}[{key}]")
    #                 nval = self.map_object(val_type, val, object_path=f"{object_path}[{key}]")
    #                 res[nkey] = nval
    #             except DataValidationError as e:
    #                 errs.append(e)
    #         if len(errs) == 1:
    #             raise errs[0]
    #         if len(errs) > 1:
    #             raise AggregateDataValidationError(object_path, child_exceptions=errs)
    #     except AttributeError as e:
    #         raise DataValidationError(
    #             f"Expected dict-like object, but failed to access its .items() method. Value was {obj}", object_path
    #         ) from e
    #     else:
    #         return res

    # def _create_list(self, tp: Type[Any], obj: List[Any], object_path: str) -> List[Any]:
    #     if isinstance(obj, str):
    #         raise DataValidationError("expected list, got string", object_path)

    #     inner_type = get_generic_type_argument(tp)
    #     errs: List[DataValidationError] = []
    #     res: List[Any] = []

    #     try:
    #         for i, val in enumerate(obj):
    #             res.append(self.map_object(inner_type, val, object_path=f"{object_path}[{i}]"))
    #         if len(res) == 0:
    #             raise DataValidationError("empty list is not allowed", object_path)
    #     except DataValidationError as e:
    #         errs.append(e)
    #     except TypeError as e:
    #         errs.append(DataValidationError(str(e), object_path))

    #     if len(errs) == 1:
    #         raise errs[0]
    #     if len(errs) > 1:
    #         raise AggregateDataValidationError(object_path, child_exceptions=errs)
    #     return res

    # def _create_str(self, obj: Any, object_path: str) -> str:
    #     # we are willing to cast any primitive value to string, but no compound values are allowed
    #     if is_obj_type(obj, (str, float, int)) or isinstance(obj, BaseValueType):
    #         return str(obj)
    #     if is_obj_type(obj, bool):
    #         raise DataValidationError(
    #             "Expected str, found bool. Be careful, that YAML parsers consider even"
    #             ' "no" and "yes" as a bool. Search for the Norway Problem for more'
    #             " details. And please use quotes explicitly.",
    #             object_path,
    #         )
    #     raise DataValidationError(
    #         f"expected str (or number that would be cast to string), but found type {type(obj)}", object_path
    #     )

    # def _create_int(self, obj: Any, object_path: str) -> int:
    #     # we don't want to make an int out of anything else than other int
    #     # except for BaseValueType class instances
    #     if is_obj_type(obj, int) or isinstance(obj, BaseValueType):
    #         return int(obj)
    #     raise DataValidationError(f"expected int, found {type(obj)}", object_path)

    # def _create_union(self, tp: Type[T], obj: Any, object_path: str) -> T:
    #     variants = get_generic_type_arguments(tp)
    #     errs: List[DataValidationError] = []
    #     for v in variants:
    #         try:
    #             return self.map_object(v, obj, object_path=object_path)
    #         except DataValidationError as e:
    #             errs.append(e)

    #     raise DataValidationError("could not parse any of the possible variants", object_path, child_exceptions=errs)

    # def _create_optional(self, tp: Type[Optional[T]], obj: Any, object_path: str) -> Optional[T]:
    #     inner: Type[Any] = get_optional_inner_type(tp)
    #     if obj is None:
    #         return None
    #     return self.map_object(inner, obj, object_path=object_path)

    # def _create_bool(self, obj: Any, object_path: str) -> bool:
    #     if is_obj_type(obj, bool):
    #         return obj
    #     raise DataValidationError(f"expected bool, found {type(obj)}", object_path)

    # def _create_literal(self, tp: Type[Any], obj: Any, object_path: str) -> Any:
    #     args = get_generic_type_arguments(tp)

    #     expected = []
    #     if sys.version_info < (3, 9):
    #         for arg in args:
    #             if is_literal(arg):
    #                 expected += get_generic_type_arguments(arg)
    #             else:
    #                 expected.append(arg)
    #     else:
    #         expected = args

    #     if obj in expected:
    #         return obj
    #     raise DataValidationError(f"'{obj}' does not match any of the expected values {expected}", object_path)

    # def _create_base_schema_object(self, tp: Type[Any], obj: Any, object_path: str) -> "BaseSchema":
    #     if isinstance(obj, (dict, BaseSchema)):
    #         return tp(obj, object_path=object_path)
    #     raise DataValidationError(f"expected 'dict' or 'NoRenameBaseSchema' object, found '{type(obj)}'", object_path)

    # def create_value_type_object(self, tp: Type[Any], obj: Any, object_path: str) -> "BaseValueType":
    #     if isinstance(obj, tp):
    #         # if we already have a custom value type, just pass it through
    #         return obj
    #     # no validation performed, the implementation does it in the constuctor
    #     try:
    #         return tp(obj, object_path=object_path)
    #     except ValueError as e:
    #         if len(e.args) > 0 and isinstance(e.args[0], str):
    #             msg = e.args[0]
    #         else:
    #             msg = f"Failed to validate value against {tp} type"
    #         raise DataValidationError(msg, object_path) from e

    # def _create_default(self, obj: Any) -> Any:
    #     if isinstance(obj, _LazyDefault):
    #         return obj.instantiate()
    #     return obj

    # def map_object(  # noqa: C901, PLR0911, PLR0912
    #     self,
    #     tp: Type[Any],
    #     obj: Any,
    #     default: Any = ...,
    #     use_default: bool = False,
    #     object_path: str = "/",
    # ) -> Any:
    #     """
    #     Given an expected type `cls` and a value object `obj`.

    #     Return a new object of the given type and map fields of `obj` into it.
    #     During the mapping procedure, runtime type checking is performed.
    #     """
    #     # Disabling these checks, because I think it's much more readable as a single function
    #     # and it's not that large at this point. If it got larger, then we should definitely split it
    #     # pylint: disable=too-many-branches,too-many-locals,too-many-statements

    #     # default values
    #     if obj is None and use_default:
    #         return self._create_default(default)

    #     # NoneType
    #     if is_none_type(tp):
    #         if obj is None:
    #             return None
    #         raise DataValidationError(f"expected None, found '{obj}'.", object_path)

    #     # Optional[T]  (could be technically handled by Union[*variants], but this way we have better error reporting)
    #     if is_optional(tp):
    #         return self._create_optional(tp, obj, object_path)

    #     # Union[*variants]
    #     if is_union(tp):
    #         return self._create_union(tp, obj, object_path)

    #     # after this, there is no place for a None object
    #     if obj is None:
    #         raise DataValidationError(f"unexpected value 'None' for type {tp}", object_path)

    #     # int
    #     if tp is int:
    #         return self._create_int(obj, object_path)

    #     # str
    #     if tp is str:
    #         return self._create_str(obj, object_path)

    #     # bool
    #     if tp is bool:
    #         return self._create_bool(obj, object_path)

    #     # float
    #     if tp is float:
    #         raise NotImplementedError(
    #             "Floating point values are not supported in the object mapper."
    #             " Please implement them and be careful with type coercions"
    #         )

    #     # Literal[T]
    #     if is_literal(tp):
    #         return self._create_literal(tp, obj, object_path)

    #     # Dict[K,V]
    #     if is_dict(tp):
    #         return self._create_dict(tp, obj, object_path)

    #     # any Enums (probably used only internally in DataValidator)
    #     if is_enum(tp):
    #         if isinstance(obj, tp):
    #             return obj
    #         raise DataValidationError(f"unexpected value '{obj}' for enum '{tp}'", object_path)

    #     # List[T]
    #     if is_list(tp):
    #         return self._create_list(tp, obj, object_path)

    #     # Tuple[A,B,C,D,...]
    #     if is_tuple(tp):
    #         return self._create_tuple(tp, obj, object_path)

    #     # type of obj and cls type match
    #     if is_obj_type(obj, tp):
    #         return obj

    #     # when the specified type is Any, just return the given value
    #     # on mypy version 1.11.0 comparison-overlap error started popping up
    #     # https://github.com/python/mypy/issues/17665
    #     if tp == Any:  # type: ignore[comparison-overlap]
    #         return obj

    #     # BaseValueType subclasses
    #     if inspect.isclass(tp) and issubclass(tp, BaseValueType):
    #         return self.create_value_type_object(tp, obj, object_path)

    #     # BaseGenericTypeWrapper subclasses
    #     if is_generic_type_wrapper(tp):
    #         inner_type = get_generic_type_wrapper_argument(tp)
    #         obj_valid = self.map_object(inner_type, obj, object_path)
    #         return tp(obj_valid, object_path=object_path)

    #     # nested BaseSchema subclasses
    #     if inspect.isclass(tp) and issubclass(tp, BaseSchema):
    #         return self._create_base_schema_object(tp, obj, object_path)

    #     # if the object matches, just pass it through
    #     if inspect.isclass(tp) and isinstance(obj, tp):
    #         return obj

    #     # default error handler
    #     raise DataValidationError(
    #         f"Type {tp} cannot be parsed. This is a implementation error. "
    #         "Please fix your types in the class or improve the parser/validator.",
    #         object_path,
    #     )

    # def is_obj_type_valid(self, obj: Any, tp: Type[Any]) -> bool:
    #     """Runtime type checking. Validate, that a given object is of a given type."""
    #     try:
    #         self.map_object(tp, obj)
    #     except (DataValidationError, ValueError):
    #         return False
    #     else:
    #         return True

    # def _assign_default(self, obj: Any, name: str, python_type: Any, object_path: str) -> None:
    #     cls = obj.__class__

    #     try:
    #         default = self._create_default(getattr(cls, name, None))
    #     except ValueError as e:
    #         raise DataValidationError(str(e), f"{object_path}/{name}") from e

    #     value = self.map_object(python_type, default, object_path=f"{object_path}/{name}")
    #     setattr(obj, name, value)

    # def _get_converted_value(self, obj: Any, key: str, source: TSource, object_path: str) -> Any:
    #     """Get a value of a field by invoking appropriate transformation function."""
    #     try:
    #         func = getattr(obj.__class__, f"_{key}")
    #         argc = len(inspect.signature(func).parameters)
    #         if argc == 1:
    #             # it is a static method
    #             return func(source)
    #         if argc == 2:
    #             # it is a instance method
    #             return func(_create_untouchable("obj"), source)
    #         raise RuntimeError("Transformation function has wrong number of arguments")
    #     except ValueError as e:
    #         msg = e.args[0] if len(e.args) > 0 and isinstance(e.args[0], str) else "Failed to validate value type"
    #         raise DataValidationError(msg, object_path) from e

    # def object_constructor(self, obj: Any, source: Union["BaseSchema", Dict[Any, Any]], object_path: str) -> None:
    #     """
    #     Construct object. Delegated constructor for the NoRenameBaseSchema class.

    #     The reason this method is delegated to the mapper is due to renaming. Like this, we don't have to
    #     worry about a different BaseSchema class, when we want to have dynamically renamed fields.
    #     """
    #     # As this is a delegated constructor, we must ignore protected access warnings

    #     # sanity check
    #     if not isinstance(source, (BaseSchema, dict)):
    #         raise DataValidationError(f"expected dict-like object, found '{type(source)}'", object_path)

    #     # construct lower level schema first if configured to do so
    #     if obj._LAYER is not None:  # noqa: SLF001
    #         source = obj._LAYER(source, object_path=object_path)  # pylint: disable=not-callable  # noqa: SLF001

    #     # assign fields
    #     used_keys = self._assign_fields(obj, source, object_path)

    #     # check for unused keys in the source object
    #     if source and not isinstance(source, BaseSchema):
    #         unused = source.keys() - used_keys
    #         if len(unused) > 0:
    #             keys = ", ".join(f"'{u}'" for u in unused)
    #             raise DataValidationError(
    #                 f"unexpected extra key(s) {keys}",
    #                 object_path,
    #             )

    #     # validate the constructed value
    #     try:
    #         obj._validate()  # noqa: SLF001
    #     except ValueError as e:
    #         raise DataValidationError(e.args[0] if len(e.args) > 0 else "Validation error", object_path or "/") from e
