from collections import defaultdict
from typing import Any, Callable, Dict, Generic, List, Tuple, Type, TypeVar

from knot_resolver_manager.utils.types import NoneType, get_optional_inner_type, is_optional

T = TypeVar("T")


class OverloadedFunctionException(Exception):
    pass


class Overloaded(Generic[T]):
    def __init__(self):
        self._vtable: Dict[Tuple[Any, ...], Callable[..., T]] = {}

    @staticmethod
    def _create_signatures(*types: Any) -> List[Any]:
        result: List[List[Any]] = [[]]
        for arg_type in types:
            if is_optional(arg_type):
                tp = get_optional_inner_type(arg_type)
                result = [p + [NoneType] for p in result] + [p + [tp] for p in result]
            else:
                result = [p + [arg_type] for p in result]

        # make tuples
        return [tuple(x) for x in result]

    def add(self, *args: Type[Any], **kwargs: Type[Any]) -> Callable[[Callable[..., T]], Callable[..., T]]:
        if len(kwargs) != 0:
            raise OverloadedFunctionException(
                "Sorry, named arguments are not supported. "
                "You can however implement them and make them functional... ;)"
            )

        def wrapper(func: Callable[..., T]) -> Callable[..., T]:
            signatures = Overloaded._create_signatures(*args)
            for signature in signatures:
                if signature in self._vtable:
                    raise OverloadedFunctionException(
                        "Sorry, signature {signature} is already defined. "
                        "You can't make a second definition of the same signature."
                    )
                self._vtable[signature] = func

            return self

        return wrapper

    def default(self, func: Callable[..., T]) -> Callable[..., T]:
        if isinstance(self._vtable, defaultdict):
            raise OverloadedFunctionException(
                "Sorry, you can't define multiple default handlers in an overloaded function"
            )

        self._vtable = defaultdict(lambda: func, self._vtable)
        return self

    def __call__(self, *args: Any, **kwargs: Any) -> T:
        if len(kwargs) != 0:
            raise OverloadedFunctionException(
                "Sorry, named arguments are not supported. "
                "You can however implement them and make them functional... ;)"
            )

        signature = tuple(type(a) for a in args)
        if signature not in self._vtable:
            raise OverloadedFunctionException(
                f"Function overload with signature {signature} is not registered and can't be called."
            )
        return self._vtable[signature](*args)

    def _print_vtable(self):
        for signature in self._vtable:
            print(f"{signature} registered")
        print()
