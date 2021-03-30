from typing import Any, Callable, Dict, Generic, Tuple, Type, TypeVar, overload

T = TypeVar("T")

class OverloadedFunctionException(Exception): pass

class overloaded(Generic[T]):
    def __init__(self):
        self.vtable: Dict[Tuple[Any], Callable[..., T]] = {}
    
    def add(self, *args: Type[Any], **kwargs: Type[Any]) -> Callable[[Callable[..., T]], Callable[..., T]]:
        if len(kwargs) != 0:
            raise OverloadedFunctionException("Sorry, named arguments are not supported. You can however implement them and make them functional... ;)")

        def wrapper(func: Callable[...,T]) -> Callable[...,T]:
            signature = tuple(args)
            self.vtable[signature] = func
            def inner_wrapper(*args: Any, **kwargs: Any) -> T:
                return self(*args, **kwargs)
            return inner_wrapper
        return wrapper
    
    def __call__(self, *args: Any, **kwargs: Any) -> T:
        if len(kwargs) != 0:
            raise OverloadedFunctionException("Sorry, named arguments are not supported. You can however implement them and make them functional... ;)")

        signature = tuple(type(a) for a in args)
        if signature not in self.vtable:
            raise OverloadedFunctionException(f"Function overload with signature {signature} is not registered and can't be called.")
        return self.vtable[signature](*args)