"""Implements JSON pointer resolution based on RFC 6901: https://www.rfc-editor.org/rfc/rfc6901."""

from typing import Any, Optional, Tuple, Union

JSONPtrAddressable = Any


class _JSONPtr:
    @staticmethod
    def _decode_token(token: str) -> str:
        """Resolve escaped characters ~ and /."""
        # the order of the replace statements is important, do not change without
        # consulting the RFC
        return token.replace("~1", "/").replace("~0", "~")

    @staticmethod
    def _encode_token(token: str) -> str:
        return token.replace("~", "~0").replace("/", "~1")

    def __init__(self, ptr: str) -> None:
        if ptr == "":
            # pointer to the root
            self.tokens = []

        else:
            if ptr[0] != "/":
                raise SyntaxError(
                    f"JSON pointer '{ptr}' invalid: the first character MUST be '/' or the pointer must be empty"
                )

            ptr = ptr[1:]
            self.tokens = [_JSONPtr._decode_token(tok) for tok in ptr.split("/")]

    def resolve(
        self, obj: JSONPtrAddressable
    ) -> Tuple[Optional[JSONPtrAddressable], JSONPtrAddressable, Union[str, int, None]]:
        parent: Optional[JSONPtrAddressable] = None
        current = obj
        current_ptr = ""
        token: Union[int, str, None] = None

        for token in self.tokens:
            if current is None:
                raise ValueError(
                    f"JSON pointer cannot reference nested non-existent object: object at ptr '{current_ptr}'"
                    f" already points to None, cannot nest deeper with token '{token}'"
                )

            if isinstance(current, (bool, int, float, str)):
                raise ValueError(f"object at '{current_ptr}' is a scalar, JSON pointer cannot point into it")

            parent = current
            if isinstance(current, list):
                if token == "-":
                    current = None
                else:
                    try:
                        token_num = int(token)
                        current = current[token_num]
                    except ValueError as e:
                        raise ValueError(
                            f"invalid JSON pointer: list '{current_ptr}' require numbers as keys, instead got '{token}'"
                        ) from e

            elif isinstance(current, dict):
                current = current.get(token, None)

            current_ptr += f"/{token}"

        return parent, current, token


def json_ptr_resolve(
    obj: JSONPtrAddressable,
    ptr: str,
) -> Tuple[Optional[JSONPtrAddressable], Optional[JSONPtrAddressable], Union[str, int, None]]:
    return _JSONPtr(ptr).resolve(obj)
