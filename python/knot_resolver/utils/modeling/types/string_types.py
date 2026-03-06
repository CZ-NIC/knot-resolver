from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, ClassVar

from knot_resolver.utils.modeling.context import Strictness
from knot_resolver.utils.modeling.errors import DataValueError

from .base_string_types import BaseString, BaseStringLength, BaseStringPattern, BaseUnit
from .integer_types import PortNumber

if TYPE_CHECKING:
    from knot_resolver.utils.modeling.context import Context


class EscapedString(BaseString):
    """A string where escape sequences are ignored and quotes are escaped."""

    def _escape(self) -> str:
        escaped_chars = {
            "'": r"\'",
            '"': r"\"",
            "\a": r"\a",
            "\n": r"\n",
            "\r": r"\r",
            "\t": r"\t",
            "\b": r"\b",
            "\f": r"\f",
            "\v": r"\v",
            "\0": r"\0",
        }

        s = list(self._value)
        for i, c in enumerate(self._value):
            if c in escaped_chars:
                s[i] = escaped_chars[c]
            elif not c.isalnum():
                s[i] = repr(c)[1:-1]
        return "".join(s)

    def escaped(self) -> str:
        return self._escape()

    def validate(self, context: Context) -> None:
        super().validate(context)
        _ = self._escape()

    def multiline(self) -> str:
        """
        Lua multiline string is enclosed in double square brackets '[[ ]]'.

        This method makes sure that double square brackets are escaped.
        """
        replace = {
            "[[": r"\[\[",
            "]]": r"\]\]",
        }

        ml = self._orig_value
        for s, r in replace.items():
            ml = ml.replace(s, r)
        return ml


class EscapedStringMin32B(EscapedString, BaseStringLength):
    _min_bytes: int = 32


class SizeUnit(BaseUnit):
    _units: ClassVar[dict[str, int]] = {
        "B": 1,
        "K": 1024,
        "M": 1024**2,
        "G": 1024**3,
    }

    def bytes(self) -> int:
        return int(self.get_base_value())

    def mbytes(self) -> int:
        return int(self.get_base_value() // 1024**2)


class TimeUnit(BaseUnit):
    _units: ClassVar[dict[str, int]] = {
        "us": 1,
        "ms": 10**3,
        "s": 10**6,
        "m": 60 * 10**6,
        "h": 3600 * 10**6,
        "d": 24 * 3600 * 10**6,
    }

    def minutes(self) -> int:
        return int(self.get_base_value() // 1000**2 // 60)

    def seconds(self) -> int:
        return int(self.get_base_value() // 1000**2)

    def millis(self) -> int:
        return int(self.get_base_value() // 1000)

    def micros(self) -> int:
        return int(self.get_base_value())


class DomainName(BaseStringPattern):
    # fmt: off
    _re = re.compile(
        r"(?=^.{,253}\.?$)"  # max 253 chars
        r"(^"
            # do not allow hyphen at the start and at the end of label
            r"(?!-)[^.]{,62}[^.-]"  # max 63 chars in label; except dot
            r"(\.(?!-)[^.]{,62}[^.-])*"  # start with dot; max 63 chars in label except dot
            r"\.?"  # end with or without dot
        r"$)"
        r"|^\.$",  # allow root-zone
    )
    # fmt: on

    def __hash__(self) -> int:
        return hash(self._value) if self._value.endswith(".") else hash(f"{self._value}.")

    def _punycode(self) -> str:
        return self._value.encode("idna").decode("utf-8") if self._value != "." else "."

    def validate(self, context: Context) -> None:
        super().validate(context)

        if context.strictness > Strictness.PERMISSIVE:
            try:
                punycode = self._punycode()
            except ValueError as e:
                msg = (f"conversion of '{self._value}' to IDN punycode representation failed",)
                raise DataValueError(msg, self._tree_path) from e

            if not type(self)._re.match(punycode):  # noqa: SLF001
                msg = (
                    f"'{self._value}' represented in punycode '{punycode}' does not match '{self._re.pattern}' pattern"
                )
                raise DataValueError(
                    msg,
                    self._tree_path,
                )

    def punycode(self) -> str:
        return self._punycode()


class InterfaceName(BaseStringPattern):
    """Network interface name."""

    _re = re.compile(r"^[a-zA-Z0-9]+(?:[-_][a-zA-Z0-9]+)*$")


class PinSha256(BaseStringPattern):
    """A string that represents base64 encoded sha256 hash."""

    _re = re.compile(r"^[A-Za-z\d+/]{43}=$")


class InterfaceNameIPAddressPort(BaseString):
    """"""

    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    interface_name: InterfaceName | None = None
    port: PortNumber | None = None

    def validate(self, context: Context) -> None:
        super().validate(context)

        if context.strictness > Strictness.PERMISSIVE:
            if "@" not in self._value:
                msg = f"expected '<interface-name|ip-address>@<port>', got '{self._value}'."
                raise DataValueError(msg, self._tree_path)

            splited = self._value.split("@", 1)

            try:
                self.ip_address = ipaddress.ip_address(splited[0])
            except ValueError as e1:
                try:
                    self.interface_name = InterfaceName(splited[0])
                except DataValueError as e2:
                    msg = f"expected IP address or interface name, got '{splited[0]}'."
                    raise DataValueError(msg) from (e1 and e2)
            self.port = PortNumber.from_string(splited[1], self._tree_path)


class InterfaceNameIPAddressOptionalPort(BaseString):
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    interface_name: InterfaceName | None = None
    port: PortNumber | None = None

    def validate(self, context: Context) -> None:
        super().validate(context)

        if context.strictness > Strictness.PERMISSIVE:
            interface_name_ip_address = self._value
            if "@" in self._value:
                splited = self._value.split("@")
                interface_name_ip_address = splited[0]

                port = PortNumber.from_string(splited[1], self._tree_path)
                port.validate(context)
                self.port = port
            try:
                self.ip_address = ipaddress.ip_address(interface_name_ip_address)
            except ValueError as e1:
                try:
                    interface_name = InterfaceName(interface_name_ip_address)
                    interface_name.validate(context)
                    self.interface_name = interface_name
                except DataValueError as e2:
                    msg = f"expected IP address or interface name, got '{splited[0]}'."
                    raise DataValueError(msg, self._tree_path) from (e1 and e2)
