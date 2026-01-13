# ruff: noqa: N801

from knot_resolver.utils.modeling.types import BaseIntegerRange


class Integer0_32(BaseIntegerRange):
    _min: int = 0
    _max: int = 32


class Integer0_512(BaseIntegerRange):
    _min: int = 0
    _max: int = 512


class Integer0_65535(BaseIntegerRange):
    _min: int = 0
    _max: int = 65_535


class IntegerNonNegative(BaseIntegerRange):
    _min: int = 0


class IntegerPositive(BaseIntegerRange):
    _min: int = 1


class Percent(BaseIntegerRange):
    _min: int = 0
    _max: int = 100


class PortNumber(BaseIntegerRange):
    _min: int = 1
    _max: int = 65_535
