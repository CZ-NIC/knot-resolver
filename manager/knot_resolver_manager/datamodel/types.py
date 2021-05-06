import re

from .errors import DataValidationError

RE_IPV6_PREFIX_96 = re.compile(r"^([0-9A-Fa-f]{1,4}:){2}:$")


class TimeUnits:
    second = 1
    minute = 60
    hour = 3600
    day = 24 * 3600

    _re = re.compile(r"^(\d+)\s{0,1}([smhd]){0,1}$")
    _map = {"s": second, "m": minute, "h": hour, "d": day}

    @staticmethod
    def parse(time_str: str) -> int:
        searched = TimeUnits._re.search(time_str)
        if searched:
            value, unit = searched.groups()
            return int(value) * TimeUnits._map.get(unit, 1)
        raise DataValidationError(f"failed to parse: {time_str}")


class SizeUnits:
    byte = 1
    kibibyte = 1024
    mebibyte = 1024 ** 2
    gibibyte = 1024 ** 3

    _re = re.compile(r"^([0-9]+)\s{0,1}([BKMG]){0,1}$")
    _map = {"B": byte, "K": kibibyte, "M": mebibyte, "G": gibibyte}

    @staticmethod
    def parse(size_str: str) -> int:
        searched = SizeUnits._re.search(size_str)
        if searched:
            value, unit = searched.groups()
            return int(value) * SizeUnits._map.get(unit, 1)
        raise DataValidationError(f"failed to parse: {size_str}")
