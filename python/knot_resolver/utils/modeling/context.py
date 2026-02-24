from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Strictness(IntEnum):
    """
    Data validation strictness.

    Attributes:
        PERMISSIVE: Validation that the input data corresponds to the structure of the data model.
        BASIC: PERMISSIVE validation plus validation of input data types and values.
        NORMAL: BASIC validation plus validation of the context between individual parts of the data.
            For example, mutually exclusive values.
        STRICT: NORMAL validation plus validation of things outside the data.
            For example, checking the existence of file/directory.
    """

    PERMISSIVE = 1
    BASIC = 2
    NORMAL = 3
    STRICT = 4


@dataclass
class Context:
    """
    Base validation context for data validation operations.

    Attributes:
        username: The user name for which permissions are to be checked.
        groupname: The group name for which permissions are to be checked.
        strictness: Level of data validation strictness.
    """

    username: str | None = None
    groupname: str | None = None
    strictness: Strictness = Strictness.NORMAL
