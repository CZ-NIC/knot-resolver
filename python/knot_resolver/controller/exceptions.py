from __future__ import annotations

from knot_resolver.exceptions import KresError


class ControllerError(KresError):
    """Class for all errors that are raised in the controller submodules."""


class ControllerNotifySocketError(ControllerError):
    """Class for notify socket errors."""

    def __init__(self, msg: str) -> None:
        msg = f"notify socket error: {msg}"
        super().__init__(msg)
