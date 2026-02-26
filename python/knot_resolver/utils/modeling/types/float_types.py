from __future__ import annotations

from .base_float_types import BaseFloatRange


class FloatNonNegative(BaseFloatRange):
    _min: float = 0.0
