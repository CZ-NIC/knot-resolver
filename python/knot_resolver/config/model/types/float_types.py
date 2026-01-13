from knot_resolver.utils.modeling.types import BaseFloatRange


class FloatNonNegative(BaseFloatRange):
    _min: float = 0.0
