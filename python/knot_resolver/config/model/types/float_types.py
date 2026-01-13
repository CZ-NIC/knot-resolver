from knot_resolver.utils.data_modeling.types import BaseFloatRange


class FloatNonNegative(BaseFloatRange):
    _min: float = 0.0
