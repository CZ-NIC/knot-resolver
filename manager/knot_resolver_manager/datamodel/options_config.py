from typing import Union

from knot_resolver_manager.utils import DataParser, DataValidator
from knot_resolver_manager.utils.types import LiteralEnum

from .types import TimeUnit

GlueCheckingEnum = LiteralEnum["normal", "strict", "permissive"]


class Prediction(DataParser):
    window: TimeUnit = TimeUnit("15m")
    period: int = 24


class Options(DataParser):
    glue_checking: GlueCheckingEnum = "normal"
    qname_minimisation: bool = True
    query_loopback: bool = False
    reorder_rrset: bool = True
    query_case_randomization: bool = True
    query_priming: bool = True
    rebinding_protection: bool = False
    refuse_no_rd: bool = True
    time_jump_detection: bool = True
    violators_workarounds: bool = False
    serve_stale: bool = False

    prediction: Union[bool, Prediction] = False


class PredictionStrict(DataValidator):
    window: int
    period: int

    def _validate(self) -> None:
        pass


class OptionsStrict(DataValidator):
    glue_checking: GlueCheckingEnum
    qname_minimisation: bool
    query_loopback: bool
    reorder_rrset: bool
    query_case_randomization: bool
    query_priming: bool
    rebinding_protection: bool
    refuse_no_rd: bool
    time_jump_detection: bool
    violators_workarounds: bool
    serve_stale: bool

    prediction: Union[bool, PredictionStrict]

    def _prediction(self, obj: Options) -> Union[bool, Prediction]:
        if obj.prediction is True:
            return Prediction()
        return obj.prediction

    def _validate(self) -> None:
        pass
