from typing import Any, Union

from typing_extensions import Literal

from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

from .types import TimeUnit

GlueCheckingEnum = LiteralEnum["normal", "strict", "permissive"]


class Prediction(SchemaNode):
    window: TimeUnit = TimeUnit("15m")
    period: int = 24


class Options(SchemaNode):
    class Raw(SchemaNode):
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

    _PREVIOUS_SCHEMA = Raw

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
    prediction: Union[Literal[False], Prediction]

    def _prediction(self, obj: Raw) -> Any:
        if obj.prediction is True:
            return Prediction()
        return obj.prediction
