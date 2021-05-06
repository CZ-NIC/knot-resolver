from typing import Optional, Union

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.datamodel.types import TimeUnits
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin


@dataclass
class PredictionConfig(DataclassParserValidatorMixin):
    window: Optional[str] = None
    _window_seconds: int = 15 * TimeUnits.minute
    period: int = 24

    def __post_init__(self):
        if self.window:
            self._window_seconds = TimeUnits.parse(self.window)

    def get_window(self) -> int:
        return self._window_seconds

    def _validate(self):
        pass


@dataclass
class OptionsConfig(DataclassParserValidatorMixin):
    prediction: Union[bool, PredictionConfig] = False

    def __post_init__(self):
        if self.prediction is True:
            self.prediction = PredictionConfig()

    def _validate(self):
        pass
