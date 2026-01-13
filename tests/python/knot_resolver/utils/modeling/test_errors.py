import pytest

from knot_resolver.utils.modeling.errors import (
    AggrDataValidationError,
    DataAnnotationError,
    DataDescriptionError,
    DataModelingError,
    DataTypeError,
    DataValidationError,
    DataValueError,
)

errors = [
    DataModelingError("this is data modeling error message", "/error"),
    DataAnnotationError("this is annotation error message", "/annotation"),
    DataDescriptionError("this is description error message", "/description"),
    DataTypeError("this is type error message", "/type"),
    DataValueError("this is value error message", "/value"),
]


def test_data_validation_error() -> None:
    error_msg = """Data validation error detected:
    [/validation] this is validation error message
        [/error] this is data modeling error message
        [/annotation] annotation error: this is annotation error message
        [/description] description error: this is description error message
        [/type] type error: this is type error message
        [/value] value error: this is value error message"""

    with pytest.raises(DataValidationError) as error:
        raise DataValidationError("this is validation error message", "/validation", errors)
    assert str(error.value) == error_msg


def test_aggregate_data_validation_error() -> None:
    error_msg = """Data validation errors detected:
    [/error] this is data modeling error message
    [/annotation] annotation error: this is annotation error message
    [/description] description error: this is description error message
    [/type] type error: this is type error message
    [/value] value error: this is value error message"""

    with pytest.raises(AggrDataValidationError) as error:
        raise AggrDataValidationError("/", errors)
    assert str(error.value) == error_msg
