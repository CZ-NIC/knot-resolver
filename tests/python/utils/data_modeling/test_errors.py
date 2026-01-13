import pytest

from knot_resolver.utils.data_modeling.errors import AggregateDataValidationError, DataValidationError


def test_data_validation_error() -> None:
    error_msg = """Configuration validation error detected:
    [/error] this is testing error"""

    with pytest.raises(DataValidationError) as error:
        raise DataValidationError("this is testing error", "/error")

    assert str(error.value) == error_msg


def test_data_validation_error_child() -> None:
    errors = [
        DataValidationError("this is testing error1", "/error1"),
        DataValidationError("this is testing error2", "/error2"),
    ]

    error_msg = """Configuration validation error detected:
    [/] this is testing error
        [/error1] this is testing error1
        [/error2] this is testing error2"""

    with pytest.raises(DataValidationError) as error:
        raise DataValidationError("this is testing error", "/", errors)

    assert str(error.value) == error_msg


def test_aggregate_data_validation_error() -> None:
    errors = [
        DataValidationError("this is testing error1", "/error1"),
        DataValidationError("this is testing error2", "/error2"),
    ]

    error_msg = """Configuration validation errors detected:
    [/error1] this is testing error1
    [/error2] this is testing error2"""

    with pytest.raises(AggregateDataValidationError) as error:
        raise AggregateDataValidationError("/", errors)

    assert str(error.value) == error_msg
