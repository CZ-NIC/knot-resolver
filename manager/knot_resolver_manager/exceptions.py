class SubprocessControllerException(Exception):
    pass


class ValidationException(Exception):
    pass


class SchemaValidationException(ValidationException):
    pass


class DataValidationException(ValidationException):
    pass
