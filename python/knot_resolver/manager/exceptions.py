from knot_resolver import KresBaseException


class KresManagerException(KresBaseException):
    pass


class KresKafkaClientError(KresManagerException):
    pass
