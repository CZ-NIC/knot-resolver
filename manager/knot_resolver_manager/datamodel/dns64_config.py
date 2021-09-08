from knot_resolver_manager.utils import DataParser, DataValidator


class Dns64(DataParser):
    prefix: str = "64:ff9b::"


class Dns64Strict(DataValidator):
    prefix: str

    def _validate(self):
        pass
