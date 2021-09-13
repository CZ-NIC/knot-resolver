from knot_resolver_manager.datamodel.types import IPv6Network96
from knot_resolver_manager.utils import DataParser, DataValidator


class Dns64(DataParser):
    prefix: IPv6Network96 = IPv6Network96("64:ff9b::/96")


class Dns64Strict(DataValidator):
    prefix: IPv6Network96

    def _validate(self):
        pass
