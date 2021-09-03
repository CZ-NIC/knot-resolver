import logging
import os
from typing import Union

from typing_extensions import Literal

from knot_resolver_manager.utils import DataParser, DataValidationException, DataValidator

logger = logging.getLogger(__name__)


def _cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (NotImplementedError, AttributeError):
        logger.warning(
            "The number of usable CPUs could not be determined using 'os.sched_getaffinity()'."
            "Attempting to get the number of system CPUs using 'os.cpu_count()'"
        )
        cpus = os.cpu_count()
        if cpus is None:
            raise DataValidationException(
                "The number of available CPUs to automatically set the number of running"
                "'kresd' workers could not be determined."
                "The number can be specified manually in 'server:instances' configuration option."
            )
        return cpus


class Server(DataParser):
    workers: Union[Literal["auto"], int] = 1
    use_cache_gc: bool = True


class ServerStrict(DataValidator):
    workers: int
    use_cache_gc: bool

    def _workers(self, obj: Server) -> int:
        if isinstance(obj.workers, int):
            return obj.workers
        elif obj.workers == "auto":
            return _cpu_count()
        raise DataValidationException(f"Unexpected value: {obj.workers}")

    def _validate(self) -> None:
        if self.workers < 0:
            raise DataValidationException("Number of workers must be non-negative")
