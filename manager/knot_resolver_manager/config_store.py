import asyncio
from asyncio import Lock
from typing import Any, Awaitable, Callable, List, Tuple

from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.exceptions import DataException, KresManagerException
from knot_resolver_manager.utils.functional import Result

VerifyCallback = Callable[[KresConfig, KresConfig], Awaitable[Result[None, str]]]
UpdateCallback = Callable[[KresConfig], Awaitable[None]]


class ConfigStore:
    def __init__(self, initial_config: KresConfig):
        self._config = initial_config
        self._verifiers: List[VerifyCallback] = []
        self._callbacks: List[UpdateCallback] = []
        self._update_lock: Lock = Lock()

    async def update(self, config: KresConfig):
        # invoke pre-change verifiers
        results: Tuple[Result[None, str], ...] = await asyncio.gather(
            *[ver(self._config, config) for ver in self._verifiers]
        )
        err_res = filter(lambda r: r.is_err(), results)
        errs = list(map(lambda r: r.unwrap_err(), err_res))
        if len(errs) > 0:
            raise KresManagerException("Validation of the new config failed. The reasons are:", *errs)

        async with self._update_lock:
            # update the stored config with the new version
            self._config = config

            # invoke change callbacks
            for call in self._callbacks:
                await call(config)

    async def register_verifier(self, verifier: VerifyCallback):
        self._verifiers.append(verifier)
        res = await verifier(self.get(), self.get())
        if res.is_err():
            raise DataException(f"Initial config verification failed with error: {res.unwrap_err()}")

    async def register_on_change_callback(self, callback: UpdateCallback):
        """
        Registers new callback and immediatelly calls it with current config
        """

        self._callbacks.append(callback)
        await callback(self.get())

    def get(self) -> KresConfig:
        return self._config


def only_on_real_changes(selector: Callable[[KresConfig], Any]) -> Callable[[UpdateCallback], UpdateCallback]:
    def decorator(orig_func: UpdateCallback) -> UpdateCallback:
        original_value_set: Any = False
        original_value: Any = None

        async def new_func(config: KresConfig):
            nonlocal original_value_set
            nonlocal original_value
            if not original_value_set:
                original_value_set = True
                original_value = selector(config)
                await orig_func(config)
            elif original_value != selector(config):
                original_value = selector(config)
                await orig_func(config)

        return new_func

    return decorator
