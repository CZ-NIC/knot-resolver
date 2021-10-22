import asyncio
from asyncio import Lock
from typing import Awaitable, Callable, List, Tuple

from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.exceptions import DataException, KresdManagerException
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
            raise KresdManagerException("Validation of the new config failed. The reasons are:", *errs)

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
