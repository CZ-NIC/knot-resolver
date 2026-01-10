import asyncio
from asyncio import Lock
from typing import Any, Awaitable, Callable, List, Tuple

from knot_resolver.datamodel import KresConfig
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling.exceptions import DataParsingError
from knot_resolver.utils.modeling.types import NoneType

from .exceptions import KresManagerBaseError

VerifyCallback = Callable[[KresConfig, KresConfig, bool], Awaitable[Result[None, str]]]
UpdateCallback = Callable[[KresConfig, bool], Awaitable[None]]


class ConfigStore:
    def __init__(self, initial_config: KresConfig) -> None:
        self._config = initial_config
        self._verifiers: List[VerifyCallback] = []
        self._callbacks: List[UpdateCallback] = []
        self._update_lock: Lock = Lock()

    async def update(self, config: KresConfig, force: bool = False) -> None:
        # invoke pre-change verifiers
        results: Tuple[Result[None, str], ...] = tuple(
            await asyncio.gather(*[ver(self._config, config, force) for ver in self._verifiers])
        )
        err_res = filter(lambda r: r.is_err(), results)
        errs = list(map(lambda r: r.unwrap_err(), err_res))
        if len(errs) > 0:
            raise KresManagerBaseError("Configuration validation failed. The reasons are:\n - " + "\n - ".join(errs))

        async with self._update_lock:
            # update the stored config with the new version
            self._config = config

            # invoke change callbacks
            for call in self._callbacks:
                await call(config, force)

    async def renew(self, force: bool = False) -> None:
        await self.update(self._config, force)

    async def register_verifier(self, verifier: VerifyCallback) -> None:
        self._verifiers.append(verifier)
        res = await verifier(self.get(), self.get(), False)
        if res.is_err():
            raise DataParsingError(f"Initial config verification failed with error: {res.unwrap_err()}")

    async def register_on_change_callback(self, callback: UpdateCallback) -> None:
        """Register new callback and immediately call it with current config."""
        self._callbacks.append(callback)
        await callback(self.get(), False)

    def get(self) -> KresConfig:
        return self._config


def only_on_no_changes_update(selector: Callable[[KresConfig], Any]) -> Callable[[UpdateCallback], UpdateCallback]:
    def decorator(orig_func: UpdateCallback) -> UpdateCallback:
        original_value_set: Any = False
        original_value: Any = None

        async def new_func_update(config: KresConfig, force: bool = False) -> None:
            nonlocal original_value_set
            nonlocal original_value
            if not original_value_set:
                original_value_set = True
            elif original_value == selector(config):
                await orig_func(config, force)
            elif force:
                await orig_func(config, force)
            original_value = selector(config)

        return new_func_update

    return decorator


def only_on_real_changes_update(selector: Callable[[KresConfig], Any]) -> Callable[[UpdateCallback], UpdateCallback]:
    def decorator(orig_func: UpdateCallback) -> UpdateCallback:
        original_value_set: Any = False
        original_value: Any = None

        async def new_func_update(config: KresConfig, force: bool) -> None:
            nonlocal original_value_set
            nonlocal original_value
            if not original_value_set:
                original_value_set = True
                await orig_func(config, force)
            elif original_value != selector(config):
                await orig_func(config, force)
            elif force:
                await orig_func(config, force)
            original_value = selector(config)

        return new_func_update

    return decorator


def only_on_real_changes_verifier(selector: Callable[[KresConfig], Any]) -> Callable[[VerifyCallback], VerifyCallback]:
    def decorator(orig_func: VerifyCallback) -> VerifyCallback:
        original_value_set: Any = False
        original_value: Any = None

        async def new_func_verifier(old: KresConfig, new: KresConfig, force: bool) -> Result[NoneType, str]:
            nonlocal original_value_set
            nonlocal original_value
            if not original_value_set:
                original_value_set = True
                original_value = selector(new)
                await orig_func(old, new, force)
            elif original_value != selector(new):
                original_value = selector(new)
                await orig_func(old, new, force)
            return Result.ok(None)

        return new_func_verifier

    return decorator
