import pytest

from knot_resolver_manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver_manager.datamodel.config_schema import KresConfig


@pytest.mark.asyncio  # type: ignore
async def test_only_once():
    count = 0

    @only_on_real_changes_update(lambda config: config.logging.level)
    async def change_callback(config: KresConfig) -> None:
        nonlocal count
        count += 1

    config = KresConfig()
    store = ConfigStore(config)

    await store.register_on_change_callback(change_callback)
    assert count == 1

    config = KresConfig()
    config.logging.level = "crit"
    await store.update(config)
    assert count == 2

    config = KresConfig()
    config.lua.script_only = True
    config.lua.script = "meaningless value"
    await store.update(config)
    assert count == 2
