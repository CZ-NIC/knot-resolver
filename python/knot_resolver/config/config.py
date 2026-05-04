from __future__ import annotations

from knot_resolver.utils.modeling import DataModel

from .templates import LOADER_TEMPLATE, WORKER_TEMPLATE


class KresConfig(DataModel):
    """ """

    def render_lua_worker(self) -> str:
        return WORKER_TEMPLATE.render(cfg=self)

    def render_lua_loader(self) -> str:
        return LOADER_TEMPLATE.render(cfg=self)
