from typing import Any, Dict

from setuptools import Extension


def build(setup_kwargs: Dict[Any, Any]) -> None:
    setup_kwargs.update(
        {
            "ext_modules": [
                Extension(
                    name="knot_resolver_manager.kresd_controller.supervisord.plugin.notify",
                    sources=["knot_resolver_manager/kresd_controller/supervisord/plugin/notifymodule.c"],
                ),
            ]
        }
    )
