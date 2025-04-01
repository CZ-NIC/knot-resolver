import os
import sys

from jinja2 import Environment, FileSystemLoader, StrictUndefined, Template


def _get_templates_dir() -> str:
    module = sys.modules["knot_resolver.datamodel"].__file__
    if module:
        templates_dir = os.path.join(os.path.dirname(module), "templates")
        if os.path.isdir(templates_dir):
            return templates_dir
        raise NotADirectoryError(f"the templates dir '{templates_dir}' is not a directory or does not exist")
    raise OSError("package 'knot_resolver.datamodel' cannot be located or loaded")


_TEMPLATES_DIR = _get_templates_dir()


def _import_kresd_worker_config_template() -> Template:
    path = os.path.join(_TEMPLATES_DIR, "worker-config.lua.j2")
    with open(path, "r", encoding="UTF-8") as file:
        template = file.read()
    return template_from_str(template)


def _import_kresd_policy_config_template() -> Template:
    path = os.path.join(_TEMPLATES_DIR, "policy-config.lua.j2")
    with open(path, "r", encoding="UTF-8") as file:
        template = file.read()
    return template_from_str(template)


def template_from_str(template: str) -> Template:
    ldr = FileSystemLoader(_TEMPLATES_DIR)
    env = Environment(trim_blocks=True, lstrip_blocks=True, loader=ldr, undefined=StrictUndefined)
    return env.from_string(template)


WORKER_CONFIG_TEMPLATE = _import_kresd_worker_config_template()


POLICY_CONFIG_TEMPLATE = _import_kresd_policy_config_template()
