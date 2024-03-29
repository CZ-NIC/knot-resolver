import os
import sys

from jinja2 import Environment, FileSystemLoader, Template


def _get_templates_dir() -> str:
    module = sys.modules["knot_resolver_manager.datamodel"].__file__
    if module:
        templates_dir = os.path.join(os.path.dirname(module), "templates")
        if os.path.isdir(templates_dir):
            return templates_dir
        raise NotADirectoryError(f"the templates dir '{templates_dir}' is not a directory or does not exist")
    raise OSError("package 'knot_resolver_manager.datamodel' cannot be located or loaded")


_TEMPLATES_DIR = _get_templates_dir()


def _import_main_template() -> Template:
    path = os.path.join(_TEMPLATES_DIR, "config.lua.j2")
    with open(path, "r", encoding="UTF-8") as file:
        template = file.read()
    return template_from_str(template)


def template_from_str(template: str) -> Template:
    ldr = FileSystemLoader(_TEMPLATES_DIR)
    env = Environment(trim_blocks=True, lstrip_blocks=True, loader=ldr)
    return env.from_string(template)


MAIN_TEMPLATE = _import_main_template()
