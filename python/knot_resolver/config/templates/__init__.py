from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, Template


def _get_templates_path() -> Path:
    templates_path = Path(__file__).resolve().parent
    if not templates_path.exists():
        raise FileNotFoundError(templates_path)
    if not templates_path.is_dir():
        raise NotADirectoryError(templates_path)
    return templates_path


_TEMPLATES_PATH: Path = _get_templates_path()


def _load_template_from_str(template: str) -> Template:
    loader = FileSystemLoader(_TEMPLATES_PATH)
    env = Environment(trim_blocks=True, lstrip_blocks=True, loader=loader, undefined=StrictUndefined)  # noqa: S701
    return env.from_string(template)


def _import_template(template: str) -> Template:
    template_file = _TEMPLATES_PATH / template
    with template_file.open() as file:
        template = file.read()
    return _load_template_from_str(template)


WORKER_TEMPLATE: Template = _import_template("worker.lua.j2")

POLICY_LOADER_TEMPLATE: Template = _import_template("policy-loader.lua.j2")
