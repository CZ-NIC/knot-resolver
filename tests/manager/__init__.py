from pathlib import Path

from knot_resolver.datamodel.globals import Context, set_global_validation_context

set_global_validation_context(Context(Path("."), False))
