from pathlib import Path

from knot_resolver.utils.modeling.validation_context import Context, set_global_validation_context

set_global_validation_context(Context(Path("."), False))
