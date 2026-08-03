#!/usr/bin/env python3

import sys
from importlib.metadata import distributions

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

pyproject = sys.argv[1] if len(sys.argv) == 2 else "pyproject.toml"

with open(pyproject, "rb") as f:
    project = tomllib.load(f)["project"]

# strip version codes
deps = {
    canonicalize_name(Requirement(req).name)
    for req in project.get("dependencies", [])
}

# find out which packages are missing
installed = {
    canonicalize_name(name)
    for dist in distributions()
    if (name := dist.metadata.get("Name"))
}
missing = deps - installed

# fail if there are some missing
if missing:
    print(f"Some required packages are missing: {sorted(missing)}", file=sys.stderr)
    sys.exit(1)
