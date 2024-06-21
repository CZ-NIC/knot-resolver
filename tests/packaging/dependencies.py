#!/usr/bin/python3

import importlib
import importlib.util
import sys
from types import ModuleType

import pkg_resources

# replace imports with mocks
dummy = ModuleType("dummy")
dummy.__dict__["setup"] = lambda *args, **kwargs: None
dummy.__dict__["build"] = lambda *args, **kwargs: None
sys.modules["setuptools"] = dummy
sys.modules["build_c_extensions"] = dummy

# load install_requires array from setup.py
spec = importlib.util.spec_from_file_location("setup", sys.argv[1] if len(sys.argv) == 2 else "setup.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
install_requires = mod.install_requires

# strip version codes
deps = set((x[: x.index(">")].lower() if ">" in x else x.lower() for x in install_requires))

# find out which packages are missing
installed = {pkg.key for pkg in pkg_resources.working_set}
missing = deps - installed

# fail if there are some missing
if len(missing) > 0:
    print(f"Some required packages are missing: {missing}", file=sys.stderr)
    exit(1)
