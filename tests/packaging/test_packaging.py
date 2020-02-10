import os
import pytest
from pathlib import Path

EXCLUDED_TEST_DIRS = [ "tests", "daemon" ]

PYTESTS_DIR = os.path.dirname(os.path.realpath(__file__))
ROOT_DIR = os.path.join(PYTESTS_DIR, "..", "..")

def list_dirs(path, include=None, exclude=None):
    filtered_dirs = []
    root_depth = path.count(os.path.sep)

    for rootpath, dirs, files in os.walk(path):
        if exclude is not None:
            dirs[:] = [d for d in dirs if d not in exclude]

        for d in dirs:
            if include is None:
                filtered_dirs.append(os.path.join(rootpath, d))
            else:
                if os.path.basename(os.path.normpath(d)) in include:
                    filtered_dirs.append(os.path.join(rootpath, d))

    return filtered_dirs

def list_tests_dirs():
    return list_dirs(ROOT_DIR, ["packaging"], EXCLUDED_TEST_DIRS)


def list_distro_vers(distro_root):
    '''
    return list of (distro, version) pairs found in distro_root
    '''
    # transform list of paths like TOP/debian/9 into (debian, 9)

    dist_ver = [p.parts[-2:] for p
                in Path(distro_root).glob('*/*') if p.is_dir()]
    return list(dist_ver)


def read_deps(deps_file):
    listf = None

    try:
        with open(deps_file, "r") as f:
            listf = f.read().splitlines()
    except FileNotFoundError:
        pass

    return listf


MODULES=list_tests_dirs()
DISTROS=list_distro_vers(os.path.join(ROOT_DIR, "tests/packaging/distros"))

@pytest.mark.parametrize('module', MODULES)
@pytest.mark.parametrize('distro', DISTROS)
def test_collect(module, distro):
    distro_dir = os.path.join(module, distro[0], distro[1])

    if os.path.isdir(distro_dir):
        bdeps = read_deps(distro_dir + "/builddeps")
        rdeps = read_deps(distro_dir + "/rundeps")
        print(bdeps)
        print(rdeps)
        assert True

    # main docker containers based on daemon/packaging will be created in pytest_sessionstart hook

    # 1) Install builddeps into main docker container and build kresd
    # 2) Get binary and config files from container 1)
    # 3) Remove container 1)
    # 4) Install rundeps into main docker container
    # 5) Move binary and config files into container 4)
    # 6) Run test
    # 7) Collect results and remove container 4)

    # NOTE: Depending on the distribution, it must be decided which commands to use for install/remove
    # packages, build etc. How?

