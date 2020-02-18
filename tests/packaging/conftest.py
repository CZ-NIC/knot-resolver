
import pytest
import py
import os
import tempfile
import subprocess
from pathlib import Path


def pytest_configure(config):
    print("MAIN hook configure")
#    print("\n--> KR_TARBALLDIR: " + str(pytest.KR_TARBALLDIR))
    pytest.KR_PYTESTS_DIR = os.path.dirname(os.path.realpath(__file__))
    pytest.KR_ROOT_DIR = os.path.join(pytest.KR_PYTESTS_DIR, "..", "..")
    pytest.KR_PREFIX = "kr-packaging-tests-"


def fresh_tarball():
    try:
        # make archive so we have clean state to test
        archive = subprocess.check_output('scripts/make-archive.sh')
    except subprocess.CalledProcessError as ex:
        logging.fatal('failed to generate fresh tarball: %s', ex.output)
        sys.exit(ex.returncode)
    return os.path.realpath(archive.strip())


def unpack_tarball(archive, targetdir):
    '''
    Prepare workdir for Docker build by unpacking fresh distribution tarball
    '''
#    logging.debug('unpacking fresh tarball %s into %s', archive, targetdir)
    subprocess.check_call(['tar', '-C', targetdir, '-xf', archive])

#@pytest.hookimpl()
#def pytest_collection(session: pytest.Session):
#    print("MAIN hook collection")
#    list_packaging_dirs(ROOT_DIR)


@pytest.fixture(scope='session')
def config(tmpdir_factory):
    archive = fresh_tarball()
    # transform knot-resolver-1.5.0-70-gf1dbebdc.tar.xz -> knot-resolver-1.5.0-70-gf1dbebdc
    pytest.KR_TARBALLDIR = tmpdir_factory.mktemp("tarball")
    unpack_tarball(archive, pytest.KR_TARBALLDIR)
    pytest.KR_TARBALLDIR = pytest.KR_TARBALLDIR.join(os.path.basename(archive).decode('ascii').rsplit('.', maxsplit=2)[0])


#@pytest.hookimpl()
#def pytest_runtest_setup():
#    print("Hook runtest setup")
