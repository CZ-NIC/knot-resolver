#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os.path
from pathlib import Path
import subprocess
import sys
import tempfile
import argparse


DISTROS_PATH = Path(os.path.realpath('scripts/distros'))
GEN_SCRIPT = Path(os.path.realpath('scripts/dockerfile_gen.py'))


def unpack(archive, targetdir):
    '''
    Prepare workdir for Docker build by unpacking fresh distribution tarball
    '''
    logging.debug('unpacking fresh tarball %s into %s', archive, targetdir)
    subprocess.check_call(['tar', '-C', targetdir, '-xf', archive])


def fresh_tarball():
    try:
        # make archive so we have clean state to test
        archive = subprocess.check_output('scripts/make-archive.sh')
    except subprocess.CalledProcessError as ex:
        logging.fatal('failed to generate fresh tarball: %s', ex.output)
        sys.exit(ex.returncode)
    return os.path.realpath(archive.strip())


def get_distro_vers(distro_root):
    '''
    return list of (distro, version) pairs found in distro_root
    '''
    # transform list of paths like TOP/debian/9 into (debian, 9)
    dist_ver = [p.parts[-2:] for p
                in Path(distro_root).glob('*/*') if p.is_dir()]
    return list(dist_ver)


def get_components(root):
    cmpl = [os.path.relpath(dirn, start=root)  # relative names only
            for dirn, _, _ in os.walk(root)
            if (os.path.basename(dirn) == 'packaging'  # path ends with
                and 'contrib' not in Path(dirn).parts)]  # ignore contrib libs
    return list(cmpl)


def test_combinations(distro_vers, components):
    tests = []
    for distro, ver in distro_vers:
        for comp in components:
            comps = ['scripts/distros', 'daemon/packaging']   # always include daemon
            if comp not in comps:
                comps.append(comp)
            tests.append([distro, ver, *comps])
    tests.sort()
    return tests


def gen_dockerfile(args, tmpdir, srcdir):
    subprocess.check_call([GEN_SCRIPT,
                          '--srcdir={}'.format(srcdir)]  # dir in tar
                          + args,
                          stdout=open(tmpdir / 'Dockerfile', 'w'))


def docker_build(tmpdir, delete):
    subprocess.check_call(
        ['docker',
         'build',
         '--rm={}'.format(str(delete).lower()),
         '--network',
         'host',
         tmpdir]
    )


def find_test(required_tests, test_combination):
    '''
    Find test in test_combination in required_tests list
    '''
    for test in required_tests:
        if test_combination[len(test_combination)-1] == test[0]:
            return True

    return False


def main():
    logging.basicConfig(level=logging.DEBUG)

    argparser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='''Find all tests in current directory, generate Dockerfiles and run all Dockerfiles one by one.
'''.format(n=sys.argv[0])
        )
    argparser.add_argument(
        '-t', '--test', action='append', nargs=1, help='Select one test to run')
    argparser.add_argument(
        '-l', '--list', action='store_true', help='Show all available tests')

    params = argparser.parse_args()

    distro_vers = get_distro_vers(DISTROS_PATH)
    components = get_components('.')
    logging.info('generating fresh tarball')
    archive = fresh_tarball()
    logging.debug('generated tarball %s', archive)
    # transform knot-resolver-1.5.0-70-gf1dbebdc.tar.xz -> knot-resolver-1.5.0-70-gf1dbebdc
    srcdir = os.path.basename(archive).decode('ascii').rsplit('.', maxsplit=2)[0]
    logging.debug('expected dir name in tarball: %s', srcdir)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        unpack(archive, tmpdir)
        baseimg = True  # do not delete first image - it works as cache
        if params.list:
            print('Available tests: ')
        # all tests
        for args in test_combinations(distro_vers, components):
            if params.list:
                print('\t' + args[len(args)-1])
                continue
            if params.test:
                if not find_test(params.test, args):
                    logging.debug('skip test for %s', args)
                    continue

            logging.debug('generating Dockerfile for %s', args)
            gen_dockerfile(args, tmpdir, srcdir)
            logging.info('testing combination %s', args)
            docker_build(tmpdir, delete=not baseimg)
            baseimg = False


if __name__ == '__main__':
    main()
