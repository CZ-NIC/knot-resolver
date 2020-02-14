#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
'''
Generate minimal Dockefile to build, install, run, and test kresd and modules.

It merges data from two sources:

1. Distribution specific commands for package installation etc.
   These come from distros/ subtree with two-level hierarchy:
   <distribution name>/<distribution version>
   The name and version must match respective names of Docker images.

2. Component-specific data like build and run-time dependencies etc.
   These come from packaging/ subtree of particular component.
   E.g. data for "daemon" component are in subtree daemon/packaging/.
   The structure again has structure
   <distribution name>/<distribution version>.
   Files common for all distributions (like tests) are right in
   in packaging/ directory of given component.
'''

import argparse
import logging
from pathlib import Path
import os
import sys


class TestEnv():
    '''
    Abstract way to schedule commands using different interpreters

    Reformat commands for different interpreters, e.g. Dockerfile, BASH, etc.
    '''
    def __init__(self, image):
        self.image = image

    def load_image(self):
        raise NotImplementedError()

    def run_cmds(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class DockerBuildEnv(TestEnv):
    '''
    Schedule commands as part of Docker build (Dockerfile)
    '''
    def __init__(self, image, srcdir):
        super().__init__(image)
        self.header = 'WORKDIR /root\nCOPY {} /root\n'.format(srcdir)

    def load_image(self):
        return 'FROM {0}:{1}\n'.format(self.image.name, self.image.version)

    def run_cmds(self):
        return '\n'.join('RUN {0}'.format(cmd) for cmd in self.image.cmds)

    def __str__(self):
        return self.load_image() + self.header + self.run_cmds()


class Image():
    '''
    Abstraction to hide differences between distributions and their versions
    '''
    def __init__(self, img_path, name, version):
        self.img_path = img_path  # scripts/distros/debian/9
        self.img_relpath = os.path.join(name, version)  # debian/9
        self.name = name
        self.version = version
        self.actions = {}
        self.cmds = []
        self._init_cmds()
        # fill in Dockerfile with image preparation commands

    def _img_path(self, filename):
        '''Prepend distro-specific path before filename'''
        return os.path.join(self.img_path, filename)

    def _init_cmds(self):
        '''
        Read commands for image modification from
        '''
        for cmd in os.listdir(self.img_path):
            if cmd == 'prep':  # multi-line commands are handled somewhere else
                continue
            with open(self._img_path(cmd)) as cmdfile:
                self.actions[cmd] = cmdfile.read().strip()

    def __str__(self):
        return '# image: {0}:{1}\n'.format(self.name, self.version) + '\n'.join(self.cmds)

    def action(self, action, arg):
        '''
        Schedule action with given argument, e.g. install package

        E.g. action "pkg_install" with argument "gcc" will schedule command
        read from image-specific file "distro/version/pkg_install" and append
        argument "arg". Result is like "apt-get install -y gcc".
        '''
        self.cmds.append('{0} {1}'.format(self.actions[action], arg))

    def action_arglist(self, action, cmpimgpath, filename):
        '''
        Plan single command with argumets equal to content of given text file
        '''
        try:
            with open(os.path.join(cmpimgpath, filename)) as listf:
                self.action(action, ' '.join(item.strip() for item in listf))
        except FileNotFoundError:
            pass

    def cmd(self, cmd):
        '''Schedule single command'''
        assert cmd
        self.cmds.append(cmd)

    def run_script(self, script):
        '''Shedule script from root directory'''
        if os.path.isfile(script):
            self.cmds.append(script)

    def img_script(self, script):
        '''Schedule script from image's directory'''
        path = self._img_path(script)
        assert os.path.isfile(path)
        self.run_script(path)


class Component():
    '''
    API for single component of software (daemon etc.) independent on image

    comp_path must contain subtree <distribution name>/<distribution version>
    with files containing command specific for particular distribution

    image must be Image to work with
    '''
    def __init__(self, comp_path, image):
        self.comp_path = comp_path
        self.compimg_path = os.path.join(comp_path, image.img_relpath)
        self.image = image
        # Some components do not have external depedencies at the moment so
        # compimg_path may not exist. That is okay, we will just run their tests.

    def _comp_script(self, script):
        path = os.path.join(self.comp_path, script)
        if os.path.exists(path):
            self.image.cmd(path)

    def install_builddeps(self):
        self.image.run_script(self.compimg_path + '/pre-build.sh')
        self.image.action_arglist('pkg_install', self.compimg_path, 'builddeps')

    def build(self):
        self.image.run_script(self.compimg_path + '/build.sh')

    def install(self):
        self.image.run_script(self.compimg_path + '/install.sh')

    def remove_builddeps(self):
        self.image.action_arglist('pkg_remove', self.compimg_path, 'builddeps')
        self.image.run_script(self.compimg_path + '/post-build.sh')

    def install_rundeps(self):
        self.image.run_script(self.compimg_path + '/pre-run.sh')
        self.image.action_arglist('pkg_install', self.compimg_path, 'rundeps')

    def test(self):
        configcmdpath = os.path.join(self.comp_path, 'test.sh')
        configtestpath = os.path.join(self.comp_path, 'test.config')
        if os.path.exists(configcmdpath):
            self._comp_script('test.sh')
        elif os.path.exists(configtestpath):
            self.image.cmd('kresd -n -c {}'.format(configtestpath))
        self.image.run_script(self.compimg_path + '/post-run.sh')


def foreach_component(components, action):
    '''Execute action for each component'''
    for comp in components:
        getattr(comp, action)()

def main():
    logging.basicConfig(level=logging.DEBUG)
    argparser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='''Generate Dockerfile to build/install/test given components.

Examples:
* Install build deps, build, install, remove build deps, and test kresd daemon:
 $ {n} debian 9 daemon/packaging > Dockerfile

* Install build and run-time deps to prepare development image:
 $ find -name packaging | xargs {n} \\
    --build=false --install=false --remove-builddeps=false --test=false \\
        debian 9 > Dockerfile
'''.format(n=sys.argv[0])
        )
    argparser.add_argument(
        '--builddeps', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--build', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--install', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--remove-builddeps', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--rundeps', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--test', default=True, type=bool, help='default: true')
    argparser.add_argument(
        '--srcdir', default=os.getcwd(), type=Path,
        help='directory to copy into new Docker image; default: .')
    argparser.add_argument(
        'distro', help='name of distribution image, e.g. "debian"')
    argparser.add_argument(
        'version', help='distribution version, e.g. 9')
    argparser.add_argument(
        'components', nargs='+',
        help='one or more components to process; order is respected')
    args = argparser.parse_args()

    # all paths must be relative to toplevel Git dir
    if not os.path.exists('.luacheckrc') or not os.path.exists('NEWS'):
        sys.exit('This script must be executed from top of distribution tree!')


    # load images from disk
    imgpath = os.path.join('scripts/distros', args.distro, args.version)
    image = Image(imgpath, args.distro, args.version)

    components = [Component(comppath, image) for comppath in args.components]
    if args.builddeps:
        foreach_component(components, 'install_builddeps')
    if args.build:
        foreach_component(components, 'build')
    if args.install:
        foreach_component(components, 'install')
    if args.remove_builddeps:
        foreach_component(components, 'remove_builddeps')
    if args.rundeps:
        foreach_component(components, 'install_rundeps')
    if args.test:
        foreach_component(components, 'test')
    print(DockerBuildEnv(image, args.srcdir))

if __name__ == '__main__':
    main()
