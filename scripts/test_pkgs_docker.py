#!/usr/bin/env python3
import argparse
import logging
from pathlib import Path
import os
import sys

PACKAGING_PATH_TODO='packaging'

class TestEnv():
    """
    Abstract way to execute commands using different interpreters

    Reformat commands for different interpreters, e.g. Dockerfile, BASH, etc.
    """
    def __init__(self, image):
        self.image = image

    def _load_image(self):
        raise NotImplementedError()

    def _run_cmds(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class DockerBuildEnv(TestEnv):
    """
    Execute commands as part of Docker build (Dockerfile)
    """
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
    """
    Abstract interface for maintaining image of particular distro version
    """
    def __init__(self, imgpath, name, version):
        self.imgpath = imgpath
        self.name = name
        self.version = version
        self.actions = {}
        self.cmds = []
        self._init_cmds()
        self._read_prep()

    def _distrofile(self, filename):
        return open(os.path.join(self.imgpath, filename))

    def _read_prep(self):
        """
        Fill Dockerfile with preparation commands.

        name == docker image name, e.g. debian
        version == docker image tag, e.g. 9
        """
        with self._distrofile('prep') as prepfile:
                for cmd in prepfile:
                    self.cmds.append(cmd.strip())

    def _init_cmds(self):
        """
        Read commands for image modification
        """
        for cmd in os.listdir(self.imgpath):
            if cmd == 'prep':  # multi-line commands are handled somewhere else
                continue
            with self._distrofile(cmd) as cmdfile:
                self.actions[cmd] = cmdfile.read().strip()

    def __str__(self):
        return '# image: {0}:{1}\n'.format(self.name, self.version) + '\n'.join(self.cmds)

    @property
    def comp_path(self):
        return os.path.join(self.name, self.version)

    def action(self, action, arg):
        self.cmds.append('{0} {1}'.format(self.actions[action], arg))

    def action_arglist(self, action, cmpimgpath, filename):
        try:
            with open(os.path.join(cmpimgpath, filename)) as listf:
                    self.action(action, ' '.join(item.strip() for item in listf))
        except FileNotFoundError:
            pass

    def cmd(self, cmd):
        self.cmds.append(cmd)

    def cmds_fromfile(self, cmdfilename):
        try:
            with open(cmdfilename) as cmdfile:
                for cmd in cmdfile:
                    cmd = cmd.strip()
                    if cmd:
                        self.cmds.append(cmd)
        except FileNotFoundError:
            pass

class Component:
    def __init__(self, comp_path, image):
        self.comp_path = comp_path
        self.compimg_path = os.path.join(comp_path, image.comp_path)
        self.image = image
        # Some components do not have external depedencies at the moment so
        # compimg_path may not exist. That is okay, we will just run their tests.

    def install_builddeps(self):
        self.image.action_arglist('pkg_install', self.compimg_path, 'builddeps')

    def remove_builddeps(self):
        self.image.action_arglist('pkg_remove', self.compimg_path, 'builddeps')

    def install_rundeps(self):
        self.image.action_arglist('pkg_install', self.compimg_path, 'rundeps')

    def test(self):
        configcmdpath = os.path.join(self.comp_path, 'test.command')
        configtestpath = os.path.join(self.comp_path, 'test.config')
        if os.path.exists(configcmdpath):
            self.image.cmds_fromfile(os.path.join(self.comp_path, 'test.command'))
        elif os.path.exists(configtestpath):
            self.image.cmd('kresd -f 1 -c {}'.format(configtestpath))

#def test_component(component, comppath, images):
#    log = logging.getLogger(component)
#    log.debug('component start: path %s', comppath)
#
#    for distro in os.listdir(comppath):
#        distropath = os.path.join(comppath, distro)
#        try:
#            for version in os.listdir(distropath):
#                cmpimgpath = os.path.join(distropath, version)
#                image = deepcopy(images[distro][version])
#                test_component_in_image(component, comppath, image, cmpimgpath)
#        except NotADirectoryError:
#            pass


def foreach_component(components, action):
    for comp in components:
        getattr(comp, action)()

def main():
    logging.basicConfig(level=logging.DEBUG)
    # all paths must be relative to toplevel Git dir
    if not os.path.exists('.luacheckrc') or not os.path.exists('NEWS'):
        sys.exit('This script must be executed from top of distribution tree!')

    argparser = argparse.ArgumentParser()
    argparser.add_argument('--builddeps', default=True, type=bool)
    argparser.add_argument('--build', default=True, type=bool)
    argparser.add_argument('--install', default=True, type=bool)
    argparser.add_argument('--remove-builddeps', default=True, type=bool)
    argparser.add_argument('--rundeps', default=True, type=bool)
    argparser.add_argument('--test', default=True, type=bool)
    argparser.add_argument('--srcdir', default=os.getcwd(), type=Path)
    argparser.add_argument('distro')
    argparser.add_argument('version')
    argparser.add_argument('components', nargs='+')
    args = argparser.parse_args()

    # load images from disk
    imgpath = os.path.join('packaging/distros', args.distro, args.version)
    image = Image(imgpath, args.distro, args.version)

    components = [Component(comppath, image) for comppath in args.components]
    if args.builddeps:
        foreach_component(components, 'install_builddeps')
    if args.build:
        image.cmds_fromfile(os.path.join(PACKAGING_PATH_TODO, 'build.sh'))
    if args.install:
        image.cmds_fromfile(os.path.join(PACKAGING_PATH_TODO, 'install.sh'))
    if args.remove_builddeps:
        foreach_component(components, 'remove_builddeps')
    if args.rundeps:
        foreach_component(components, 'install_rundeps')
    if args.test:
        foreach_component(components, 'test')
    print(DockerBuildEnv(image, args.srcdir))

main()
