#!/usr/bin/env python3
from copy import deepcopy
import logging
from pathlib import Path
import os
import tempfile

PACKAGING_PATH_TODO='packaging'

class TestEnv():
    """
    abstract way to execute commands
    """
    def __init__(self, image):
        self.image = image

    def _load_image(self):
        raise NotImplementedError()

    def _run_cmds(self):
        raise NotImplementedError()

    def __str__(self):
        raise NotImplementedError()


class DockerBuildEnv():
    """
    execute commands as part of Docker build
    """
    def __init__(self, image):
        self.header = 'WORKDIR /root\nCOPY . /root\n'
        self.image = image

    def load_image(self):
        return 'FROM {0}:{1}\n'.format(self.image.name, self.image.version)

    def run_cmds(self):
        return '\n'.join('RUN {0}'.format(cmd) for cmd in self.image.cmds)

    def __str__(self):
        return self.load_image() + self.header + self.run_cmds()


class Image():
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

def test_component_in_image(component, comppath, image, cmpimgpath):
    image.action_arglist('pkg_install', cmpimgpath, 'builddeps')
    # build
    image.cmds_fromfile(os.path.join(PACKAGING_PATH_TODO, 'build.sh'))
    # install
    image.cmds_fromfile(os.path.join(PACKAGING_PATH_TODO, 'install.sh'))
    image.action_arglist('pkg_remove', cmpimgpath, 'builddeps')
    image.action_arglist('pkg_install', cmpimgpath, 'rundeps')
    # test
    configcmdpath = os.path.join(comppath, 'test.command')
    configtestpath = os.path.join(comppath, 'test.config')
    if os.path.exists(configcmdpath):
        image.cmds_fromfile(os.path.join(comppath, 'test.command'))
    elif os.path.exists(configtestpath):
        image.cmd('kresd -f 1 -c {} /tmp'.format(configtestpath))
    print(DockerBuildEnv(image))

def test_component(component, comppath, images):
    log = logging.getLogger(component)
    log.debug('component start: path %s', comppath)

    for distro in os.listdir(comppath):
        distropath = os.path.join(comppath, distro)
        try:
            for version in os.listdir(distropath):
                cmpimgpath = os.path.join(distropath, version)
                image = deepcopy(images[distro][version])
                test_component_in_image(component, comppath, image, cmpimgpath)
        except NotADirectoryError:
            pass


def main():
    logging.basicConfig(level=logging.DEBUG)
    # all paths must be relative to toplevel Git dir
    if not os.path.exists('.luacheckrc'):
        sys.exit('This script must be executed from top of distribution tree!')

    # load images from disk
    images = {}
    for distro in os.listdir('packaging/distros'):
        distropath = os.path.join('packaging/distros', distro)
        for version in os.listdir(distropath):
            imgpath = os.path.join(distropath, version)
            images.setdefault(distro, {})[version] = Image(imgpath, distro, version)

    for component in os.listdir('packaging/components'):
        comppath = os.path.join('packaging/components', component)
        test_component(component, comppath, images)

main()
