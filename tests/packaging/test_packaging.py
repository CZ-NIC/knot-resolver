# SPDX-License-Identifier: GPL-3.0-or-later

import os
import pytest
import docker
import logging
from pathlib import Path
from abc import ABC, abstractmethod


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
client = docker.from_env()


class DockerCmdError(Exception):
    """ Raised when shell command in Docker container failed """
    pass


class ContainerHandler():
    def __init__(self, image):
        self.img_id = image
        self.container = None

    def run(self):
        self.container = client.containers.run(self.img_id, network_mode='host',
                                               tty=True, detach=True)
        logger.info('Run container ID={}'.format(self.container))

    def stop(self):
        self.container.kill()

    def exec_cmd(self, cmd, workdir):
        # workaround: When exec_run is called in GitLab CI/CD workdir argument doesn't work.
        inter_cmd = ''
        if workdir is not None:
            inter_cmd = 'cd {}; '.format(workdir)

        rcode, out = self.container.exec_run('/bin/sh -c \'' + inter_cmd + cmd + '\'')
        if rcode != 0:
            raise DockerCmdError(rcode, out)

    def getFiles(self, output, path):
        strm, stat = self.container.get_archive(path)
        with open(output, 'wb') as ofile:
            for data in strm:
                ofile.write(data)


class DockerImages(ABC):
    def __init__(self, version):
        self.version = version
        self.module = None
        self.distro = None
        self.build_id = None
        self.run_id = None

    @abstractmethod
    def cmd_pkgs_install(self):
        raise NotImplementedError

    @abstractmethod
    def cmd_kresd_install(self):
        raise NotImplementedError

    @abstractmethod
    def cmd_kresd_build(self):
        raise NotImplementedError

    def readDependencies(self, deps_file):
        """Read dependencies from file"""
        listf = None
        try:
            with open(deps_file, 'r') as f:
                listf = f.read().splitlines()
        except FileNotFoundError:
            pass

        return listf

    def __genDockerFile(self, path, from_image=None):
        """Generate Dockerfile for build image"""
        if self.module is None:
            raise AttributeError

        if from_image is None:
            if os.path.isfile(os.path.join(self.module, self.distro, 'docker-image-name')):
                with open(os.path.join(self.module, self.distro, 'docker-image-name')) as f:
                    from_image = f.read()
            else:
                from_image = '{0}:{1}'.format(self.distro, self.version)

        distro_dir = os.path.join(self.module, self.distro, self.version)

        dockerf = open(os.path.join(path, 'Dockerfile-build'), 'w')

        dockerf.write('FROM {}\n'.format(from_image))
        dockerf.write('WORKDIR /root/kresd\n')
        if self.module == 'daemon/.packaging':
            dockerf.write('COPY . /root/kresd\n')
        # when this file doesn't exists, tzdata needs user interaction
        dockerf.write('RUN if [ ! -f /etc/localtime ];' +
                      'then ln -fs /usr/share/zoneinfo/Europe/Prague /etc/localtime; fi\n')
        if os.path.isfile(os.path.join(distro_dir, 'pre-build.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'pre-build.sh')))
        if os.path.isfile(os.path.join(distro_dir, 'builddeps')):
            dockerf.write('RUN {0} {1}\n'.format(self.cmd_pkgs_install(),
                          ' '.join(self.readDependencies(os.path.join(distro_dir, 'builddeps')))))
        if os.path.isfile(os.path.join(distro_dir, 'build.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'build.sh')))
        else:
            dockerf.write('RUN {}\n'.format(self.cmd_kresd_build()))
        if os.path.isfile(os.path.join(distro_dir, 'install.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'install.sh')))
        else:
            dockerf.write('RUN {}\n'.format(self.cmd_kresd_install()))
        if os.path.isfile(os.path.join(distro_dir, 'post-build.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'post-build.sh')))

        dockerf.close()

    def __genDockerFile_run(self, path, build_id, from_image=None):
        """Generate Dockerfile for run image"""
        if self.module is None:
            raise AttributeError

        if from_image is None:
            if os.path.isfile(os.path.join(self.module, self.distro, 'docker-image-name')):
                with open(os.path.join(self.module, self.distro, 'docker-image-name')) as f:
                    from_image = f.read()
            else:
                from_image = '{0}:{1}'.format(self.distro, self.version)

        distro_dir = os.path.join(self.module, self.distro, self.version)

        dockerf = open(os.path.join(path, 'Dockerfile-run'), 'w')

        dockerf.write('FROM {}\n'.format(from_image))
        dockerf.write('COPY --from={} /root/kresd /root/kresd\n'.format(build_id))
        dockerf.write('WORKDIR /root/kresd\n')
        if os.path.isfile(os.path.join(distro_dir, 'pre-run.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'pre-run.sh')))
        if os.path.isfile(os.path.join(distro_dir, 'rundeps')):
            dockerf.write('RUN {0} {1}\n'.format(self.cmd_pkgs_install(),
                          ' '.join(self.readDependencies(os.path.join(distro_dir, 'rundeps')))))
        if os.path.isfile(os.path.join(distro_dir, 'pre-test.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'pre-test.sh')))

        dockerf.close()

    def build(self, tmpdir, tag="", from_image=None):
        self.__genDockerFile(tmpdir, from_image=from_image)

        logger.debug('tmpdir={}'.format(tmpdir))
        logger.debug('datadir={}'.format(pytest.KR_ROOT_DIR))
        logger.debug('tag={}'.format(tag))
        image = client.images.build(path=str(pytest.KR_ROOT_DIR),
                                    dockerfile=os.path.join(tmpdir, 'Dockerfile-build'),
                                    network_mode='host', tag=tag, rm=True)
        logger.info('"Build image" ID={} created'.format(image[0].short_id))
        self.build_id = image[0].short_id
        return self.build_id

    def build_run(self, tmpdir, build_id, from_image=None, tag=""):
        self.__genDockerFile_run(tmpdir, build_id, from_image=from_image)

        logger.debug('tmpdir={}'.format(tmpdir))
        logger.debug('datadir={}'.format(tmpdir))
        logger.debug('tag={}'.format(tag))
        image = client.images.build(path=str(tmpdir),
                                    dockerfile=os.path.join(tmpdir, 'Dockerfile-run'),
                                    network_mode='host', tag=tag, rm=True)
        logger.info('"Run image" ID={} created'.format(image[0].short_id))
        self.run_id = image[0].short_id
        return self.run_id


class DebianImage(DockerImages):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'debian'

    def cmd_pkgs_install(self):
        return 'apt-get install -y '

    def cmd_kresd_install(self):
        return 'ninja -C build_packaging install >/dev/null'

    def cmd_kresd_build(self):
        return """\\
                [ -d /root/kresd/build_packaging ] && rm -rf /root/kresd/build_packaging/; \\
                CFLAGS=\"$CFLAGS -Wall -pedantic -fno-omit-frame-pointer\"; \\
                LDFLAGS=\"$LDFLAGS -Wl,--as-needed\"; \\
                meson build_packaging \\
                    --buildtype=plain \\
                    --prefix=/root/kresd/install_packaging \\
                    --libdir=lib \\
                    --default-library=static \\
                    -Dsystemd_files=enabled \\
                    -Dclient=enabled \\
                    -Dkeyfile_default=/usr/share/dns/root.key \\
                    -Droot_hints=/usr/share/dns/root.hints \\
                    -Dinstall_kresd_conf=enabled \\
                    -Dunit_tests=enabled \\
                    -Dc_args=\"${CFLAGS}\" \\
                    -Dc_link_args=\"${LDFLAGS}\"; \\
                ninja -C build_packaging
                """


class UbuntuImage(DebianImage):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'ubuntu'


class CentosImage(DockerImages):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'centos'

    def cmd_pkgs_install(self):
        return "yum install -y "

    def cmd_kresd_install(self):
        return 'ninja-build -C build_packaging install'

    def cmd_kresd_build(self):
        return """\\
                [ -d /root/kresd/build_packaging ] && rm -rf /root/kresd/build_packaging/; \\
                CFLAGS=\"$CFLAGS -Wall -pedantic -fno-omit-frame-pointer\"; \\
                LDFLAGS=\"$LDFLAGS -Wl,--as-needed\"; \\
                meson build_packaging \\
                    --buildtype=plain \\
                    --prefix=/root/kresd/install_packaging \\
                    --sbindir=sbin \\
                    --libdir=lib \\
                    --includedir=include \\
                    --sysconfdir=etc \\
                    --default-library=static \\
                    -Dsystemd_files=enabled \\
                    -Dclient=enabled \\
                    -Dunit_tests=enabled \\
                    -Dmanaged_ta=enabled \\
                    -Dkeyfile_default=/root/kresd/install_packaging/var/lib/knot-resolver/root.keys \\
                    -Dinstall_root_keys=enabled \\
                    -Dinstall_kresd_conf=enabled; \\
                ninja-build -C build_packaging
                """


class FedoraImage(DockerImages):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'fedora'

    def cmd_pkgs_install(self):
        return "dnf install -y "

    def cmd_kresd_install(self):
        return 'ninja -C build_packaging install >/dev/null'

    def cmd_kresd_build(self):
        return """\\
                [ -d /root/kresd/build_packaging ] && rm -rf /root/kresd/build_packaging/; \\
                CFLAGS=\"$CFLAGS -Wall -pedantic -fno-omit-frame-pointer\"; \\
                LDFLAGS=\"$LDFLAGS -Wl,--as-needed\"; \\
                meson build_packaging \\
                    --buildtype=plain \\
                    --prefix=/root/kresd/install_packaging \\
                    --sbindir=sbin \\
                    --libdir=lib \\
                    --includedir=include \\
                    --sysconfdir=etc \\
                    --default-library=static \\
                    -Dsystemd_files=enabled \\
                    -Dclient=enabled \\
                    -Dunit_tests=enabled \\
                    -Dmanaged_ta=enabled \\
                    -Dkeyfile_default=/root/kresd/install_packaging/var/lib/knot-resolver/root.keys \\
                    -Dinstall_root_keys=enabled \\
                    -Dinstall_kresd_conf=enabled; \\
                ninja -C build_packaging
                """


class LeapImage(FedoraImage):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'leap'

    def cmd_pkgs_install(self):
        return "zypper install -y "


def create_distro_image(name, version):
    img = None

    if (name == 'debian'):
        img = DebianImage(version)
    elif (name == 'ubuntu'):
        img = UbuntuImage(version)
    elif (name == 'centos'):
        img = CentosImage(version)
    elif (name == 'fedora'):
        img = FedoraImage(version)
    elif (name == 'leap'):
        img = LeapImage(version)
    else:
        img = None

    return img


def list_dirs(path, exclude=None):
    """return all 'packaging' directories with full path"""
    filtered_dirs = []

    for rootpath, dirs, _ in os.walk(path):

        if (os.path.basename(rootpath) == '.packaging'):
            fdir = os.path.relpath(rootpath, path)
            if exclude is not None:
                if fdir not in exclude:
                    filtered_dirs.append(fdir)
            else:
                filtered_dirs.append(fdir)

    return filtered_dirs


def list_tests_dirs():
    """return all 'packaging' directories"""
    return list_dirs(pytest.KR_ROOT_DIR)


def list_distro_vers(distro_root):
    """
    return list of { 'name': distro_name, 'version': distro_version)
    pairs found in distro_root
    """
    # transform list of paths like TOP/debian/10 into (debian, 10)
    dist_ver = [{'name': p.parts[-2], 'version': p.parts[-1]} for p
                in Path(distro_root).glob('*/*') if p.is_dir()]

    return list(dist_ver)


MODULES = list_tests_dirs()
DISTROS = list_distro_vers(os.path.join(pytest.KR_ROOT_DIR, 'daemon/.packaging'))
DISTROS_NAMES = ['{0}_{1}'.format(distro['name'], distro['version']) for distro in DISTROS]


@pytest.fixture(scope='session', params=DISTROS, ids=DISTROS_NAMES)
def buildenv(request, tmpdir_factory):
    distro = request.param

    logger.debug('Creating main images for "{0} {1}"'.format(distro['name'], distro['version']))
    img = create_distro_image(distro['name'], distro['version'])
    if img is None:
        logger.warning('Unknown distro {}'.format(distro['name']))
    else:
        img.module = 'daemon/.packaging'
        tmpdir = tmpdir_factory.mktemp(distro['name']+distro['version'])
        img.build(tmpdir, tag=pytest.KR_PREFIX+distro['name']+distro['version']+'-build')
        img.build_run(tmpdir, img.build_id,
                      tag=pytest.KR_PREFIX+distro['name']+distro['version']+'-run')

    yield img
#    client.images.remove(img.run_id)
#    client.images.remove(img.build_id)


@pytest.mark.parametrize('module', MODULES)
def test_collect(module, buildenv, tmp_path):
    logger.info(' ### Run test {} ###'.format(module))

    if buildenv is None:
        logger.error('Distro "{0} {1}" isn\'t implemented'.format(buildenv.distro,
                                                                  buildenv.version))
        assert False

    rcode = None
    buildmod = None
    module_dir = os.path.join(pytest.KR_ROOT_DIR, module)
    distro_dir = os.path.join(module_dir, buildenv.distro, buildenv.version)

    if os.path.isfile(os.path.join(distro_dir, 'NOTSUPPORTED')):
        pytest.skip('Unsupported linux distribution ({0} {1}:{2})'.format(buildenv.distro, buildenv.version, module))

    try:
        if module == 'daemon/.packaging':
            # use main "run image" without changes
            logging.info('Use main "run image"')
            ch = ContainerHandler(buildenv.run_id)
            ch.run()
        elif buildenv is not None:
            if os.path.isfile(os.path.join(distro_dir, 'pre-build.sh')) \
                    or os.path.isfile(os.path.join(distro_dir, 'builddeps')):
                # create module specific "build image"
                logger.info('Create new "build image"')
                buildmod = create_distro_image(buildenv.distro, buildenv.version)
                buildmod.module = module
                buildmod.build(tmp_path, from_image=buildenv.build_id,
                               tag=pytest.KR_PREFIX+buildmod.distro+buildmod.version+'-' +
                               module.replace('/.packaging', '')+'-build')

            if buildmod is not None:
                # new build image was made, create new module specific "run image"
                logger.info('Create module specific "run image" from Dockerfile')
                buildmod.build_run(tmp_path, buildmod.build_id,
                                   tag=pytest.KR_PREFIX+buildmod.distro+buildmod.version+'-' +
                                   module.replace('/.packaging', '')+'-run', from_image=buildenv.run_id)
                ch = ContainerHandler(buildmod.run_id)
                ch.run()
            elif os.path.isfile(os.path.join(distro_dir, 'pre-run.sh')) \
                    or os.path.isfile(os.path.join(distro_dir, 'rundeps')):
                # use main "run image" and apply module specific changes
                logger.info('Apply module specific changes to "run image"')
                buildmod = buildenv
                ch = ContainerHandler(buildmod.run_id)
                ch.run()

                if os.path.isfile(os.path.join(distro_dir, 'pre-run.sh')):
                    ch.exec_cmd(os.path.join(module, buildenv.distro, buildenv.version,
                                'pre-run.sh'), '/root/kresd/')

                if os.path.isfile(os.path.join(distro_dir, 'rundeps')):
                    logger.debug(buildmod.cmd_pkgs_install() + ' '.join(
                                  buildmod.readDependencies(os.path.join(distro_dir, 'rundeps'))))
                    ch.exec_cmd(buildmod.cmd_pkgs_install() + ' '.join(
                                buildmod.readDependencies(os.path.join(distro_dir, 'rundeps'))),
                                '/root/kresd/')

                if os.path.isfile(os.path.join(distro_dir, 'pre-test.sh')):
                    ch.exec_cmd(os.path.join(module, buildenv.distro, buildenv.version,
                                'pre-test.sh'), '/root/kresd/')
            else:
                # use main "run image" without changes
                logging.info('Use main "run image"')
                ch = ContainerHandler(buildenv.run_id)
                ch.run()

        # run test
        if os.path.isfile(os.path.join(module_dir, 'test.config')):
            ch.exec_cmd('/root/kresd/install_packaging/sbin/kresd -n -c ' + os.path.join('..',
                        module, 'test.config'), '/root/kresd/install_packaging/')
        elif os.path.isfile(os.path.join(module_dir, 'test.sh')):
            ch.exec_cmd(os.path.join('..', module, 'test.sh'),
                        '/root/kresd/install_packaging/')
        else:
            ch.stop()
            ch.container.remove()
            logger.error('Test file (test.config or test.sh) not found')
            assert False

        rcode = 0

        if os.path.isfile(os.path.join(distro_dir, 'post-run.sh')):
            ch.exec_cmd(os.path.join(module, buildenv.distro, buildenv.version, 'post-run.sh'),
                        '/root/kresd/')

    except DockerCmdError as err:
        rcode, out = err.args
        logger.debug('rcode: {}'.format(rcode))
        logger.error(out.decode('utf-8'))
    finally:
        ch.stop()
        ch.container.remove()
        if buildmod is not None and buildmod is not buildenv:
            client.images.remove(buildmod.run_id)
            client.images.remove(buildmod.build_id)

    assert(rcode == 0)
