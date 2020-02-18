import os
import pytest
import docker
from pathlib import Path
from abc import ABC, abstractmethod

EXCLUDED_TEST_DIRS = [ 'daemon/packaging', 'tests/unit/packaging', 'tests/packaging', 'tests/integration/deckard/contrib/libfaketime/packaging' ]
client = docker.from_env()

class ContainerHandler():
    def __init__(self, image):
        self.img_id = image
        self.container = None

    def run(self):
        self.container = client.containers.run(self.img_id, network_mode='host', tty=True, detach=True)
        print('--> Container ID: {}'.format(self.container))


    def stop(self):
        self.container.kill()


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
    def cmd_install(self):
        raise NotImplementedError

    @abstractmethod
    def cmd_build(self):
        raise NotImplementedError

    @abstractmethod
    def cmd_pkgs_install(self):
        raise NotImplementedError

    def setModule(self, module):
        self.module = module

    def __readDependencies(self, deps_file):
        listf = None
        try:
            with open(deps_file, 'r') as f:
                listf = f.read().splitlines()
        except FileNotFoundError:
            pass

        return listf


    def __genDockerFile(self, path):
        if (self.module is None):
            raise AttributeError

        distro_dir = os.path.join(self.module, self.distro, self.version) 

        dockerf = open(os.path.join(path,'Dockerfile-build'), 'w')

        dockerf.write('FROM {0}:{1}\n'.format(self.distro, self.version))
        dockerf.write('WORKDIR /root/kresd\nCOPY . /root/kresd\n')
        # when this file doesn't exists, tzdata needs user interaction
        dockerf.write('RUN if [ ! -f /etc/localtime ]; then ln -fs /usr/share/zoneinfo/Europe/Prague /etc/localtime; fi\n')
        if os.path.isfile(os.path.join(distro_dir, 'pre-build.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'pre-build.sh')))
        if os.path.isfile(os.path.join(distro_dir, 'builddeps')):
            dockerf.write('RUN {0} {1}\n'.format(self.cmd_pkgs_install(),
                          ' '.join(self.__readDependencies(os.path.join(distro_dir, 'builddeps')))))
        dockerf.write('RUN {}\n'.format(self.cmd_build()))
        dockerf.write('RUN {}\n'.format(self.cmd_install()))
        if os.path.isfile(os.path.join(distro_dir, 'post-build.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'post-build.sh')))


        dockerf.close()
        # workdir copy /tmp/pytest-session/kresd/
        # pre-build
        # deps
        # build
        # install
        # post-build
        # copy
 
    def __genDockerFile_run(self, path):
        if (self.module is None):
            raise AttributeError

        distro_dir = os.path.join(self.module, self.distro, self.version) 

        dockerf = open(os.path.join(path,'Dockerfile-run'), 'w')

        dockerf.write('FROM {0}:{1}\n'.format(self.distro, self.version))
        dockerf.write('COPY data.tar /root\nRUN cd /root; tar xf /root/data.tar\n')
        dockerf.write('WORKDIR /root/kresd\n')
        if os.path.isfile(os.path.join(distro_dir, 'pre-run.sh')):
            dockerf.write('RUN {}\n'.format(os.path.join(distro_dir, 'pre-run.sh')))
        if os.path.isfile(os.path.join(distro_dir, 'rundeps')):
            dockerf.write('RUN {0} {1}\n'.format(self.cmd_pkgs_install(),
                          ' '.join(self.__readDependencies(os.path.join(distro_dir, 'rundeps')))))

        dockerf.close()

        
        # workdir copy /tmp/pytest-???/kresd/
        # pre-run
        # deps
        # run


        dockerf.close()

    def build(self, tmpdir, tag=""):
        self.__genDockerFile(tmpdir)

        print('--> DIR: {0}\n--> DATA: {1}\n--> TAG: {2}'.format(tmpdir, pytest.KR_TARBALLDIR, tag))
        image = client.images.build(path=str(pytest.KR_TARBALLDIR),
                                 dockerfile=os.path.join(tmpdir, 'Dockerfile-build'),
                                 network_mode='host', tag=tag, rm=True)
        print('--> Image ID - build: {}'.format(image[0].short_id))
        self.build_id = image[0].short_id
        return self.build_id

    def build_run(self, tmpdir, tag=""):
        self.__genDockerFile_run(tmpdir)

        print('--> DIR: {0}\n--> DATA: {1}\n--> TAG: {2}'.format(tmpdir, tmpdir, tag))
        image = client.images.build(path=str(tmpdir),
                                 dockerfile=os.path.join(tmpdir, 'Dockerfile-run'),
                                 network_mode='host', tag=tag, rm=True)
        print('--> Image ID - run: {}'.format(image[0].short_id))
        self.run_id = image[0].short_id
        return self.run_id

    def test(self, image):
        pass

class DebianImage(DockerImages):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'debian'

    def cmd_install(self):
        # apt install
        print('--> Debian: install')
        return 'ninja -C build_packaging install >/dev/null'

    def cmd_build(self):
        print('--> Debian: build')
        return """\\
                CFLAGS=\"$CFLAGS -Wall -pedantic -fno-omit-frame-pointer\"; \\
                LDFLAGS=\"$LDFLAGS -Wl,--as-needed\"; \\
                meson build_packaging \\
                    --buildtype=plain \\
                    --prefix=/root/kresd/install_packaging \\
                    --libdir=lib \\
                    --default-library=static \\
                    -Ddoc=enabled \\
                    -Dsystemd_files=enabled \\
                    -Dclient=enabled \\
                    -Dkeyfile_default=/usr/share/dns/root.key \\
                    -Droot_hints=/usr/share/dns/root.hints \\
                    -Dinstall_kresd_conf=enabled \\
                    -Dunit_tests=enabled \\
                    -Dc_args=\"${CFLAGS}\" \\
                    -Dc_link_args=\"${LDFLAGS}\";
                """

    def cmd_pkgs_install(self):
        return 'apt-get install -y '

class UbuntuImage(DebianImage):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'ubuntu'

class CentosImage(DockerImages):
    def __init__(self, version):
        super().__init__(version)
        self.distro = 'centos'

    def cmd_install(self):
        raise NotImplementedError
        return ""

    def cmd_build(self):
        raise NotImplementedError
        return ""

    def cmd_pkgs_install(self):
        raise NotImplementedError
        return ""



def list_dirs(path, exclude=None):
    filtered_dirs = []
    root_depth = path.count(os.path.sep)

    for rootpath, dirs, _ in os.walk(path):

        if (os.path.basename(rootpath) == 'packaging'):
            fdir = os.path.relpath(rootpath, path)
            if exclude is not None:
                if fdir not in exclude:
                    filtered_dirs.append(fdir)
            else :
                filtered_dirs.append(fdir)

    return filtered_dirs

def list_tests_dirs():
    return list_dirs(pytest.KR_ROOT_DIR, EXCLUDED_TEST_DIRS)


def list_distro_vers(distro_root):
    '''
    return list of (distro, version) pairs found in distro_root
    '''
    # transform list of paths like TOP/debian/9 into (debian, 9)

    dist_ver = [p.parts[-2:] for p
                in Path(distro_root).glob('*/*') if p.is_dir()]

    return list(dist_ver)


MODULES=list_tests_dirs()


@pytest.fixture(scope='session', params=list_distro_vers(os.path.join(pytest.KR_ROOT_DIR,
                'tests/packaging/distros')))
def buildenv(request, tmpdir_factory):
    distro = request.param
    print('creating buildenv: {0} {1}'.format(distro[0], distro[1]))
    if (distro[0] == 'debian'):
        img = DebianImage(distro[1])
    elif (distro[0] == 'ubuntu'):
        img = UbuntuImage(distro[1])
    elif (distro[0] == 'centos'):
        img = CentosImage(distro[1])

    if (distro[0] == 'ubuntu'):
        yield None
    else:
        img.setModule('daemon/packaging')
        tmpdir = tmpdir_factory.mktemp(distro[0]+distro[1])
        img.build(tmpdir, tag=pytest.KR_PREFIX+distro[0]+distro[1]+'-build')
        ch = ContainerHandler(img.build_id)
        ch.run()
        ch.getFiles(os.path.join(tmpdir, 'data.tar'), '/root/kresd')
        ch.stop()
        img.build_run(tmpdir, tag=pytest.KR_PREFIX+distro[0]+distro[1]+'-run')
        yield img
    print('removing buildenv: {}'.format(distro))


@pytest.mark.parametrize('module', MODULES)
#@pytest.mark.parametrize('distro', DISTROS)
def test_collect(config, module, buildenv):
    print('MAIN test collect ({}, {})'.format(module, buildenv))

    #if(buildenv.distro == "debian" and module == "/home/ljezek/Vyvoj/knot-resolver/tests/packaging/../../modules/http/packaging"):
#    if(buildenv.distro == "debian" and module == "daemon/packaging"):
#        buildenv.setModule(module)
#        buildenv.build(tmp_path)

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

