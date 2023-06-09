#!/usr/bin/python3
"""
Enable Knot Resolver upstream repo on current system.

Requires python3-distro.

Run this as ROOT.
"""

import argparse
import distro as distro_
from pathlib import Path
from subprocess import run, PIPE
import sys


REPO_CHOICES = ['latest', 'testing', 'build']


def detect_distro():
    return '%s-%s' % (distro_.id(), distro_.version())


def parse_distro(distro):
    id_, _, ver_ = distro.rpartition('-')
    return id_, ver_


def distro2obs(distro):
    distro_id, distro_ver = parse_distro(distro)
    if not str(distro_ver):
        return None
    if distro_id == 'debian':
        return 'Debian_%s' % distro_ver
    if distro_id == 'ubuntu':
        return 'xUbuntu_%s' % distro_ver
    if distro_id == 'opensuse-leap':
        return 'openSUSE_Leap_%s' % distro_ver
    return None


def show_info():
    print("distro ID: %s" % detect_distro())
    print("distro name: %s %s" % (distro_.name(), distro_.version(pretty=True)))


def enable_deb_repo(repo_id, distro):
    obs_distro = distro2obs(distro)
    if not obs_distro:
        return fail('unsupported Debian-based distro: %s' % distro)

    requires = ['python3-requests', 'gnupg']
    print("installing required packages: %s" % ' '.join(requires))
    p = run(['apt', 'install', '-y'] + requires)
    import requests

    sources_p = Path('/etc/apt/sources.list.d/%s.list' % repo_id)
    sources_txt = 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/%s/%s/ /' % (repo_id, obs_distro)
    key_url = 'https://download.opensuse.org/repositories/home:CZ-NIC:%s/%s/Release.key' % (repo_id, obs_distro)
    print("writing sources list: %s" % sources_p)
    with sources_p.open('wt') as f:
        f.write(sources_txt + '\n')
        print(sources_txt)
    print("fetching key: %s" % key_url)
    r = requests.get(key_url)
    if not r.ok:
        return fail('failed to fetch repo key: %s' % key_url)
    key_txt = r.content.decode('utf-8')
    print("adding key using `apt-key add`")
    p = run(['apt-key', 'add', '-'], input=key_txt, encoding='utf-8')
    if p.returncode != 0:
        print('apt-key add failed :(')
    run(['apt', 'update'])
    print("%s repo added" % repo_id)


def enable_suse_repo(repo_id, distro):
    obs_distro = distro2obs(distro)
    if not obs_distro:
        return fail('unsupported SUSE distro: %s' % distro)

    repo_url = 'https://download.opensuse.org/repositories/home:CZ-NIC:{repo}/{distro}/home:CZ-NIC:{repo}.repo'.format(
        repo=repo_id, distro=obs_distro)
    print("adding OBS repo: %s" % repo_url)
    run(['zypper', 'addrepo', repo_url])
    run(['zypper', '--no-gpg-checks', 'refresh'])


def enable_repo(repo_id, distro):
    distro_id, distro_ver = parse_distro(distro)
    print("enable %s repo on %s" % (repo_id, distro))

    if distro_id in ['debian', 'ubuntu']:
        enable_deb_repo(repo_id, distro)
    elif distro_id == 'opensuse-leap':
        enable_suse_repo(repo_id, distro)
    elif distro_id == 'arch':
        print("no external repo needed on %s" % distro_id)
    else:
        fail("unsupported distro: %s" % distro_id)


def fail(msg):
    print(msg)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
            description="Enable Knot Resolver repo on this system")
    parser.add_argument('repo', choices=REPO_CHOICES, nargs='?', default=REPO_CHOICES[0],
            help="repo to enable")
    parser.add_argument('-d', '--distro', type=str,
            help="override target distro (DISTRO-VERSION format)")
    parser.add_argument('-i', '--info', action='store_true',
            help="show distro information and exit")

    args = parser.parse_args()
    if args.info:
        show_info()
        return

    distro = args.distro
    if not distro:
        distro = detect_distro()

    repo = 'knot-resolver-%s' % args.repo
    enable_repo(repo, distro)


if __name__ == '__main__':
    main()
