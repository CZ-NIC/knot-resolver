#!/bin/bash

set -o errexit
set -o nounset

function init_debian {
    export DEBIAN_FRONTEND=noninteractive

    # upgrade system to latest
    apt-get update -qqq
    apt-get upgrade -y -qqq

    # configure repository with Knot Resolver dependencies
    apt-get -y -qqq install apt-transport-https lsb-release ca-certificates wget curl gnupg2
    sh -c 'echo "deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-build/Debian_10/ /" > /etc/apt/sources.list.d/home:CZ-NIC:knot-resolver-build.list'
    sh -c 'curl -fsSL https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-build/Debian_10/Release.key | gpg --dearmor > /etc/apt/trusted.gpg.d/home_CZ-NIC_knot-resolver-build.gpg'
    apt-get update -qqq

    # apkg
    apt-get install -y python3-pip meson git python3-venv
}

function init_fedora {
    # upgrade system to latest and install pip
    dnf upgrade -y
    dnf install -y python3-pip
}


# system setup
if command -v dnf; then
    init_fedora
elif command -v apt-get; then
    init_debian
else
    echo "System not supported."
    exit 1
fi

# install apkg
python3 -m pip install --user pipx
python3 -m pipx ensurepath
PATH="$PATH:/root/.local/bin"  # hack to make binaries installed with pipx work
python3 -m pipx install apkg

# prepare the repo
#git clone https://gitlab.nic.cz/knot/knot-resolver
cd /repo
git config --global user.email "automated-script"
git config --global user.name "Automated Script"
git checkout manager-integration-without-submodule
git submodule update --init --recursive

# build the package
apkg system-setup
apkg build -b
apkg srcpkg






