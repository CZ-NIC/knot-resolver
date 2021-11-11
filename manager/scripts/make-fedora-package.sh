#!/bin/bash

set -o errexit
set -o nounset

# upgrade system to latest
dnf upgrade -y

# apkg
dnf install -y python3-pip
pip3 install apkg

# prepare the repo
git clone https://gitlab.nic.cz/knot/knot-resolver
cd knot-resolver
git config --global user.email "ci@knot-resolver"
git config --global user.name "GitLab CI"
git checkout manager-pkg
git rebase origin/manager-integration
git submodule update --init --recursive

# build the package
apkg system-setup
apkg build -b
apkg srcpkg
