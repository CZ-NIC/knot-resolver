#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Builds the checked out version in OBS repository

set -o errexit -o nounset -o xtrace

obs_repo=$1

# Clean working tree
if [[ $(git status --porcelain | wc -l) -ne 0 ]]; then
    echo "working tree dirty: git clean -dfx && git reset --hard"
    exit 1
fi

# Create tarball
scripts/make-archive.sh

# Submit to OBS
scripts/make-distrofiles.sh -s
scripts/build-in-obs.sh $obs_repo

echo "Check results at https://build.opensuse.org/package/show/home:CZ-NIC:$obs_repo/knot-resolver"
