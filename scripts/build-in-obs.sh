#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Example usage:
# 1. place tarball to be released in git root dir
# 2. scripts/make-distrofiles.sh
# 3. scripts/build-in-obs.sh knot-resolver-latest
set -o errexit -o nounset -o xtrace

project=home:CZ-NIC:$1
package=knot-resolver

if ! [[ "$1" == *-devel || "$1" == *-testing ]]; then
	read -p "Pushing to '$project', are you sure? [y/N]: " yn
	case $yn in
		[Yy]* )
            ;;
		* )
            exit 1
	esac
fi

osc co "${project}" "${package}"
pushd "${project}/${package}"
osc del * ||:
cp -L ../../*.orig.tar.xz ../../*.debian.tar.xz ../../*.dsc ./
cp -rL ../../distro/rpm/* ./
cp -rL ../../distro/arch/* ./
osc addremove
osc ci -n
popd
