#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Push packaging files to OBS
#
# Example usage:
# 1. ./scripts/make-obs.sh
# 2. ./scripts/build-in-obs.sh knot-resolver-latest
set -o errexit -o nounset -o xtrace

pkgdir='pkg/obs'

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
cp -r ../../${pkgdir}/* ./
osc addremove
osc ci -n
popd
