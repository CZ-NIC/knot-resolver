#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."
pkgdir="build_dist/meson-dist"

package=knot-resolver


pushd ${pkgdir}
version=$(ls ${package}*.tar.xz | sed "s/${package}-\(.*\).tar.xz/\1/")
popd

# Check version for invalid characters
if [[ $(echo "${version}" | grep '^[[:alnum:].]$') -ne 0 ]]; then
	echo "Invalid version number: may contain only alphanumeric characters and dots"
	exit 1
fi

# Fill in VERSION field in distribution specific files
files="distro/rpm/${package}.spec distro/deb/changelog distro/arch/PKGBUILD distro/turris/Makefile"
for file in ${files}; do
	sed -i "s/__VERSION__/${version}/g" "${file}"
done

# Rename archive to debian format
pkgname="${package}-${version}"
debname="${package}_${version}.orig"
cp "${pkgdir}/${pkgname}.tar.xz" "${debname}.tar.xz"

# Prepare clean debian-specific directory
tar -xf "${debname}.tar.xz"
pushd "${pkgname}" > /dev/null
cp -arL ../distro/deb debian

# Create debian archive and dsc
dpkg-source -b .
popd > /dev/null
