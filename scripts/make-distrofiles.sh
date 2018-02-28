#!/bin/bash -e

package=knot-resolver

cd "$(git rev-parse --show-toplevel)"
version=$(ls ${package}*.tar.xz | sed "s/${package}-\(.*\).tar.xz/\1/")

# Check version for invalid characters
if [[ $(echo "${version}" | grep '^[[:alnum:].]$') -ne 0 ]]; then
	echo "Invalid version number: may contain only alphanumeric characters and dots"
	exit 1
fi

# Fill in VERSION field in distribution specific files
files="distro/rpm/${package}.spec distro/deb/debian/changelog distro/deb/${package}.dsc distro/arch/PKGBUILD"
for file in ${files}; do
	sed -i "s/__VERSION__/${version}/g" "${file}"
done

# Rename archive to debian format
mv "${package}-${version}.tar.xz" "${package}_${version}.orig.tar.xz"

# Create debian archive and dsc
pushd distro/deb
tar -chaf "${package}_${version}-1.debian.tar.xz" debian
archive=${package}_${version}-1.debian.tar.xz
echo " $(md5sum ${archive} | cut -d' ' -f1) $(wc -c ${archive})" >> ${package}.dsc
popd
archive=${package}_${version}.orig.tar.xz
echo " $(md5sum ${archive} | cut -d' ' -f1) $(wc -c ${archive})" >> distro/deb/${package}.dsc
