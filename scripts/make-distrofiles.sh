#!/bin/bash -e

scripts/make-archive.sh

cd "$(git rev-parse --show-toplevel)"
VERSION=$(scripts/show-version.sh)

# Fill in VERSION field in distribution specific files
files='distro/fedora/knot-resolver.spec distro/arch/PKGBUILD distro/debian/debian/changelog distro/debian/knot-resolver.dsc'
for file in $files; do
	sed -i "s/__VERSION__/$VERSION/g" "$file"
done

# Rename archive to debian format
mv knot-resolver-$VERSION.tar.xz knot-resolver_$VERSION.orig.tar.xz

# Create debian archive and dsc
pushd distro/debian
tar -chaf knot-resolver_$VERSION-1.debian.tar.xz debian
archive=knot-resolver_$VERSION-1.debian.tar.xz
echo " $(md5sum $archive | cut -d' ' -f1) $(wc -c $archive)" >> knot-resolver.dsc
popd
archive=knot-resolver_$VERSION.orig.tar.xz
echo " $(md5sum $archive | cut -d' ' -f1) $(wc -c $archive)" >> distro/debian/knot-resolver.dsc
