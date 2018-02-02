#!/bin/bash -e

# Create a source rpm for Fedora/EPEL

cd "$(git rev-parse --show-toplevel)"
scripts/make-archive.sh
VERSION=$(ls knot-resolver-*.tar.xz | sed 's/knot-resolver-\(.*\).tar.xz/\1/' | cut -f1 -d '-')
PRERELEASE=$(ls knot-resolver-*.tar.xz | sed 's/knot-resolver-\(.*\).tar.xz/\1/' | cut -f1 -d '-' --complement -s)
sed -i.bak "s/%define VERSION .*/%define VERSION $VERSION/" distro/fedora/knot-resolver.spec
if [ -n "$PRERELEASE" ]; then
	sed -i "s/#%% define PRERELEASE .*/%define PRERELEASE $PRERELEASE/" distro/fedora/knot-resolver.spec
fi
mv knot-resolver-*.tar.xz distro/fedora/
cd distro/fedora
rpkg srpm
mv knot-resolver.spec{.bak,}
mv *.src.rpm ../../
mv *.tar.xz ../../
