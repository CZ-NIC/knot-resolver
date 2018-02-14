#!/bin/bash -e

# Fill in VERSION and PRERELEASE fields in Fedora spec file

cd "$(git rev-parse --show-toplevel)"
VERSION=$(scripts/show-version.sh | sed 's/knot-resolver-\(.*\).tar.xz/\1/' | cut -f1 -d '-')
PRERELEASE=$(scripts/show-version.sh | sed 's/knot-resolver-\(.*\).tar.xz/\1/' | cut -f1 -d '-' --complement -s)
sed -i.bak "s@%define VERSION .*@%define VERSION $VERSION@" distro/fedora/knot-resolver.spec
if [ -n "$PRERELEASE" ]; then
	sed -i "s@#%% define PRERELEASE .*@%define PRERELEASE $PRERELEASE@" distro/fedora/knot-resolver.spec
fi
