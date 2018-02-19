#!/bin/bash -e

# Fill in VERSION field in Fedora spec file

cd "$(git rev-parse --show-toplevel)"
VERSION=$(scripts/show-version.sh | sed 's/knot-resolver-\(.*\).tar.xz/\1/')
sed -i.bak "s@%define VERSION .*@%define VERSION $VERSION@" distro/fedora/knot-resolver.spec
