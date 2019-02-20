#!/bin/bash
set -o errexit -o nounset -o xtrace

# Create a source rpm for Fedora/EPEL

cd "$(git rev-parse --show-toplevel)"
scripts/make-dev-archive.sh
scripts/make-distrofiles.sh
mv knot-resolver_*.orig.tar.xz distro/rpm/
cd distro/rpm
rpkg srpm --outdir .
mv *.src.rpm ../../
mv *.tar.xz ../../
