#!/bin/bash
# Create a source rpm for Fedora/EPEL
set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

scripts/make-distrofiles.sh
mv knot-resolver_*.orig.tar.xz distro/rpm/
cd distro/rpm
rpkg srpm --outdir .
mv *.src.rpm ../../
mv *.tar.xz ../../
