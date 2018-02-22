#!/bin/bash -e

# Create a source rpm for Fedora/EPEL

cd "$(git rev-parse --show-toplevel)"
scripts/make-archive.sh
scripts/make-distrofiles.sh
mv knot-resolver_*.orig.tar.xz distro/fedora/
cd distro/fedora
rpkg srpm
mv *.src.rpm ../../
mv *.tar.xz ../../
