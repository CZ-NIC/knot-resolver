#!/bin/bash -e

# Example usage:
# scripts/make-distrofiles.sh
# scripts/build-in-obs.sh knot-resolver-devel

repo=home:CZ-NIC:$1

osc co "$repo" knot-resolver
cd "$repo/knot-resolver"
osc del *
cp ../../*.tar.xz ./
cp -rL ../../distro/fedora/* ./
cp -rL ../../distro/arch/* ./
cp ../../distro/debian/*.debian.tar.xz ./
cp ../../distro/debian/knot-resolver.dsc ./
osc addremove
osc ci -n
