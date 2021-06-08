#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# create OpenSUSE Build System (OBS) source package
#
# this needs to be run on a system with:
#
# * apkg
# * dpkg-buildpackage
#
# usage:
#   ./scripts/make-obs.sh [path.to.archive.xz] [1]
#
# supply archives as optional arguments to build from,
# otherwise archive will be built from sources by apkg
# second argument is optional release number (defaults to 1)
#
# output at pkg/obs/ (removed on each run)
set -o errexit -o nounset

pushd "$(dirname ${0})/.."

OUTDIR="pkg/obs"
APKG_OPTS="-O $OUTDIR"

if [ -z $@ ]; then
    echo "building OBS srcpkg from project files"
else
    AR=$1
    echo "building OBS srcpkg from specified archive(s)"
    APKG_OPTS="-a $AR $APKG_OPTS"

    RELEASE=${2:-}
    if [ ! -z "$RELEASE" ]; then
        echo "custom release: $RELEASE"
        APKG_OPTS="-r $RELEASE $APKG_OPTS"
    fi
fi

set -o xtrace

: removing existing output files at output dir: $OUTDIR
rm -rf "$OUTDIR"
: making debian source package from archive
apkg srcpkg $APKG_OPTS -d debian
: removing extra debian source package files
rm -f $OUTDIR/*_source.*
: rendering RPM template
apkg srcpkg $APKG_OPTS -d fedora --render-template
: fixing RPM .spec to use debian source archive
sed -i 's/^\(Source0:\s\+\).*/\1knot-resolver_%{version}.orig.tar.xz/' $OUTDIR/*.spec
: rendering PKGBUILD template
apkg srcpkg $APKG_OPTS -d arch --render-template
: fixing PKGBUILD to use debian source archive
sed -i 's/^source=.*/source=("knot-resolver_${pkgver}.orig.tar.xz")/' $OUTDIR/PKGBUILD
popd >/dev/null

echo "OBS srcpkg ready at: $OUTDIR"

