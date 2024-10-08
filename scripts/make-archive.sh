#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Create a development tarball
set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

# make sure we don't accidentally add / overwrite forgotten changes in git
(git diff-index --quiet HEAD && git diff-index --cached --quiet HEAD) || \
    (echo 'git index has uncommitted changes!'; exit 1)

if ! git describe --tags --exact-match; then
    # devel version
    VERSION_TAG=$(git describe --tags | cut -d- -f1)
    VERSION=${VERSION_TAG#v}
    GIT_HASH=$(git rev-parse --short=6 HEAD)
    N_COMMITS=$(git rev-list $VERSION_TAG.. --count)
    FULL_VERSION="$VERSION.dev$N_COMMITS+$GIT_HASH"

    # modify and commit meson.build
    sed -i "s/^\(\s*version\s*:\s*'\)\([^']\+\)\('.*\)/\1$FULL_VERSION\3/" meson.build

    : changed version in meson.build, changes must be committed to git
    git add meson.build
    git commit -m 'DROP: devel version archive'

    cleanup() {
        # undo commit
        git reset --hard HEAD^ >/dev/null
    }
    trap cleanup EXIT
fi

# create tarball
rm -rf build_dist ||:
meson build_dist
ninja -C build_dist dist

# copy tarball to apkg path
DIST_ARCHIVE=$(find "build_dist/meson-dist/" -name "knot-resolver-*.tar.xz")
APKG_ARCHIVE="pkg/archives/dev/$(basename $DIST_ARCHIVE)"
mkdir -p pkg/archives/dev
cp "$DIST_ARCHIVE" "$APKG_ARCHIVE"

# remove build directory
rm -rf build_dist ||:

# print path to generated tarball as expected by apkg
echo "$APKG_ARCHIVE"
