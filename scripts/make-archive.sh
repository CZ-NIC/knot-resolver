#!/bin/bash
set -o nounset

# Create a distribution tarball, like 'make dist' from autotools.
cd "${MESON_SOURCE_ROOT}"

# Check if git is clean
test 0 -ne $(git status --porcelain -uno | wc -l) && \
    echo "ERROR: Git working tree is dirty, make it clean first" && \
    exit 1
git submodule status --recursive | grep -q '^[^ ]' && \
    echo "ERROR: Git submodules are dirty, run: git submodule update --recursive --init" && \
    exit 2

RELEASE_VERSION="${1}"  # pass in version from meson.project_version()
VERSION="${RELEASE_VERSION}"

# Check version and use devel version if appicable
export GIT_DIR="${MESON_SOURCE_ROOT}/.git"
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null)
HAS_GIT=$?
GIT_TAG=$(git describe --exact-match 2>/dev/null)
HAS_TAG=$?

if  [[ ${HAS_GIT} -eq 0 ]]; then
    if [[ ${HAS_TAG} -eq 0 ]]; then
        # git tag must match release version number
        if [ "${GIT_TAG}" != "v${RELEASE_VERSION}" ]; then
            echo "ERROR: Release version number doesn't match git tag!"
            exit 1
        fi
    else
        # devel verion has <TIMESTAMP>.<GIT_HASH> appended to it
        # if more than one branch is actively developed, switch to the same
        # version model as Knot DNS (X.Y.dev.T.G for master, X.Y.Z.T.G for older)
        TIMESTAMP=$(date -u +'%s' 2>/dev/null)
        VERSION="${RELEASE_VERSION}.${TIMESTAMP}.${GIT_HASH}"
    fi
fi

# 'git ls-files --recurse-submodules' works only if modules are initialized
NAME="knot-resolver-${VERSION}"
tar caf "${NAME}.tar.xz" -h --no-recursion --transform "s|^|${NAME}/|" -- $(git ls-files --recurse-submodules)
echo "$PWD/${NAME}.tar.xz"
