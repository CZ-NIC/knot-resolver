#!/bin/bash
set -o nounset
cd "$(dirname ${0})"

RELEASE_VERSION="${1}"  # pass in version from meson.project_version()

export GIT_DIR="$PWD/../.git"
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null)
HAS_GIT=$?
GIT_TAG=$(git describe --exact-match 2>/dev/null)
HAS_TAG=$?

if [[ ${HAS_GIT} -ne 0 ]]; then
    # no .git directory / git -> use release version
    echo "${RELEASE_VERSION}"
elif  [[ ${HAS_TAG} -eq 0 ]]; then
    # git tag must match release version number
    if [ "${GIT_TAG}" != "v${RELEASE_VERSION}" ]; then
        echo "Release version number doesn't match git tag!"
        exit 1
    fi
    echo "${RELEASE_VERSION}"
else
    # devel verion has <TIMESTAMP>.<GIT_HASH> appended to it
    # if more than one branch is actively developed, switch to the same
    # version model as Knot DNS (X.Y.dev.T.G for master, X.Y.Z.T.G for older)
    TIMESTAMP=$(date -u +'%s' 2>/dev/null)
    echo "${RELEASE_VERSION}.${TIMESTAMP}.${GIT_HASH}"
fi
exit 0
