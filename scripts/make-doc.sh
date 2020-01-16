#!/bin/bash
cd "$(dirname ${0})/.."

pushd doc
doxygen
popd

SPHINX=$(command -v sphinx-build-3)
if [ $? -ne 0 ]; then
    SPHINX=$(command -v sphinx-build-3.6)
    if [ $? -ne 0 ]; then
        SPHINX=$(command -v sphinx-build)
    fi
fi

set -o errexit -o nounset

rm -rf doc/html
${SPHINX} -W -b html -d doc/.doctrees doc doc/html
