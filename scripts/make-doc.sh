#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
cd "$(dirname ${0})/.."

pushd doc
doxygen
popd

SPHINX=$(command -v sphinx-build-3)
if [ $? -ne 0 ]; then
    SPHINX=$(command -v sphinx-build)
fi

set -o errexit -o nounset

rm -rf doc/html
${SPHINX} ${@} -b html -d doc/.doctrees doc doc/html

if command -v makeinfo &>/dev/null; then
    rm -rf doc/texinfo
    ${SPHINX} ${@} -b texinfo -d doc/.doctrees doc doc/texinfo && \
        make -C doc/texinfo info
    mkdir doc/texinfo/.install
    mv doc/texinfo/knot-resolver.info doc/texinfo/.install/
fi
