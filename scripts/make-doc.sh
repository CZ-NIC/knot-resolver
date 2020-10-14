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

    # Sphinx < 2 doesn't create a separate directory for figures, so if
    # necessary move them to the correct location and update the references in
    # the generated Info file
    if [ ! -d doc/texinfo/knot-resolver-figures ]; then
        cd doc/texinfo
        mkdir knot-resolver-figures
        mv *.png *.svg knot-resolver-figures/
        sed -e 's/\(\[image .*src="\)/\1knot-resolver-figures\//' \
            knot-resolver.info > knot-resolver.info.tmp
        mv knot-resolver.info.tmp knot-resolver.info
        cd ../..
    fi

    mkdir doc/texinfo/.install
    mv doc/texinfo/knot-resolver.info \
       doc/texinfo/knot-resolver-figures \
       doc/texinfo/.install/
fi
