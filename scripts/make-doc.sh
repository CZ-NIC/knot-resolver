#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
cd "$(dirname ${0})/.."

# generate JSON schema for the manager's declarative config
pushd manager
## the following python command should hopefully run without any dependencies except for standard python
mkdir -p ../doc/_static/
python3 -m knot_resolver_manager.cli schema > ../doc/_static/config.schema.json
generate-schema-doc --config expand_buttons=true ../doc/_static/config.schema.json ../doc/_static/schema_doc.html

# generate readable version of the JSON schema
# we could replace jsonschema2md with the following at some point in the future:
#generate-schema-doc --config template_name=md --config show_toc=false ../doc/_static/config.schema.json ../doc/_static/schema_doc.md
jsonschema2md ../doc/_static/config.schema.json /dev/stdout | sed 's/^#/###/' > ../doc/config-schema-body.md
popd


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
    ${SPHINX} ${@} -b texinfo -d doc/.doctrees doc doc/texinfo

    # Sphinx < 2 doesn't create a separate directory for figures, so if
    # necessary move them to the correct location and update the references in
    # the generated Texinfo file
    if [ ! -d doc/texinfo/knot-resolver-figures ]; then
        cd doc/texinfo
        mkdir knot-resolver-figures
        mv *.png *.svg knot-resolver-figures/
        sed -e 's/\(@image{\)/\1knot-resolver-figures\//' \
            knot-resolver.texi > knot-resolver.texi.tmp
        mv knot-resolver.texi.tmp knot-resolver.texi
        cd ../..
    fi

    make -C doc/texinfo info

    mkdir doc/texinfo/.install
    mv doc/texinfo/knot-resolver.info \
       doc/texinfo/knot-resolver-figures \
       doc/texinfo/.install/
fi
