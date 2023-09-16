#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
cd "$(dirname ${0})/.."

# generate JSON schema for the manager's declarative config
pushd manager
## the following python command should hopefully run without any dependencies except for standard python
mkdir -p ../doc/_static/
python3 -m knot_resolver_manager.cli schema > ../doc/_static/config.schema.json
generate-schema-doc --config expand_buttons=true ../doc/_static/config.schema.json ../doc/_static/schema_doc.html
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
