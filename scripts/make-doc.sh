#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset
cd "$(dirname "${0}")/.."

# generate JSON schema for the manager's declarative config
pushd manager
## the following python command should hopefully run without any dependencies except for standard python
mkdir -p ../doc/_static/
python3 -m knot_resolver_manager.cli schema > ../doc/_static/config.schema.json
generate-schema-doc --config expand_buttons=true ../doc/_static/config.schema.json ../doc/_static/schema_doc.html
popd

# generating the user documentation
SPHINX=$(type -P sphinx-build-3 sphinx-build | head -n1)
rm -rf doc/html
"$SPHINX" "$@" -b html -d doc/user/.doctrees doc/user doc/html

pushd doc/dev
doxygen
popd

# generating the developer documentation
rm -rf doc/html/dev
"$SPHINX" "$@" -b html -d doc/dev/.doctrees doc/dev doc/html/dev
