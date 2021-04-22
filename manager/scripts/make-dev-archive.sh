#!/bin/bash
# create dev archive from current repo HEAD
set -o errexit -o nounset

cd "$(dirname ${0})/.."

if ! command -v poetry &> /dev/null
then
    echo "poetry is required to create archive: pip install poetry"
    exit 1
fi

set -o xtrace

# create archive using poetry and get its name
ARNAME=$(poetry build -f sdist | sed -n 's/\s\+- Built \(knot-resolver-manager-.*\.tar\.gz\)/\1/p')
ARPATH="dist/$ARNAME"

# print path to generated archive for apkg
echo "$ARPATH"
