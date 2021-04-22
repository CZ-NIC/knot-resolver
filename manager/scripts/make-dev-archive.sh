#!/bin/bash
# create dev archive from current repo HEAD

# ensure consistent behaviour
src_dir="$(dirname "$(realpath "$0")")"
source $src_dir/_env.sh


set -o xtrace

# create archive using poetry and get its name
ARNAME=$(poetry build -f sdist | sed -n 's/\s\+- Built \(knot-resolver-manager-.*\.tar\.gz\)/\1/p')
ARPATH="dist/$ARNAME"

# print path to generated archive for apkg
echo "$ARPATH"
