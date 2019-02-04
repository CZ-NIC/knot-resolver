#!/bin/bash
set -o errexit -o nounset

cd "${1}/deckard"

git submodule update --init --recursive
make depend
