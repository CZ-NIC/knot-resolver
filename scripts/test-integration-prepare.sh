#!/bin/bash
set -o errexit -o nounset

cd "${1}"

git submodule update --init --recursive
make depend
