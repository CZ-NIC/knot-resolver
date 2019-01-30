#!/bin/bash
set -o errexit -o nounset

cd $1
doxygen
