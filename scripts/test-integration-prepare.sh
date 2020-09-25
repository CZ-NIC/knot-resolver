#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset

cd "${1}"

git submodule update --init --recursive
make depend &>/dev/null
