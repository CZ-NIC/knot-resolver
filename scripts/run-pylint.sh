#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset

cd "$(dirname ${0})/.."

# Find Python modules and standalone Python scripts
FILES=$(find ./tests/pytests \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-name '*.py' -print)

python3 -m pylint -j 0 --rcfile ./tests/pytests/pylintrc ${FILES}
