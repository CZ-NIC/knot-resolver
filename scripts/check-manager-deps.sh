#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This script compates the Python dependencies of manager component with the
# last packaged version.
#
# If there are any differences, first make sure to update packaging files in
# distro/pkg and then update the list below.
#

set -o nounset -o xtrace

sed -nE \
    '/\[tool.poetry.dependencies\]/,/\[tool.poetry.dev-dependencies\]/p' \
    manager/pyproject.toml \
    >/tmp/current-deps

# TODO: ensure everything is properly packaged and then update the list
cat >/tmp/previous-deps << EOF
#[tool.poetry.dependencies]
#python = "^3.6.8"
#aiohttp = "^3.6.12"
#pydbus = "^0.6.0"
#PyGObject = "^3.38.0"
#Jinja2 = "^2.11.3"
#click = "^7.1.2"
#PyYAML = "^5.4.1"
#requests = "^2.25.1"
#typing-extensions = ">=3.7.2"
#
#[tool.poetry.dev-dependencies]
EOF

diff -u /tmp/previous-deps /tmp/current-deps
