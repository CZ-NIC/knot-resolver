#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Return latest upstream version of Knot Resolver
#
# This script is used by apkg to detect latest upstream version, test with:
#
#     apkg info upstream-version
#     apkg get-archive
#
# It must only output valid YAML to stdout!
set -o errexit

REPO=https://gitlab.nic.cz/knot/knot-resolver.git

VERSION=$(git ls-remote --tags --refs $REPO | cut -f2- | sed -n "s#^refs/tags/v##p" | sort -V | tail -1)
echo "version: $VERSION"
