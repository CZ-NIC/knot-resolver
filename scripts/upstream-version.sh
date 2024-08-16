#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# return latest upstream 5.x version of Knot Resolver
set -o errexit

REPO=https://gitlab.nic.cz/knot/knot-resolver.git

git ls-remote --tags --refs $REPO | cut -f2- | sed -n "s#^refs/tags/v##p" | grep '^5\.' | sort -V | tail -1
