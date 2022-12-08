#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Run on 'meson dist' to copy VCS information (e.g. to generate documentation
# with correct copyright year)
set -o errexit -o nounset -o xtrace

if [ -z "$MESON_DIST_ROOT" ]; then
	echo "MESON_DIST_ROOT is not set! Must be run from 'meson dist'!" >&2
	exit 1
fi
if [ -z "$MESON_SOURCE_ROOT" ]; then
	echo "MESON_SOURCE_ROOT is not set! Must be run from 'meson dist'!" >&2
	exit 1
fi

cp "$MESON_SOURCE_ROOT/.kr-vcs-info" "$MESON_DIST_ROOT"
