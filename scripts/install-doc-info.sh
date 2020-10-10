#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset

# Install the Info manual
make -C "${MESON_SOURCE_ROOT}/doc/texinfo" \
     infodir="${MESON_INSTALL_DESTDIR_PREFIX}/share/info" \
     install-info
