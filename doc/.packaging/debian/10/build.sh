#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
[ -d /root/kresd/build_packaging ] && rm -rf /root/kresd/build_packaging/;
CFLAGS="$CFLAGS -Wall -pedantic -fno-omit-frame-pointer"
LDFLAGS="$LDFLAGS -Wl,--as-needed"
meson build_packaging \
	--buildtype=plain \
	--prefix=/root/kresd/install_packaging \
	--libdir=lib \
	--default-library=static \
	-Ddoc=enabled \
	-Dsystemd_files=enabled \
	-Dclient=enabled \
	-Dkeyfile_default=/usr/share/dns/root.key \
	-Droot_hints=/usr/share/dns/root.hints \
	-Dinstall_kresd_conf=enabled \
	-Dunit_tests=enabled \
	-Dc_args="${CFLAGS}" \
	-Dc_link_args="${LDFLAGS}";
