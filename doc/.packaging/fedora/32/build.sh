#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
[ -d /root/kresd/build_packaging ] && rm -rf /root/kresd/build_packaging/;
CFLAGS="$CFLAGS -Wall -pedantic -fno-omit-frame-pointer"
LDFLAGS="$LDFLAGS -Wl,--as-needed"
meson build_packaging \
	--buildtype=plain \
	--prefix=/root/kresd/install_packaging \
	--sbindir=sbin \
	--libdir=lib \
	--includedir=include \
	--sysconfdir=etc \
	-Ddoc=enabled \
	-Dsystemd_files=enabled \
	-Dclient=enabled \
	-Dunit_tests=enabled \
	-Dmanaged_ta=enabled \
	-Dkeyfile_default=/var/lib/knot-resolver/root.keys \
	-Dinstall_root_keys=enabled \
	-Dinstall_kresd_conf=enabled;
