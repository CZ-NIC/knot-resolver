# SPDX-License-Identifier: GPL-3.0-or-later

CFLAGS="$CFLAGS -Wall -pedantic -fno-omit-frame-pointer"
LDFLAGS="$LDFLAGS -Wl,--as-needed"
meson build_packaging \
	--buildtype=plain \
	--prefix=/usr \
	--libdir=lib \
	-Ddoc=enabled \
	-Dsystemd_files=enabled \
	-Dclient=enabled \
	-Dkeyfile_default=/usr/share/dns/root.key \
	-Droot_hints=/usr/share/dns/root.hints \
	-Dinstall_kresd_conf=enabled \
	-Dunit_tests=enabled \
	-Dc_args="${CFLAGS}" \
	-Dc_link_args="${LDFLAGS}"

ninja -C build_packaging

