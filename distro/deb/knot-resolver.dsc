Format: 3.0 (quilt)
Source: knot-resolver
Binary:
 knot-resolver,
 knot-resolver-module-http,
 knot-resolver-doc,
 libkres7,
 libkres-dev
Architecture: any all
Version: __VERSION__-1
Maintainer: Knot Resolver <knot-resolver@labs.nic.cz>
Uploaders:  Tomas Krizek <tomas.krizek@nic.cz>
Homepage: https://www.knot-resolver.cz/
Testsuite: autopkgtest
Build-Depends:
 debhelper (>= 9~),
 dns-root-data,
 libcmocka-dev (>= 1.0.0),
 libedit-dev,
 libgeoip-dev,
 libgnutls28-dev,
 libhiredis-dev,
 libjansson-dev,
 libknot-dev (>= 2.6.4),
 liblmdb-dev,
 libluajit-5.1-dev,
 libmemcached-dev,
 libsystemd-dev (>= 227),
 libuv1-dev,
 luajit,
 pkg-config,
 python3
Build-Depends-Indep:
 doxygen,
 python3-breathe,
 python3-sphinx,
 python3-sphinx-rtd-theme
Package-List:
 knot-resolver deb net optional arch=any
 knot-resolver-doc deb doc optional arch=all
 knot-resolver-module-http deb net optional arch=all
 libkres-dev deb libdevel optional arch=any
 libkres7 deb libs optional arch=any
Files:
