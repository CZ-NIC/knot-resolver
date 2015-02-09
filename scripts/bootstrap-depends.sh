#!/bin/bash  
set -e

CMOCKA_TAG="cmocka-0.4.1"
URCU_TAG="v0.8.6"
LIBUV_TAG="v1.3.0"
KNOT_TAG="master"

# prepare build env
PREFIX=${1}; [ -z ${PREFIX} ] && PREFIX="${HOME}/.local"
PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig"
install -d ${PREFIX}/{lib,libexec,include,bin,sbin,man,share,etc,info,doc,var}
[ ! -d .depend ] && mkdir .depend; cd .depend

# platform-specific
if [ "$TRAVIS_OS_NAME" == "osx" ]; then
	brew upgrade
	brew install python
fi

# liburcu
if [ ! -e ${PREFIX}/include/urcu.h ]; then
	git clone -b ${URCU_TAG} git://git.urcu.so/userspace-rcu.git || true
	cd userspace-rcu
	./bootstrap
	./configure --prefix=${PREFIX} --disable-dependency-tracking --disable-rpath
	( make ${MAKEOPTS} ; make install ) || true
	cd ..
fi

# libknot
if [ ! -e ${PREFIX}/include/libknot ]; then
	git clone -b ${KNOT_TAG} https://github.com/CZNIC-Labs/knot.git || true
	cd knot
	autoreconf -i
	if [ $(uname) == "Darwin" ]; then # Workaround for crypto version check on OS X
		export libcrypto_CFLAGS="-I /usr/local/opt/openssl/include"
		export libcrypto_LIBS="-L/usr/local/opt/openssl/lib -lcrypto"
	fi
	./configure --prefix=${PREFIX} --with-lmdb=no --disable-fastparser --disable-dependency-tracking
	make ${MAKEOPTS} && make install
	cd ..
fi

# cmocka
if [ ! -e ${PREFIX}/include/cmocka.h ]; then
	git clone -b ${CMOCKA_TAG} git://git.cryptomilk.org/projects/cmocka.git || true
	cd cmocka
	mkdir build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} ..
	make ${MAKEOPTS} && make install
	cd ../..
fi

# libuv
if [ ! -e ${PREFIX}/include/uv.h ]; then
	git clone -b ${LIBUV_TAG} https://github.com/libuv/libuv.git || true
	cd libuv
	sh autogen.sh
	./configure --prefix=${PREFIX} --disable-dependency-tracking
	make ${MAKEOPTS} && make install
fi
