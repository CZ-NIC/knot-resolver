#!/bin/sh  
set -e

CMOCKA_TAG="cmocka-0.4.1"
PKG_CONFIG_PATH="${1}/lib/pkgconfig"

if [ -z ${1} ]; then
	echo "$0 <fakeroot>"
	exit 1
fi

install -d ${1}

# lmdb
if [ ! -e ${1}/include/lmdb.h ]; then
	git clone https://gitorious.org/mdb/mdb.git || true
	cd mdb/libraries/liblmdb
	make
	install -d ${1}/lib ${1}/include
	install -t ${1}/lib liblmdb.so
	install -t ${1}/include lmdb.h
	cd ../../..
fi

# liburcu
if [ ! -e ${1}/include/urcu.h ]; then
	git clone git://git.urcu.so/userspace-rcu.git || true
	cd userspace-rcu
	./bootstrap
	./configure --prefix=${1}
	make
	make install
	cd ..
fi

# libknot
if [ ! -e ${1}/include/libknot ]; then
	git clone https://github.com/CZNIC-Labs/knot.git || true
	cd knot
	git checkout resolver_improvements
	autoreconf -i
	./configure --prefix=${1}
	make
	make install
	cd ..
fi

# cmocka
if [ ! -e ${1}/include/cmocka.h ]; then
	wget http://git.cryptomilk.org/projects/cmocka.git/snapshot/${CMOCKA_TAG}.tar.gz
	tar xvzf ${CMOCKA_TAG}.tar.gz
	cd ${CMOCKA_TAG}
	mkdir build
	cd build
	cmake -DCMAKE_INSTALL_PREFIX=${1} ..
	make
	make install
	cd ../..
fi

# libuv
if [ ! -e ${1}/include/uv.h ]; then
	git clone https://github.com/libuv/libuv.git || true
	cd libuv
	sh autogen.sh
	./configure --prefix=${1}
	make 
	make install
fi
