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
DEPEND_CACHE="https://dl.dropboxusercontent.com/u/2255176/resolver-${TRAVIS_OS_NAME}-cache.tar.lzma"
PIP_PKGS="${TRAVIS_BUILD_DIR}/tests/pydnstest/requirements.txt cpp-coveralls"
if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
	brew install --force makedepend
	brew install --force python
	brew link --overwrite python
	pip install --upgrade pip
	pip install -r ${PIP_PKGS}
	if wget "${DEPEND_CACHE}" -o cache.tar.lzma; then
		echo "extracting prebuilt dependencies from ${DEPEND_CACHE}"
		tar -x -C ${HOME} -f cache.tar.lzma || true
	fi
fi
if [ "${TRAVIS_OS_NAME}" == "linux" ]; then
	pip install --user ${USER} -r ${PIP_PKGS}
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
