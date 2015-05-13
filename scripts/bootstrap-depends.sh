#!/bin/bash  
set -e

CMOCKA_TAG="cmocka-0.4.1"
CMOCKA_URL="git://git.cryptomilk.org/projects/cmocka.git"
LIBUV_TAG="v1.5.0"
LIBUV_URL="https://github.com/libuv/libuv.git"
KNOT_TAG="master"
KNOT_URL="https://github.com/CZ-NIC/knot.git"
GMP_TAG="6.0.0"
GMP_URL="https://gmplib.org/download/gmp/gmp-${GMP_TAG}.tar.xz"
JANSSON_TAG="2.7"
JANSSON_URL="http://www.digip.org/jansson/releases/jansson-${JANSSON_TAG}.tar.gz"
NETTLE_TAG="2.7.1"
NETTLE_URL="https://ftp.gnu.org/gnu/nettle/nettle-${NETTLE_TAG}.tar.gz"
GNUTLS_TAG="3.3.12"
GNUTLS_URL="ftp://ftp.gnutls.org/gcrypt/gnutls/v3.3/gnutls-${GNUTLS_TAG}.tar.xz"
LUA_TAG="5.2.3"
LUA_URL="http://www.lua.org/ftp/lua-${LUA_TAG}.tar.gz"

# prepare install prefix
PREFIX=${1}; [ -z ${PREFIX} ] && export PREFIX="${HOME}/.local"
install -d ${PREFIX}/{lib,libexec,include,bin,sbin,man,share,etc,info,doc,var}

# prepare build env
export PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig"
export BUILD_DIR="$(pwd)/.build-depend"
export LOG=$(pwd)/build.log
[ ! -e ${BUILD_DIR} ] && mkdir ${BUILD_DIR}; cd ${BUILD_DIR}
echo "build: ${BUILD_DIR}"
echo "log:   ${LOG}" | tee ${LOG}

function on_failure {
	cat ${LOG}
}
trap on_failure ERR

function fetch_pkg {
	if [ "${2##*.}" == git ]; then
		[ ! -e $1 ] && git clone -b $3 "$2" $1 &> /dev/null
	else
		[ ! -f $1.tar.${2##*.} ] && curl "$2" > $1.tar.${2##*.}
		tar xf $1.tar.${2##*.}
	fi
	cd $1
}

function build_pkg {
	if [ -f configure.ac ]; then
		if [ ! -e ./configure ]; then
			[ -e autogen.sh ] && sh autogen.sh || autoreconf -if
		fi
		./configure --prefix=${PREFIX} --enable-shared $*
		make ${MAKEOPTS}
		make install
	elif [ -f CMakeLists.txt ]; then
		[ -e cmake-build ] && rm -rf cmake-build; mkdir cmake-build; cd cmake-build
		cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} ..
		make ${MAKEOPTS}
		make install
	else
		make $*
	fi
}

function pkg {
	if [ ! -e ${PREFIX}/$4 ] && [ "${BUILD_IGNORE}" == "${BUILD_IGNORE/$1/}" ] ; then
		cd ${BUILD_DIR}
		echo "[x] fetching $1-$3"
		fetch_pkg "$1-$3" "$2" $3 >> ${LOG}
		echo "[x] building $1-$3"
		shift 4
		(build_pkg $*) >> ${LOG} 2>&1
	fi
}

# travis-specific
PIP_PKGS="${TRAVIS_BUILD_DIR}/tests/pydnstest/requirements.txt cpp-coveralls"
if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
	DEPEND_CACHE="https://dl.dropboxusercontent.com/u/2255176/resolver-${TRAVIS_OS_NAME}-cache.tar.gz"
	curl "${DEPEND_CACHE}" > cache.tar.gz && tar -xz -C ${HOME} -f cache.tar.gz || true
	brew update
	brew install --force makedepend python libtasn1 || true
	brew link --overwrite python || true
	pip install --upgrade pip || true
	pip install -r ${PIP_PKGS}
fi
if [ "${TRAVIS_OS_NAME}" == "linux" ]; then
	pip install --user ${USER} -r ${PIP_PKGS}
	rm ${HOME}/.cache/pip/log/debug.log || true
fi

# gnutls + dependencies
pkg gmp ${GMP_URL} ${GMP_TAG} include/gmp.h --disable-static
pkg nettle ${NETTLE_URL} ${NETTLE_TAG} include/nettle \
	--disable-documentation --with-lib-path=${PREFIX}/lib --with-include-path=${PREFIX}/include
export GMP_CFLAGS="-I${PREFIX}/include"
export GMP_LIBS="-L${PREFIX}/lib -lgmp"
pkg gnutls ${GNUTLS_URL} ${GNUTLS_TAG} include/gnutls \
	--disable-tests --disable-doc --disable-valgrind-tests --disable-static
# jansson
pkg jansson ${JANSSON_URL} ${JANSSON_TAG} include/jansson.h --disable-static
# libknot
pkg libknot ${KNOT_URL} ${KNOT_TAG} include/libknot \
	--disable-static --with-lmdb=no --disable-fastparser --disable-daemon --disable-utilities --disable-documentation
# cmocka
pkg cmocka ${CMOCKA_URL} ${CMOCKA_TAG} include/cmocka.h
# libuv
pkg libuv ${LIBUV_URL} ${LIBUV_TAG} include/uv.h --disable-static
# lua
pkg lua ${LUA_URL} ${LUA_TAG} include/lua.h generic install INSTALL_TOP=${PREFIX}
if [ ! -f ${PREFIX}/lib/pkgconfig/lua.pc ]; then
cat > ${PREFIX}/lib/pkgconfig/lua.pc << EOF
prefix=${PREFIX}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: Lua
Description: An Extensible Extension Language
Version: ${LUA_TAG}
Requires:
Libs: -L\${libdir} -llua -lm
Cflags: -I\${includedir}
EOF
fi

# remove on successful build
rm -rf ${BUILD_DIR}
