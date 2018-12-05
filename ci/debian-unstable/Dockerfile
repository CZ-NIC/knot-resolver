FROM debian:unstable
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
ARG KNOT_BRANCH=2.7

WORKDIR /root
CMD ["/bin/bash"]

# generic cleanup
RUN apt-get update -qq
RUN apt-get upgrade -y -qqq

# Knot and Knot Resolver dependecies
RUN apt-get install -y -qqq make cmake pkg-config git build-essential bsdmainutils libtool autoconf liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev libsystemd-dev libidn11-dev protobuf-c-compiler libfstrm-dev libuv1-dev libcmocka-dev libluajit-5.1-dev lua-sec lua-socket lua-http

# build and install latest version of Knot DNS
# (kresd depends on libknot and libdnssec)
RUN git clone --depth=1 --branch=$KNOT_BRANCH https://gitlab.labs.nic.cz/knot/knot-dns.git /tmp/knot
WORKDIR /tmp/knot
RUN pwd
RUN autoreconf -if
RUN ./configure --prefix=/usr
RUN make
RUN make install
RUN ldconfig

# Valgrind for kresd CI
RUN apt-get install valgrind wget -y -qqq
RUN wget https://raw.githubusercontent.com/LuaJIT/LuaJIT/v2.0.4/src/lj.supp -O /lj.supp
# TODO: rebuild LuaJIT with Valgrind support

# Lua lint for kresd CI
RUN apt-get install luarocks -y -qqq
RUN luarocks install luacheck

# code coverage
RUN apt-get install -y -qqq lcov
RUN luarocks install luacov

# LuaJIT binary for stand-alone scripting
RUN apt-get install -y -qqq luajit

# clang for kresd CI, version updated as debian updates it
RUN apt-get install -y -qqq clang clang-tools clang-tidy
