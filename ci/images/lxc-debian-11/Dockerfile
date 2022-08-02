# SPDX-License-Identifier: GPL-3.0-or-later

FROM registry.nic.cz/labs/lxc-gitlab-runner/debian-11:latest
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
# >= 3.0 needed because of --enable-xdp=yes
ARG KNOT_BRANCH=3.1
ENV DEBIAN_FRONTEND=noninteractive

# generic cleanup
RUN apt-get update -qq

# Knot and Knot Resolver dependencies
RUN apt-get install -y -qqq git make cmake pkg-config meson \
	build-essential bsdmainutils libtool autoconf libcmocka-dev \
	liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev libsystemd-dev \
	libelf-dev libmnl-dev libidn11-dev libuv1-dev \
	libluajit-5.1-dev lua-http libssl-dev libnghttp2-dev

# Build and testing deps for Resolver's dnstap module (go stuff is just for testing)
RUN apt-get install -y -qqq \
	protobuf-c-compiler libprotobuf-c-dev libfstrm-dev \
	golang-any
RUN bash -c "go get github.com/{FiloSottile/gvt,cloudflare/dns,dnstap/golang-dnstap,golang/protobuf/proto}"

# documentation dependencies
RUN apt-get install -y -qqq doxygen python3-sphinx python3-breathe python3-sphinx-rtd-theme

# Python packages required for Deckard CI
# Python: grab latest versions from PyPi
# (Augeas binding in Debian packages are slow and buggy)
RUN apt-get install -y -qqq python3-pip wget augeas-tools
RUN pip3 install --upgrade pip
RUN pip3 install pylint
RUN pip3 install pep8
RUN pip3 install pytest-xdist
# FIXME replace with dnspython >= 2.2.0 once released
RUN pip3 install git+https://github.com/bwelling/dnspython.git@72348d4698a8f8b209fbdf9e72738904ad31b930
# tests/pytest dependencies: skip over broken versions
RUN pip3 install jinja2 'pytest != 6.0.0' pytest-html pytest-xdist
# apkg for packaging
RUN pip3 install apkg

# packet capture tools for Deckard
RUN apt-get install --no-install-suggests --no-install-recommends -y -qqq tcpdump wireshark-common

# Faketime for Deckard
RUN apt-get install -y -qqq faketime

# C dependencies for python-augeas
RUN apt-get install -y -qqq libaugeas-dev libffi-dev
# Python dependencies for Deckard
RUN wget https://gitlab.nic.cz/knot/deckard/raw/master/requirements.txt -O /tmp/deckard-req.txt
RUN pip3 install -r /tmp/deckard-req.txt

# build and install latest version of Knot DNS
RUN git clone --depth=1 --branch=$KNOT_BRANCH https://gitlab.nic.cz/knot/knot-dns.git /tmp/knot
WORKDIR /tmp/knot
RUN pwd
RUN autoreconf -if
RUN ./configure --prefix=/usr --enable-xdp=yes
RUN CFLAGS="-g" make
RUN make install
RUN ldconfig

# Valgrind for kresd CI
RUN apt-get install valgrind -y -qqq
RUN wget https://github.com/LuaJIT/LuaJIT/raw/v2.1.0-beta3/src/lj.supp -O /lj.supp
# TODO: rebuild LuaJIT with Valgrind support

# Lua lint for kresd CI
RUN apt-get install luarocks -y -qqq
RUN luarocks --lua-version 5.1 install luacheck

# respdiff for kresd CI
RUN apt-get install lmdb-utils -y -qqq
RUN git clone --depth=1 https://gitlab.nic.cz/knot/respdiff /var/opt/respdiff
RUN pip3 install -r /var/opt/respdiff/requirements.txt

# Python static analysis for respdiff
RUN pip3 install mypy
RUN pip3 install flake8

# Python requests for CI scripts
RUN pip3 install requests

# docker-py for packaging tests
RUN pip3 install docker

# Unbound for respdiff
RUN apt-get install unbound unbound-anchor -y -qqq
RUN printf "server:\n interface: 127.0.0.1@53535\n use-syslog: yes\n do-ip6: no\nremote-control:\n control-enable: no\n" >> /etc/unbound/unbound.conf

# BIND for respdiff
RUN apt-get install bind9 -y -qqq
RUN printf '\nOPTIONS="-4 $OPTIONS"' >> /etc/default/bind9
RUN printf 'options {\n directory "/var/cache/bind";\n listen-on port 53533 { 127.0.0.1; };\n listen-on-v6 port 53533 { ::1; };\n};\n' > /etc/bind/named.conf.options

# PowerDNS Recursor for Deckard CI
RUN apt-get install pdns-recursor -y -qqq

# code coverage
RUN apt-get install -y -qqq lcov
RUN luarocks --lua-version 5.1 install luacov

# LuaJIT binary for stand-alone scripting
RUN apt-get install -y -qqq luajit

# clang for kresd CI, version updated as debian updates it
RUN apt-get install -y -qqq clang clang-tools clang-tidy

# OpenBuildService CLI tool
RUN apt-get install -y osc

# curl (API)
RUN apt-get install -y curl

# configure knot-resolver-testing OBS repo for dependencies missing in Debian
RUN echo 'deb http://download.opensuse.org/repositories/home:/CZ-NIC:/knot-resolver-testing/Debian_11/ /' > /etc/apt/sources.list.d/knot-resolver-testing.list
RUN wget -nv https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-testing/Debian_11/Release.key -O Release.key
RUN APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1 apt-key add Release.key
RUN rm Release.key
RUN apt-get update -qq

# packages from our knot-resolver-testing repo
RUN apt-get update
RUN apt-get install -y -qqq lua-psl

# en_US.UTF-8 locale for scripts.update-authors.sh
RUN apt-get install -y -qqq locales
RUN sed -i "/en_US.UTF-8/ s/^#\(.*\)/\1/" /etc/locale.gen
RUN locale-gen
