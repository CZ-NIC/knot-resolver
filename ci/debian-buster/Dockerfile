FROM debian:buster-20190204
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
ARG KNOT_BRANCH=2.7

WORKDIR /root
CMD ["/bin/bash"]

# generic cleanup
RUN apt-get update -qq
# TODO: run upgrade once buster reaches a stable release
# RUN apt-get upgrade -y -qqq

# Knot and Knot Resolver dependecies
RUN apt-get install -y -qqq git make cmake pkg-config build-essential bsdmainutils libtool autoconf liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev libsystemd-dev libidn11-dev protobuf-c-compiler libfstrm-dev libuv1-dev libcmocka-dev libluajit-5.1-dev lua-sec lua-socket lua-http meson
# documentation dependecies
RUN apt-get install -y -qqq doxygen python3-sphinx python3-breathe python3-sphinx-rtd-theme

# Python packags required for Deckard CI
# Python: grab latest versions from PyPi
# (dnspython and Augeas binding in Debian packages are slow and buggy)
RUN apt-get install -y -qqq python3-pip wget augeas-tools
RUN pip3 install --upgrade pip
RUN pip3 install pylint
RUN pip3 install pep8
RUN pip3 install pytest-xdist
# tests/pytest dependencies
RUN pip3 install dnspython jinja2 pytest pytest-html pytest-xdist

# C dependencies for python-augeas
RUN apt-get install -y -qqq libaugeas-dev libffi-dev
# Python dependencies for Deckard
RUN wget https://gitlab.labs.nic.cz/knot/deckard/raw/master/requirements.txt -O /tmp/deckard-req.txt
RUN pip3 install -r /tmp/deckard-req.txt

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
RUN apt-get install valgrind -y -qqq
RUN wget https://github.com/LuaJIT/LuaJIT/raw/v2.1.0-beta3/src/lj.supp -O /lj.supp
# TODO: rebuild LuaJIT with Valgrind support

# Lua lint for kresd CI
RUN apt-get install luarocks -y -qqq
RUN luarocks install luacheck

# respdiff for kresd CI
RUN apt-get install lmdb-utils -y -qqq
RUN git clone --depth=1 https://gitlab.labs.nic.cz/knot/respdiff /var/opt/respdiff
RUN pip3 install -r /var/opt/respdiff/requirements.txt

# Python static analysis for respdiff
RUN pip3 install mypy
RUN pip3 install flake8

# Python requests for CI scripts
RUN pip3 install requests

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
RUN luarocks install luacov

# LuaJIT binary for stand-alone scripting
RUN apt-get install -y -qqq luajit

# OpenBuildService CLI tool
RUN apt-get install -y osc

# curl (API)
RUN apt-get install -y curl
