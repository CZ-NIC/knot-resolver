# SPDX-License-Identifier: GPL-3.0-or-later

ARG KRES_BASE_IMG
ARG KNOT_BRANCH=3.1

FROM ${KRES_BASE_IMG}
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>

# build and install latest version of Knot DNS
RUN git clone --depth=1 --branch=$KNOT_BRANCH https://gitlab.nic.cz/knot/knot-dns.git /tmp/knot
WORKDIR /tmp/knot
RUN pwd
RUN autoreconf -if
RUN ./configure --prefix=/usr --enable-xdp=yes --disable-documentation
RUN CFLAGS="-g" make
RUN make install
RUN ldconfig

WORKDIR /root
