# SPDX-License-Identifier: GPL-3.0-or-later

FROM debian:bullseye
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
# >= 3.0 needed because of --enable-xdp=yes
ARG KNOT_BRANCH=3.1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /root
CMD ["/bin/bash"]

# dependencies (mounts and rm to force cache utilization)
RUN \
	--mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
	--mount=target=/var/cache/apt,type=cache,sharing=locked \
	\
	rm -f /etc/apt/apt.conf.d/docker-clean && \
	\
	apt-get update -qq && \
	apt-get install --no-install-suggests --no-install-recommends -y -qqq \
		\
		`# Knot DNS and Knot Resolver` \
		git make cmake pkg-config meson build-essential bsdmainutils \
		libtool autoconf automake libcmocka-dev liburcu-dev \
		libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev \
		libsystemd-dev libelf-dev libmnl-dev libidn11-dev libuv1-dev \
		libjemalloc-dev libluajit-5.1-dev lua-http libssl-dev \
		libnghttp2-dev libbpf-dev luajit

# build and install latest version of Knot DNS
RUN git clone --depth=1 --branch=$KNOT_BRANCH https://gitlab.nic.cz/knot/knot-dns.git /tmp/knot
WORKDIR /tmp/knot
RUN pwd
RUN autoreconf -if
RUN ./configure --prefix=/usr --enable-xdp=yes --disable-documentation
RUN CFLAGS="-g" make
RUN make install
RUN ldconfig
