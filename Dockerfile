# Intermediate container for Knot DNS build (not persistent)
FROM debian:stable AS knot-dns-build
ARG KNOT_DNS_VERSION=v2.7.2

# Build dependencies
ENV KNOT_DNS_BUILD_DEPS git-core build-essential libtool autoconf pkg-config \
	libgnutls28-dev	libprotobuf-dev libprotobuf-c-dev libfstrm-dev
ENV KNOT_RESOLVER_BUILD_DEPS build-essential pkg-config bsdmainutils liblmdb-dev \
	libluajit-5.1-dev libuv1-dev libprotobuf-dev libprotobuf-c-dev \
	libfstrm-dev luajit lua-sec lua-socket
ENV BUILDENV_DEPS ${KNOT_DNS_BUILD_DEPS} ${KNOT_RESOLVER_BUILD_DEPS}
RUN apt-get update -qq && \
	apt-get -y -qqq install ${BUILDENV_DEPS}

# Install Knot DNS from sources
RUN git clone -b $KNOT_DNS_VERSION --depth=1 https://gitlab.labs.nic.cz/knot/knot-dns.git /tmp/knot-dns && \
	cd /tmp/knot-dns && \
	autoreconf -if && \
	./configure --disable-static --disable-fastparser --disable-documentation \
		--disable-daemon --disable-utilities --with-lmdb=no && \
	make -j4 install && \
	ldconfig

# Copy libknot, libdnssec, libzscanner to runtime
RUN mkdir -p /tmp/root/usr/local/include /tmp/root/usr/local/lib /tmp/root/usr/local/lib/pkgconfig && \
	cp -rt /tmp/root/usr/local/include /usr/local/include/libknot /usr/local/include/libdnssec /usr/local/include/libzscanner && \
	cp -rt /tmp/root/usr/local/lib /usr/local/lib/libknot* /usr/local/lib/libdnssec* /usr/local/lib/libzscanner* && \
	cp -rt /tmp/root/usr/local/lib/pkgconfig /usr/local/lib/pkgconfig/libknot.pc /usr/local/lib/pkgconfig/libdnssec.pc /usr/local/lib/pkgconfig/libzscanner.pc


# Intermediate container with runtime dependencies
FROM debian:stable-slim AS runtime

# Install runtime dependencies
ENV KNOT_DNS_RUNTIME_DEPS libgnutls30
ENV KNOT_RESOLVER_RUNTIME_DEPS liblmdb0 luajit libluajit-5.1-2 libuv1 lua-sec lua-socket
ENV KNOT_RESOLVER_RUNTIME_DEPS_HTTP libjs-bootstrap libjs-d3 libjs-jquery lua-http lua-mmdb
ENV KNOT_RESOLVER_RUNTIME_DEPS_EXTRA libfstrm0 lua-cqueues
ENV KNOT_RESOLVER_RUNTIME_DEPS_SSL ca-certificates
ENV RUNTIME_DEPS ${KNOT_DNS_RUNTIME_DEPS} ${KNOT_RESOLVER_RUNTIME_DEPS} \
    ${KNOT_RESOLVER_RUNTIME_DEPS_HTTP} ${KNOT_RESOLVER_RUNTIME_DEPS_EXTRA} \
    ${KNOT_RESOLVER_RUNTIME_DEPS_SSL}
RUN apt-get update -qq && \
	apt-get install -y -qqq ${RUNTIME_DEPS} && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*


# Intermediate container for Knot Resolver build
FROM knot-dns-build AS build

# Get Knot Resolver code from current directory
COPY . /tmp/knot-resolver

# Build Knot Resolver
ARG CFLAGS="-O2 -fstack-protector -g"
ENV LDFLAGS -Wl,--as-needed
RUN cd /tmp/knot-resolver && \
	make "-j$(nproc)" && \
	make install DESTDIR=/tmp/root && \
	mkdir -p /tmp/root/etc/knot-resolver && \
	cp ./etc/config.docker /tmp/root/etc/knot-resolver/kresd.conf && \
	cp ./distro/common/root.keys /tmp/root/etc/knot-resolver/


# Final container
FROM runtime
LABEL cz.knot-resolver.vendor="CZ.NIC"
LABEL maintainer="knot-resolver-users@lists.nic.cz"

# Export DNS over UDP & TCP, DNS-over-TLS, web interface
EXPOSE 53/UDP 53/TCP 853/TCP 8053/TCP

# Fetch Knot Resolver + Knot DNS libraries from build image
COPY --from=build /tmp/root/ /
RUN ldconfig

ENTRYPOINT ["/usr/local/sbin/kresd"]
CMD ["-c", "/etc/knot-resolver/kresd.conf"]
