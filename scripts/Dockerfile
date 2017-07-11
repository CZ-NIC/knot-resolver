FROM alpine:edge
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Environment
ENV BUILD_PKGS build-base automake autoconf libtool pkgconfig git luajit-dev libuv-dev gnutls-dev jansson-dev userspace-rcu-dev curl
ENV RUN_PKGS luajit libuv gnutls jansson bash
ENV BUILD_IGNORE gmp nettle jansson gnutls lua libuv cmocka
ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig
ENV CFLAGS -O2 -ftree-vectorize -fstack-protector -g
ENV LDFLAGS -Wl,--as-needed

# Expose port
EXPOSE 53

# Select entrypoint
WORKDIR /data
CMD ["/usr/local/sbin/kresd"]

# Install dependencies and sources
RUN \
apk --update add ${RUN_PKGS} && \
apk add --virtual build-dep ${BUILD_PKGS} && \
git clone https://gitlab.labs.nic.cz/knot/resolver.git /tmp/build && \
cd /tmp/build && \
./scripts/bootstrap-depends.sh /usr/local && \
make -j4 install && \
# Trim down the image
cd / && \
apk del --purge build-dep && \
rm -rf /var/cache/apk/* /tmp/build
