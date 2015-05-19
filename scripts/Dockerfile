FROM debian:jessie
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Environment
ENV THREADS 4
ENV BUILD_PKGS git-core make gcc libtool autoconf pkg-config cmake libgnutls28-dev libjansson-dev libluajit-5.1-dev
ENV RUN_PKGS bsdmainutils libgnutls-deb0-28 libjansson4 libluajit-5.1-2 luajit python vim-common
ENV PREFIX /usr/local
ENV BUILD_DIR /tmp/build
ENV BUILD_IGNORE gmp nettle jansson gnutls lua
ENV CFLAGS -DNDEBUG -O2 -g -fstack-protector
ENV LDFLAGS -Wl,--as-needed

# Expose port
EXPOSE 53

# Select entrypoint
WORKDIR /data
CMD ["/usr/local/bin/kresolved"]

# Install dependencies and sources
RUN apt-get -q -y update && \
apt-get install -q -y ${BUILD_PKGS} ${RUN_PKGS} && \
# Install dependencies
git clone https://gitlab.labs.nic.cz/knot/resolver.git ${BUILD_DIR} && \
cd ${BUILD_DIR} && \
./scripts/bootstrap-depends.sh ${PREFIX} && \
ldconfig && \
# Install knot-resolver
make -j${THREADS} && \
make install && \
ldconfig && \
# Trim down the image
apt-get purge -q -y ${BUILD_PKGS} && \
apt-get autoremove -q -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*
