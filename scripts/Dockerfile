FROM debian:jessie
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Environment
ENV THREADS 4
ENV BUILD_PKGS git-core make gcc libtool autoconf pkg-config cmake libgnutls28-dev libjansson-dev liblua5.2-dev
ENV RUN_PKGS libgnutls-deb0-28 libjansson4 liblua5.2-0 lua5.2
ENV PREFIX /usr/local
ENV BUILD_DIR /tmp/build
ENV BUILD_IGNORE gmp nettle jansson gnutls lua

# Expose port
EXPOSE 53

# Select entrypoint
WORKDIR /root
CMD ["/usr/local/sbin/kresolved"]

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
