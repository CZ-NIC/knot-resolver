FROM cznic/knot:latest
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Environment
ENV THREADS 4
ENV BUILD_PKGS git-core make gcc libtool autoconf pkg-config liblmdb-dev libcmocka-dev libssl-dev

# Expose port
EXPOSE 53

# Select entrypoint
WORKDIR /root
CMD ["/usr/local/sbin/kresolved", "-a", "0.0.0.0#53"]

# Install dependencies and sources
RUN apt-get -q -y update && \
apt-get install -q -y ${BUILD_PKGS} && \
# Install libuv
git clone https://github.com/libuv/libuv.git /libuv-src && \
cd /libuv-src && \
sh autogen.sh && \
./configure && \
make -j${THREADS} && \
make install && \
ldconfig && \
# Install knot-resolver
git clone https://gitlab.labs.nic.cz/knot/resolver.git /resolver-src && \
cd /resolver-src && \ 
sh ./bootstrap && \
./configure && \
make -j${THREADS} && \
make check && \
make install && \
ldconfig && \
# Trim down the image
rm -rf /libuv-src && \
rm -rf /resolver-src && \
apt-get purge -q -y ${BUILD_PKGS} && \
apt-get autoremove -q -y && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
