FROM cznic/knot:latest
MAINTAINER Marek Vavrusa <marek.vavrusa@nic.cz>

# Install libuv
RUN mkdir /src; \
git clone https://github.com/libuv/libuv.git /src/libuv; \
cd /src/libuv; \
sh autogen.sh && ./configure && make && make install && ldconfig; \
rm -rf /src/libuv

# Install knot-resolver
RUN apt-get -q -y update; \
apt-get install -q -y \
libcmocka-dev; \
git clone https://gitlab.labs.nic.cz/knot/resolver.git /src/knot-resolver; \
cd /src/knot-resolver; \
autoreconf -if && ./configure && make && make check && make install && ldconfig; \
# Trim down the image
apt-get clean; \
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /src/knot-resolver

# Select entrypoint
WORKDIR /root
CMD ["/usr/local/sbin/kresolved", "-a", "0.0.0.0#53"]

# Expose port
EXPOSE 53
