FROM debian:stable
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# name: cznic/ci-debian-kresd
RUN apt-get update -qq
RUN apt-get install -y -qqq apt-utils
RUN apt-get upgrade -y -qqq
RUN apt-get install -y -qqq make cmake pkg-config git build-essential bsdmainutils libtool autoconf make pkg-config liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev libsystemd-dev libidn11-dev protobuf-c-compiler libfstrm-dev pkg-config libknot-dev libuv1-dev libcmocka-dev libluajit-5.1-dev # dependencies for knot-resolver
RUN apt-get install -y -qqq valgrind python3 python3-dev python3-jinja2 python3-pip python3-yaml libffi-dev libaugeas-dev
RUN pip3 install --upgrade pip
RUN pip3 install --user dnspython python-augeas
RUN git clone https://gitlab.labs.nic.cz/knot/knot-dns.git /tmp/knot
RUN cd /tmp/knot && autoreconf -if && ./configure && make && make install && ldconfig
