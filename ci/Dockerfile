FROM debian:stable
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# name: cznic/ci-debian-kresd

# install dependecies
RUN apt-get update -qq
RUN apt-get install -y -qqq apt-utils
RUN apt-get upgrade -y -qqq
RUN apt-get install -y -qqq make cmake pkg-config git build-essential bsdmainutils libtool autoconf make pkg-config liburcu-dev libgnutls28-dev libedit-dev liblmdb-dev libcap-ng-dev libsystemd-dev libidn11-dev protobuf-c-compiler libfstrm-dev pkg-config libknot-dev libuv1-dev libcmocka-dev libluajit-5.1-dev valgrind python3 python3-dev python3-jinja2 python3-pip python3-yaml libffi-dev libaugeas-dev python3-pep8 unzip wget lua-sec lua-socket
RUN apt-get purge python3-dnspython
RUN pip3 install --upgrade pip
RUN pip3 install --user dnspython python-augeas
RUN pip3 install pylint

#install unbound
RUN apt-get install unbound unbound-anchor -y -qqq
RUN printf "server:\n interface: 127.0.0.1@53535\n use-syslog: yes\nremote-control:\n control-enable: no\n" >> /etc/unbound/unbound.conf

#install bind
RUN apt-get install bind9 -y -qqq
RUN printf 'options {\n directory "/var/cache/bind";\n listen-on port 53533 { 127.0.0.1; };\n listen-on-v6 port 53533 { ::1; };\n};\n' > /etc/bind/named.conf.options

#download respdiff
RUN wget https://gitlab.labs.nic.cz/knot/resolver-benchmarking/repository/archive.zip -O respdiff.zip
RUN unzip respdiff.zip
RUN cp -R resolver-benchmarking*/response_differences/respdiff /var/opt/respdiff
RUN pip3 install -r resolver-benchmarking*/requirements.txt
RUN rm -rf respdiff.zip resolver-benchmarking*

#build knot
RUN git clone https://gitlab.labs.nic.cz/knot/knot-dns.git /tmp/knot
RUN cd /tmp/knot && autoreconf -if && ./configure && make && make install && ldconfig

#prepare for valgrind
RUN wget https://raw.githubusercontent.com/LuaDist/luajit/2.0.3/src/lj.supp -O /lj.supp
