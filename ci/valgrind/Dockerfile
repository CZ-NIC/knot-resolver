FROM cznic/ubuntu:16.04
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# name: cznic/ubuntu-valgrind:16.04
# run ci tests with valgrind memory checks
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y valgrind
