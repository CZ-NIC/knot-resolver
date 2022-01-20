# SPDX-License-Identifier: GPL-3.0-or-later

FROM registry.nic.cz/labs/lxc-gitlab-runner/debian-11
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
ARG KNOT_BRANCH=3.1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y \
	python3 \
	python3-pip

RUN pip3 install apkg
RUN apkg system-setup

RUN git clone --depth=1 --branch=$KNOT_BRANCH https://gitlab.nic.cz/knot/knot-dns.git \
	&& cd knot-dns \
	&& apkg install --build-dep

RUN rm -rf /var/lib/apt/lists/* knot-dns
