# SPDX-License-Identifier: GPL-3.0-or-later

FROM debian:stable
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>
ARG SDK_NAME=OpenWrt-SDK*x86_64
ARG SDK_REPO=omnia

WORKDIR /tmp

RUN echo "deb http://ftp.debian.org/debian stretch-backports main" >> /etc/apt/sources.list

RUN apt-get update -qq
RUN apt-get -t stretch-backports install -y git
RUN apt-get install -y -qqq git-core build-essential libssl-dev libncurses5-dev \
	unzip gawk zlib1g-dev git subversion mercurial ccache libtinfo-dev libncurses5 \
	libncurses5-dev wget

RUN wget --quiet "https://repo.turris.cz/$SDK_REPO/" -r -nd -np --accept="$SDK_NAME.tar.bz2" && \
	tar xjf $SDK_NAME.tar.bz2 && \
	rm $SDK_NAME.tar.bz2 && \
	mv $SDK_NAME turris

CMD ["/bin/bash"]
