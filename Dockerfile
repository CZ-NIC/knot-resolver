# SPDX-License-Identifier: GPL-3.0-or-later

# Intermediate container for build
FROM debian:11 AS build

ENV OBS_REPO=knot-resolver-latest
ENV DISTROTEST_REPO=Debian_11


RUN apt-get update -qq && \
	apt-get -qqq -y install python3-pip python3-venv devscripts && \
	pip3 install pipx && \
	pipx install apkg

COPY . /source

RUN cd /source && \
	export PATH="$PATH:/root/.local/bin" && \
	git submodule update --init --recursive && \
	git config --global user.name "Docker Build" && \
	git config --global user.email docker-build@knot-resolver && \
	/root/.local/bin/apkg build-dep -y && \
	/root/.local/bin/apkg build


# Real container
FROM debian:11-slim AS runtime

ENV OBS_REPO=knot-resolver-latest
ENV DISTROTEST_REPO=Debian_11

RUN apt-get update -qq && \
	apt-get update -qq

COPY --from=build /source/pkg/pkgs/debian-11 /pkg

# install resolver, minimize image and prepare config directory
RUN apt-get install -y /pkg/*/*.deb && \
	rm -r /pkg && \
	apt-get remove -y -qq curl gnupg2 && \
	apt-get autoremove -y && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* && \
	mkdir /config

COPY manager/etc/knot-resolver/config.example.docker.yaml /config/config.yaml

LABEL cz.knot-resolver.vendor="CZ.NIC"
LABEL maintainer="knot-resolver-users@lists.nic.cz"

# Export plain DNS, DoT, DoH and management interface
EXPOSE 53/UDP 53/TCP 443/TCP 853/TCP 5000/TCP

ENTRYPOINT ["/usr/bin/knot-resolver"]
CMD ["-c", "/config/config.yaml"]
