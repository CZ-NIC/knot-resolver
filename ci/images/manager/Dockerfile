# SPDX-License-Identifier: GPL-3.0-or-later

FROM fedora:35
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]
ENV PATH="/root/.local/bin:${PATH}"

# Install Python
RUN dnf install -y git diffutils python3.6 python3.7 python3.8 python3.9 python3.10 python3-gobject pkg-config cairo-devel gcc python3-devel gobject-introspection-devel cairo-gobject-devel which \
	&& dnf clean all

# Install Poetry
RUN python3 -m pip install -U pip \
	&& curl -sSL https://install.python-poetry.org | python3 - \
	# not exactly required, but helpful
	&& python3 -m pip install poethepoet
