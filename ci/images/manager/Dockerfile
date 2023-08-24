# SPDX-License-Identifier: GPL-3.0-or-later

FROM fedora:38
LABEL Knot Resolver <knot-resolver@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]
ENV PATH="/root/.local/bin:${PATH}"

# Install Python and deps
RUN dnf install -y python3.7 python3.8 python3.9 python3.10 python3.10-devel python3 python3-devel python3-gobject\
	git which diffutils gcc pkg-config cairo-devel gobject-introspection-devel cairo-gobject-devel\
	&& dnf clean all

# Install pip
RUN python3.7 -m ensurepip\
	# Install poetry
	&& curl -sSL https://install.python-poetry.org | python3 - --version 1.4.2\
	# not exactly required, but helpful
	&& python3.7 -m pip install poethepoet
