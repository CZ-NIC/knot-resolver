# SPDX-License-Identifier: GPL-3.0-or-later

FROM fedora:38
LABEL Knot Resolver <knot-resolver@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]
ENV PATH="/root/.local/bin:${PATH}"

# Install Python and deps
RUN dnf install -y\
    python3.8 python3.9 python3.10 python3.10-devel\
    python3.11 python3.11-devel python3.12 python3.12-devel\
    python3-gobject pipx git which diffutils gcc pkg-config\
    cairo-devel gobject-introspection-devel cairo-gobject-devel\
    && dnf clean all

# Install poetry
RUN pipx install poetry==1.4.2\
    # not exactly required, but helpful
	&& pipx install poethepoet
