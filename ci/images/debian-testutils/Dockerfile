# SPDX-License-Identifier: GPL-3.0-or-later

ARG KRES_BASE_IMAGE

FROM ${KRES_BASE_IMAGE}
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# test dependencies
RUN \
	--mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
	--mount=target=/var/cache/apt,type=cache,sharing=locked \
	\
	apt-get update -qq && \
	apt-get install --no-install-suggests --no-install-recommends -y -qqq \
		\
		`# dnstap module` \
		protobuf-c-compiler libprotobuf-c-dev libfstrm-dev \
		\
		`# dnstap testing` \
		golang-any \
		\
		`# documentation` \
		doxygen texinfo python3-sphinx python3-breathe \
		python3-sphinx-rtd-theme \
		\
		`# Deckard` \
		wget augeas-tools faketime libaugeas-dev libffi-dev tcpdump \
		wireshark-common dnsdist \
		\
		`# respdiff` \
		lmdb-utils unbound unbound-anchor bind9 pdns-recursor \
		\
		`# Misc` \
		valgrind luarocks lcov clang clang-tools clang-tidy osc curl \
		locales

# Testing deps for Resolver's dnstap module
COPY ./tests/dnstap /root/tests/dnstap
WORKDIR /root/tests/dnstap/src/dnstap-test
RUN go get .
WORKDIR /root

# Python packages required for Deckard CI
# Python: grab latest versions from PyPi
# (Augeas binding in Debian packages are slow and buggy)
RUN $VENV/bin/pip3 install --upgrade pip
RUN $VENV/bin/pip3 install pylint
RUN $VENV/bin/pip3 install pep8
RUN $VENV/bin/pip3 install dnspython
# tests/pytest dependencies: skip over broken versions
RUN $VENV/bin/pip3 install jinja2 'pytest != 6.0.0' pytest-html pytest-xdist pytest-forked
# apkg for packaging
RUN $VENV/bin/pip3 install apkg

# Python dependencies for Deckard
RUN wget https://gitlab.nic.cz/knot/deckard/raw/master/requirements.txt -O /tmp/deckard-req.txt
RUN $VENV/bin/pip3 install -r /tmp/deckard-req.txt

# Valgrind for kresd CI
RUN wget https://github.com/LuaJIT/LuaJIT/raw/v2.1.0-beta3/src/lj.supp -O /lj.supp
# TODO: rebuild LuaJIT with Valgrind support

# Lua lint for kresd CI
RUN luarocks --lua-version 5.1 install luacheck

# respdiff for kresd CI
RUN git clone --depth=1 https://gitlab.nic.cz/knot/respdiff /var/opt/respdiff
RUN $VENV/bin/pip3 install -r /var/opt/respdiff/requirements.txt

# Python static analysis for respdiff
RUN $VENV/bin/pip3 install mypy
RUN $VENV/bin/pip3 install flake8

# Python requests for CI scripts
RUN $VENV/bin/pip3 install requests

# docker-py for packaging tests
RUN $VENV/bin/pip3 install docker

# Unbound for respdiff
RUN printf "server:\n interface: 127.0.0.1@53535\n use-syslog: yes\n do-ip6: no\nremote-control:\n control-enable: no\n" >> /etc/unbound/unbound.conf

# BIND for respdiff
RUN printf '\nOPTIONS="-4 $OPTIONS"' >> /etc/default/bind9
RUN printf 'options {\n directory "/var/cache/bind";\n listen-on port 53533 { 127.0.0.1; };\n listen-on-v6 port 53533 { ::1; };\n};\n' > /etc/bind/named.conf.options

# code coverage
RUN luarocks --lua-version 5.1 install luacov

# en_US.UTF-8 locale for scripts.update-authors.sh
RUN sed -i "/en_US.UTF-8/ s/^#\(.*\)/\1/" /etc/locale.gen
RUN locale-gen

# SonarCloud scanner
RUN wget -O /var/opt/wrapper.zip https://sonarcloud.io/static/cpp/build-wrapper-linux-x86.zip
RUN wget -O /var/opt/scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
RUN unzip -d /var/opt /var/opt/wrapper.zip
RUN unzip -d /var/opt /var/opt/scanner.zip
ENV PATH "$PATH:/var/opt/build-wrapper-linux-x86:/var/opt/sonar-scanner-5.0.1.3006-linux/bin"
