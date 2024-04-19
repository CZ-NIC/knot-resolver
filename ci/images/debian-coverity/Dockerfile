# SPDX-License-Identifier: GPL-3.0-or-later

ARG KRES_BASE_IMAGE
FROM ${KRES_BASE_IMAGE}
MAINTAINER Knot Resolver <knot-resolver@labs.nic.cz>

ARG COVERITY_SCAN_PROJECT_NAME

RUN \
	--mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
	--mount=target=/var/cache/apt,type=cache,sharing=locked \
	\
	apt-get update -qq && \
	apt-get install --no-install-suggests --no-install-recommends -y -qqq \
		\
		`# Coverity tools and uploading logs` \
		curl tar

# download Coverity tools
RUN --mount=type=secret,id=coverity-token \
	curl -o /tmp/cov-analysis-linux64.tar.gz https://scan.coverity.com/download/cxx/linux64 \
	--form project=$COVERITY_SCAN_PROJECT_NAME --form token=$(cat /run/secrets/coverity-token) \
	--fail --verbose
RUN tar xfz /tmp/cov-analysis-linux64.tar.gz
RUN mv cov-analysis-linux64-* /opt/cov-analysis
