#!/bin/bash
# build specified docker image

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source "${CURRENT_DIR}"/vars.sh "$@"
set -ex

if [ -n "$COVERITY_SCAN_TOKEN" ]; then
	SECRETS="$SECRETS --secret id=coverity-token,env=COVERITY_SCAN_TOKEN"
fi

export DOCKER_BUILDKIT=1 # Enables using secrets in docker-build
docker build --no-cache -t "${FULL_NAME}" "${IMAGE}" --build-arg KNOT_BRANCH=${KNOT_BRANCH} $SECRETS
