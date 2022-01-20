#!/bin/bash
# build specified docker image

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source "${CURRENT_DIR}"/vars.sh "$@"
set -ex

docker build --no-cache --squash -t "${FULL_NAME}" "${IMAGE}" --build-arg KNOT_BRANCH=${KNOT_BRANCH}
