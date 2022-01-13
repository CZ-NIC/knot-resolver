#!/bin/bash
# upload docker image into registry

CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
source "${CURRENT_DIR}"/vars.sh "$@"
set -ex

docker push "${FULL_NAME}"
