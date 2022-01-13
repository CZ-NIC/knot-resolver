#!/bin/bash
# define common variables for image build scripts

KNOT_BRANCH="${KNOT_BRANCH:-3.1}"

REGISTRY="registry.nic.cz/knot/knot-resolver/ci"
IMAGE=$1
if [ -z "${IMAGE}" ]; then
    echo "image name not provided"
    exit 1
fi
TAG="knot-${KNOT_BRANCH}"
FULL_NAME="${REGISTRY}/${IMAGE}:${TAG}"
