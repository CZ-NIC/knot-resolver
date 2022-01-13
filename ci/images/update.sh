#!/bin/bash
# build and upload docker image(s) into registry
#
# this is a simple wrapper around build.sh and update.sh
#
# to build & upload all images: ./update.sh */

if [[ $# -le 0 ]]; then
    echo "usage: $0 IMAGE..."
    exit 1
fi
set -e

for ARG in "$@"
do
    IMAGE=${ARG%/}
    echo "Building $IMAGE..."
    ./build.sh $IMAGE
    echo "Pushing $IMAGE..."
    ./push.sh $IMAGE
done

