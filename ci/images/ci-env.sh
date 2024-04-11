#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset
cd "$(dirname "${0}")/../.."


### Registry config ############################################################

docker_cmd="${DOCKER_CMD:-docker}"
registry="${CI_REGISTRY:-registry.nic.cz}"
image_prefix="$registry/knot/knot-resolver/ci-auto"
commit_tag="${CI_COMMIT_TAG:-}"
commit_branch="${CI_COMMIT_BRANCH:-}"
commit_ref="$commit_tag$commit_branch" # Tag and branch are exclusive

if [ -n "$commit_tag" -a -n "$commit_branch" ]; then
	echo "CI_COMMIT_TAG and CI_COMMIT_BRANCH are exclusive - declare only one!" >&2
	exit 1
fi
if [ -z "$commit_ref" ]; then
	echo "One of CI_COMMIT_TAG or CI_COMMIT_BRANCH must be declared" >&2
	exit 1
fi


### CI image config ############################################################

dockerfiles="debian11 debian12 debian12_coverity"

declare -A knot_branches=()
knot_branches["debian11"]="3.2 3.1"
knot_branches["debian12"]="master 3.3 3.2"
knot_branches["debian12_coverity"]="3.3"

declare -A special_args=()
special_args["debian12_coverity"]="--secret id=coverity-token,env=COVERITY_SCAN_TOKEN"

prepare_img_strings ()
{
	knot_branch_us="$(sed -r 's/\./_/g' <<< "$knot_branch")"
	image_name="$image_prefix/$dockerfile-knot_$knot_branch_us"
	image_tag="$image_name:$commit_ref"
}

if [ -z "${COVERITY_SCAN_TOKEN:-}" ]; then
	echo "COVERITY_SCAN_TOKEN is not set" >&2
	exit 1
fi

$docker_cmd login "$registry" --username "$CI_REGISTRY_USER" --password-stdin <<<"$CI_JOB_TOKEN"
