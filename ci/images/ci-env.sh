#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset
cd "$(dirname "${0}")/../.."


### Utils ######################################################################

ci_log ()
{
	echo "[[[ $(basename "$0" '.sh') ]]] $@" >&2
}


### Registry config ############################################################

docker_cmd="${DOCKER_CMD:-docker}"
registry="${CI_REGISTRY:-registry.nic.cz}"
image_prefix="$registry/knot/knot-resolver/ci-auto"
commit_tag="${CI_COMMIT_TAG:-}"
commit_branch="${CI_COMMIT_BRANCH:-}"
commit_ref="$commit_tag$commit_branch" # Tag and branch are exclusive

if [ -n "$commit_tag" -a -n "$commit_branch" ]; then
	ci_log "CI_COMMIT_TAG and CI_COMMIT_BRANCH are exclusive - declare only one!"
	exit 1
fi
if [ -z "$commit_ref" ]; then
	ci_log "One of CI_COMMIT_TAG or CI_COMMIT_BRANCH must be declared"
	exit 1
fi


### CI image structure definition ##############################################

declare -a repos=()  # Array of OCI repository names (image keys)

## OCI repository attributes - associative arrays keyed by repository names.
declare -A image_name=()  # The full repository/image name
declare -A image_tag=()   # Repository name with "version" tag appended
declare -A dockerfile_dir=()  # Directory containing the Dockerfile (relative to ci/images)

declare -A base_image=()  # KRES_BASE_IMAGE value (if applicable)
declare -A knot_branch=()  # KNOT_BRANCH value (if applicable)
declare -A coverity_scan_project_name=() # COVERITY_SCAN_PROJECT_NAME value (if applicable)
declare -A special_arg=()  # Special arguments appended to the Docker command

# Simple "constructor". Parameters are as follows:
#  - OCI repository name
#  - Dockerfile directory name
#  - [Optional attribute key 1]
#  - [Optional attribute value 1]
#  - [Optional attribute key 2]
#  - [Optional attribute value 2]
#  - [...]
add_image ()
{
	local repo="$1"
	local name="$image_prefix/$repo"

	repos+=("$repo")

	image_name["$repo"]="$name"
	image_tag["$repo"]="$name:$commit_ref"
	dockerfile_dir["$repo"]="$2"

	shift 2

	while [ -n "${1:-}" ]; do
		local key="$1"
		local value="$2"
		shift 2

		if [ "$key" == 'base_image' ]; then
			base_image["$repo"]="$value"
		elif [ "$key" = 'knot_branch' ]; then
			knot_branch["$repo"]="$value"
		elif [ "$key" = 'special_arg' ]; then
			special_arg["$repo"]="$value"
		elif [ "$key" = 'coverity_scan_project_name' ]; then
			coverity_scan_project_name["$repo"]="$value"
		fi
	done
}

dump_image_info ()
{
	local repo="$1"
	ci_log "===== $repo info begin ====="
	ci_log "image_name = ${image_name["$repo"]:-<none>}"
	ci_log "image_tag = ${image_tag["$repo"]:-<none>}"
	ci_log "dockerfile_dir = ${dockerfile_dir["$repo"]:-<none>}"
	ci_log "base_image = ${base_image["$repo"]:-<none>}"
	ci_log "knot_branch = ${knot_branch["$repo"]:-<none>}"
	ci_log "special_arg = ${special_arg["$repo"]:-<none>}"
	ci_log "coverity_scan_project_name = ${coverity_scan_project_name["$repo"]:-<none>}"
	ci_log "===== $repo info end ====="
}


### CI images ##################################################################

# These images are built in the declared order. The order is mostly just
# important for the images that have each other in the 'base_image' attribute,
# otherwise, it should not matter.

add_image 'debian11-base' 'debian11'
add_image 'debian12-base' 'debian12'

add_image 'debian11-knot_3_2' 'knot' \
	'base_image' "${image_tag['debian11-base']}" \
	'knot_branch' '3.2'
add_image 'debian11-knot_3_1' 'knot' \
	'base_image' "${image_tag['debian11-base']}" \
	'knot_branch' '3.1'
add_image 'debian12-knot_master' 'knot' \
	'base_image' "${image_tag['debian12-base']}" \
	'knot_branch' 'master'
add_image 'debian12-knot_3_3' 'knot' \
	'base_image' "${image_tag['debian12-base']}" \
	'knot_branch' '3.3'
add_image 'debian12-knot_3_2' 'knot' \
	'base_image' "${image_tag['debian12-base']}" \
	'knot_branch' '3.2'

add_image 'main' 'debian-testutils' \
	'base_image' "${image_tag['debian12-knot_3_3']}"
add_image 'coverity' 'debian-coverity' \
	'base_image' "${image_tag['debian12-knot_3_3']}" \
	'special_arg' '--secret id=coverity-token,env=COVERITY_SCAN_TOKEN' \
	'coverity_scan_project_name' "$COVERITY_SCAN_PROJECT_NAME"


### Misc. preparations #########################################################

# Check for Coverity token existence
if [ -z "${COVERITY_SCAN_TOKEN:-}" ]; then
	ci_log "COVERITY_SCAN_TOKEN is not set"
	exit 1
fi

$docker_cmd login "$registry" --username "$CI_REGISTRY_USER" --password-stdin <<<"$CI_JOB_TOKEN"
