#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

source "$(dirname "${0}")/ci-env.sh"

failed_images=()

exit_code=0
for repo in "${repos[@]}"; do
	err=0

	ci_log "Building '${image_tag["$repo"]}'"
	build_args=()
	build_args+=(${special_arg["$repo"]:-})
	if [ -n "${base_image["$repo"]:-}" ]; then
		build_args+=("--build-arg" "KRES_BASE_IMAGE=${base_image["$repo"]}")
	fi
	if [ -n "${knot_branch["$repo"]:-}" ]; then
		build_args+=("--build-arg" "KNOT_BRANCH=${knot_branch["$repo"]}")
	fi
	if [ -n "${coverity_scan_project_name["$repo"]:-}" ]; then
		build_args+=("--build-arg" "COVERITY_SCAN_PROJECT_NAME=${coverity_scan_project_name["$repo"]}")
	fi

	dump_image_info "$repo"
	ci_log "Build args: ${build_args[*]}"

	set +e
	"$docker_cmd" build \
		"${build_args[@]}" \
		--cache-from "${image_name["$repo"]}:6.0" \
		--cache-from "${image_name["$repo"]}:master" \
		--cache-from "${image_tag["$repo"]}" \
		--file "ci/images/${dockerfile_dir["$repo"]}/Dockerfile" \
		--tag "${image_tag["$repo"]}" \
		.
	if [ "$?" -ne "0" ]; then
		failed_images+=("${image_tag["$repo"]}")
		exit_code=16
		set -e
		continue
	fi
	set -e

	"$docker_cmd" push "${image_tag["$repo"]}"

	if [ "$err" -eq "0" ]; then
		ci_log "Finished '${image_tag["$repo"]}' - [OK]"
	else
		ci_log "Finished '${image_tag["$repo"]}' - [ERROR]"
	fi
done

if [ "$exit_code" -ne "0" ]; then
	ci_log "Finished with errors in the following images:"
	for img in "${failed_images[@]}"; do
		ci_log " - $img"
	done
fi
exit $exit_code
