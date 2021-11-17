#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# generate variables for coverage testing
# $1 = top source directory
# $2 = coverage data directory path
# $3 = name of test/new subdirectory name
# $4 = [optional] --export to generate export commands

set -o errexit -o nounset
shopt -s nullglob

test -z "${COVERAGE:-}" && exit 0  # not enabled, do nothing
test ! -z "${V:-}" && set -o xtrace  # verbose mode

EXPORT=""
test "${4:-}" == "--export" && EXPORT="export "
TOPSRCDIR="$1"
DATAROOT="$2"
OUTPATH="$2/$3"

# check that output directory is empty
# beware: Makefile will always call coverage_env.sh for all targets
# so directories get created but not populated
# i.e. test -d is not sufficient check
OUTPATH_FILENAMES=("${OUTPATH}"/*)  # filenames in BASH array
(( ${#OUTPATH_FILENAMES[*]} )) && echo "false" && >&2 echo "fatal: output directory ${OUTPATH} must be empty (or non-existent)" && exit 1

mkdir -p "${OUTPATH}"
# convert paths to absolute
pushd "${OUTPATH}" &> /dev/null
touch .topdir_kresd_coverage
OUTPATH="$(pwd -P)"
popd &> /dev/null

# determine GCOV_PREFIX_STRIP value for current source directory
TOPSRCDIR_SLASHES="${TOPSRCDIR//[^\/]/}" # remove everything except /
GCOV_PREFIX_STRIP="${#TOPSRCDIR_SLASHES}" # number of / == number of components

KRESD_COVERAGE_STATS="${OUTPATH}/luacov.stats.out"
GCOV_PREFIX="${OUTPATH}"
echo "${EXPORT}KRESD_COVERAGE_STATS=\"${KRESD_COVERAGE_STATS}\" ${EXPORT}GCOV_PREFIX=\"${GCOV_PREFIX}\" ${EXPORT}GCOV_PREFIX_STRIP=\"${GCOV_PREFIX_STRIP}\""
