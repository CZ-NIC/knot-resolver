#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later

# $1 = top source directory
# $2 = coverage data directory path
# $3 = output directory for *.info files

set -o errexit -o nounset
shopt -s nullglob
IFS=$'\n'

TOPSRCDIR="$1"
DATAROOT="$2"
OUTDIR="$3"

cd "${TOPSRCDIR}"
for COVNAME in $(find "${DATAROOT}" -name .topdir_kresd_coverage)
do
	find "${DATAROOT}" -name '*.gcda' -not -path "${DATAROOT}/*" -delete
	COVDIR="$(dirname "${COVNAME}")"
	COVDATA_FILENAMES=("${COVDIR}"/*)  # filenames in BASH array
	(( ${#COVDATA_FILENAMES[*]} )) || continue  # skip empty dirs

	cp -r -t ${TOPSRCDIR} "${COVDIR}"/*
	${LCOV} -q --no-external --capture -d lib -d daemon -d modules -o "$(mktemp -p "${OUTDIR}" -t XXXXXXXX.c.info)" > /dev/null
done
