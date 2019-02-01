#!/bin/bash
# Utility script used by meson to run config tests post installation
set -o nounset -o errexit

# if anything fails during test setup, use exit code 77 to mark it as skipped
function skip {
    exit 77
}
trap skip ERR

TEST_DIR="$(dirname ${TEST_FILE})"
TMP_RUNDIR="$(mktemp -d)"

function finish {
    rm -rf "${TMP_RUNDIR}"
}
trap finish EXIT

cp -a "${TEST_DIR}/"* "${TMP_RUNDIR}/"
cd "${TMP_RUNDIR}"

test -x "${KRESD_EXEC}" || (echo "${KRESD_EXEC} not executable!"; exit 77)
trap ERR  # get actual kresd error code from now on

${KRESD_EXEC} "$@"
