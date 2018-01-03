#!/bin/bash -e
export SOURCE_PATH=$(cd "$(dirname "$0")" && pwd -P)
export TEST_FILE=${2}
export TMP_RUNDIR="$(mktemp -d)"
export KRESD_NO_LISTEN=1
function finish {
	rm -rf "${TMP_RUNDIR}"
}
trap finish EXIT

echo "# $(basename ${TEST_FILE})"
${DEBUGGER} ${1} -f 1 -c ${SOURCE_PATH}/test.cfg "${TMP_RUNDIR}"