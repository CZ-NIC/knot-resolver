#!/bin/bash -e
export SOURCE_PATH="$(cd "$(dirname "$0")" && pwd -P)"
export TEST_FILE="${2}"
TEST_DIR="$(dirname $TEST_FILE)"
export TMP_RUNDIR="$(mktemp -d)"
export KRESD_NO_LISTEN=1
function finish {
	rm -rf "${TMP_RUNDIR}"
}
trap finish EXIT


echo "# $(basename ${TEST_FILE})"
cp -a "${TEST_DIR}/"* "${TMP_RUNDIR}/"
CMDLINE_ARGS="$(cat "${TEST_FILE%.test.lua}.args" 2>/dev/null || echo "")"
EXPECTED_RETURNCODE="$(cat "${TEST_FILE%.test.lua}.returncode" 2>/dev/null || echo 0)"
set +e
${DEBUGGER} ${1} -f 1 -c ${SOURCE_PATH}/test.cfg $CMDLINE_ARGS "${TMP_RUNDIR}"
RETCODE="$?"
if [ "$RETCODE" -ne "$EXPECTED_RETURNCODE" ]; then
	echo "Expected return code '$EXPECTED_RETURNCODE' got '$RETCODE'."
fi
test "$RETCODE" -eq "$EXPECTED_RETURNCODE"
