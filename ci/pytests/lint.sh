#!/bin/bash

python3 -m flake8 --max-line-length=100 tests/pytests
FLAKE8=$?

ci/pytests/pylint-run.sh
PYLINT=$?

if [ $PYLINT -ne 0 ]; then
	exit 1
fi
if [ $FLAKE8 -ne 0 ]; then
	exit 1
fi

exit 0
