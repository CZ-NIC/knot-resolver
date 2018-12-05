#!/bin/bash

python3 -m pytest --html pytests.html --self-contained-html -dn 24 tests/pytests
