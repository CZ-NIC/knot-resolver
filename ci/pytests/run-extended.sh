#!/bin/bash

# Execute extended, long-running test suite

python3 -m pytest -ra --capture=no tests/pytests/conn_flood.py
