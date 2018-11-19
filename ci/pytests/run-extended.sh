#!/bin/bash

# Execute extended, long-running test suite

python3 -m pytest tests/pytests/conn_flood.py --capture=no
