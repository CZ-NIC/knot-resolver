#!/bin/bash

set -e

kresctl config set -p /workers 5

test "$(ps -a -x | grep kresd | grep -v grep | wc -l)" -eq 5
