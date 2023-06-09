#!/bin/bash

# fail fast
set -e

# We expect `kresctl` command to exist in $PATH
command -v kresctl > /dev/null
