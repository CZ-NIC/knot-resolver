#!/bin/bash -e
git describe | sed 's/^v//' | sed 's/-\(g[0-9a-f]\+\)/\.\1/'
