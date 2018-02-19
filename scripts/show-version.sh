#!/bin/bash -e
git describe | sed 's/^v//' | sed 's/-/\./g'
