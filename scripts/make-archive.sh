#!/bin/sh -e
# Create a distribution tarball, like 'make dist' from autotools.
cd "$(git rev-parse --show-toplevel)"
ver="$(scripts/show-version.sh)"
test 0 -ne $(git status --porcelain | wc -l) && \
	echo "Git working tree is dirty, make it clean first" && \
	exit 1
git submodule status --recursive | grep -q '^[^ ]' && \
	echo "Git submodules are dirty, run: git submodule update --recursive --init" && \
	exit 2

# 'git ls-files --recurse-submodules' works only if modules are initialized
name="knot-resolver-$ver"
tar caf "$name.tar.xz" -h --no-recursion --transform "s|^|$name/|" -- $(git ls-files --recurse-submodules)
echo "$name.tar.xz"
