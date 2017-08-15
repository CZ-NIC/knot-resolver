#!/bin/sh -e
# Create a distribution tarball, like 'make dist' from autotools.
ver="$(git describe | sed 's/^v//')"
# 'git ls-files --recurse-submodules' fails, unfortunately
files="$(
	git ls-files
	cd modules/policy/lua-aho-corasick/
	git ls-files | sed 's|^|modules/policy/lua-aho-corasick/|'
	)"
name="knot-resolver-$ver"
tar caf "$name.tar.xz" --no-recursion --transform "s|^|$name/|" -- $files
echo "$name.tar.xz"

