#!/bin/bash -x
# SPDX-License-Identifier: GPL-3.0-or-later

# ./test-distro.sh {obs_repo} {distro}
# Example usage: ./test-distro.sh knot-resolver-devel debian9

pkgtestdir="$(dirname ${0})"
repofile="$pkgtestdir/repos.yaml"

distro=$2
repo=$1

# Select repos
echo -e "repos:\n  - $repo" > $repofile
if [ "$repo" == "knot-resolver-devel" ]; then
    # get Knot DNS from knot-resolver-latest
	echo -e '  - knot-resolver-latest' >> $repofile
fi

pushd "$pkgtestdir/$distro"
vagrant destroy -f &>/dev/null
vagrant up
ret=$?
vagrant destroy -f &>/dev/null
popd
exit $ret
