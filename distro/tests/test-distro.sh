#!/bin/bash -x

# ./test-distro.sh {devel|latest} {distro}
# Example usage: ./test-distro.sh devel debian9

pkgtestdir="$(dirname ${0})"
repofile="$pkgtestdir/repos.yaml"

distro=$2
repo=$1

# Select repos
# TODO: enable knot-dns-devel
echo -e 'repos:\n  - knot-resolver-latest' > $repofile  # latest is needed for knot
case "$repo" in
	devel)
		echo -e '  - knot-resolver-devel' >> $repofile
		;;
	testing)
		echo -e 'repos:\n  - knot-resolver-testing' > $repofile
		;;
	latest)
		;;
	*)
		echo "Unknown repo, choose devel|latest|testing"
		exit 1
		;;
esac

pushd "$pkgtestdir/$distro"
vagrant destroy -f &>/dev/null
vagrant up
ret=$?
vagrant destroy -f &>/dev/null
popd
exit $ret
