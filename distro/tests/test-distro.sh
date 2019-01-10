#!/bin/bash -x

# ./test-distro.sh {devel|latest} {distro}
# Example usage: ./test-distro.sh devel debian9

distro=$2
repo=$1

# Select repos
echo -e 'repos:\n  - knot-resolver-latest' > repos.yaml  # latest is needed for knot
case "$repo" in
	devel)
		echo -e '  - knot-resolver-devel' >> repos.yaml
		;;
	testing)
		echo -e 'repos:\n  - knot-resolver-testing' > repos.yaml
		;;
	latest)
		;;
	*)
		echo "Unknown repo, choose devel|latest|testing"
		exit 1
		;;
esac

cd "$distro"
vagrant destroy -f &>/dev/null
vagrant up
ret=$?
vagrant destroy -f &>/dev/null
exit $ret

