#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Make a `.kr-vcs-info` file for archive purposes
set -o errexit -o nounset -o xtrace

cd "$(dirname ${0})/.."

vcs_info_name='.kr-vcs-info'

# make sure we don't accidentally add / overwrite forgotten changes in git
#(git diff-index --quiet HEAD && git diff-index --cached --quiet HEAD) || \
#    (echo 'git index has uncommitted changes!'; exit 1)

rm -f "$vcs_info_name"

commit_date="$(git show --no-patch --format=%cs)"
commit_hash="$(git show --no-patch --format=%H)"
tag="$(git describe --tags --exact-match || echo '')"

cat > "$vcs_info_name" <<EOF
{
	$(test -n "$tag" && echo "\"tag\": \"$tag\",")
	"commitDate": "$commit_date",
	"commitHash": "$commit_hash"
}
EOF
