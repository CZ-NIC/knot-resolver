DECKARD_COMMIT=$(git ls-tree HEAD:tests/integration/ | grep commit | grep deckard | cut -f1 | cut -f3 '-d ')
DECKARD_PATH="tests/integration/deckard"
pushd $DECKARD_PATH > /dev/null
if git merge-base --is-ancestor $DECKARD_COMMIT origin/master; then
	echo "Deckard submodule commit is on in its master branch. All good in the hood."
	exit 0
else
	echo "Deckard submodule commit $DECKARD_COMMIT is not in Deckard's master branch."
	echo "This WILL cause CI breakages so make sure your changes in Deckard are merged"
	echo "or point the submodule to another commit."
	exit 1
fi

