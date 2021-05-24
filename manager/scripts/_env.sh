# fail on errors
set -o errexit

# define color codes
red="\033[0;31m"
yellow="\033[0;33m"
green="\033[0;32m"
bright_black="\033[0;90m"
reset="\033[0m"

# ensure consistent top level directory
gitroot="$(git rev-parse --show-toplevel)"
if test -z "$gitroot"; then
	echo -e "${red}This command can be run only in a git repository tree.${reset}"
	exit 1
fi
cd $gitroot

# ensure consistent environment with virtualenv
if test -z "$VIRTUAL_ENV" -a "$CI" != "true" -a -z "$KNOT_ENV"; then
	echo -e "${yellow}You are NOT running the script within the project's virtual environment.${reset}"
	echo -e "Do you want to continue regardless? [yN]"
	read cont
	if test "$cont" != "y" -a "$cont" != "Y"; then
		echo -e "${red}Exiting early...${reset}"
		exit 1
	fi
fi

# update PATH with node_modules
PATH="$PATH:$gitroot/node_modules/.bin"

# fail even on unbound variables
set -o nounset