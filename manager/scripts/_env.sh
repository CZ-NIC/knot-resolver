# fail on errors
set -o errexit

# define color codes
red="\033[0;31m"
yellow="\033[0;33m"
green="\033[0;32m"
bright_black="\033[0;90m"
blue="\033[0;34m"
reset="\033[0m"

# ensure consistent top level directory
gitroot="$(git rev-parse --show-toplevel)"
if test -z "$gitroot"; then
	echo -e "${red}This command can be run only in a git repository tree.${reset}"
	exit 1
fi
cd $gitroot/manager

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


function build_kresd {
	echo
	echo Building Knot Resolver
	echo ----------------------
	echo -e "${blue}In case of an compilation error, run this command to try to fix it:${reset}"
	echo -e "\t${blue}rm -r $(realpath .install_kresd) $(realpath .build_kresd)${reset}"
	echo
	pushd ..
	mkdir -p manager/.build_kresd manager/.install_kresd
	meson manager/.build_kresd --prefix=$(realpath manager/.install_kresd) --default-library=static --buildtype=debug
	ninja -C manager/.build_kresd
	ninja install -C manager/.build_kresd
	export PYTHONPATH="$(realpath manager/.build_kresd/python):${PYTHONPATH:-}"
	popd
}
