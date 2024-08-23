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

# create runtime directories
if [ -z "${KRES_CONFIG_DIR:-}" ]; then
	KRES_CONFIG_DIR="$gitroot/etc/config"
fi
mkdir -p "$KRES_CONFIG_DIR/runtime" "$KRES_CONFIG_DIR/cache"

# env variables
if [ -z "${KRES_MANAGER_CONFIG:-}" ]; then
    KRES_MANAGER_CONFIG="$KRES_CONFIG_DIR/config.dev.yaml"
fi

if [ -z "${KRES_MANAGER_API_SOCK:-}" ]; then
    KRES_MANAGER_API_SOCK="$KRES_CONFIG_DIR/manager.sock"
fi
export KRES_MANAGER_CONFIG
export KRES_MANAGER_API_SOCK

function build_kresd {
	if [ -d .build_kresd ]; then
		echo
		echo Building Knot Resolver
		echo ----------------------
		echo -e "${blue}In case of an compilation error, run this command to try to fix it:${reset}"
		echo -e "\t${blue}rm -r $(realpath .install_kresd) $(realpath .build_kresd)${reset}"
		echo
		ninja -C .build_kresd
		ninja install -C .build_kresd
		export PYTHONPATH="$(realpath .build_kresd/python):${PYTHONPATH:-}"
	else
		echo
		echo Knot Resolver daemon is not configured.
		echo "Please run './poe configure' (optionally with additional Meson arguments)"
		echo
		exit 2
	fi
}
