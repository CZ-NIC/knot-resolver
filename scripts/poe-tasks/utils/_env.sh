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

# build dirs
build_dir=$gitroot/.build
install_dir=$gitroot/.install

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
if [ -z "${KRES_CONFIG_FILE:-}" ]; then
    KRES_CONFIG_FILE="$KRES_CONFIG_DIR/config.dev.yaml"
fi

if [ -z "${KRES_API_SOCK_FILE:-}" ]; then
    KRES_API_SOCK_FILE="$KRES_CONFIG_DIR/kres-api.sock"
fi
export KRES_CONFIG_FILE
export KRES_API_SOCK_FILE

function kres_meson_configure {
	reconfigure=''
	if [ -f .build/ninja.build ]; then
		reconfigure='--reconfigure'
	fi
	echo
	echo Configuring Knot Resolver Meson
	echo -------------------------------
	echo -e "${blue}${reset}"
	echo
	meson setup $build_dir $reconfigure --prefix=$install_dir -Duser=$USER -Dgroup=$(id -gn) "$@"
	echo
	echo Copying Knot Resolver constants.py module
	echo -----------------------------------------
	cp -v $build_dir/python/constants.py $gitroot/python/knot_resolver/constants.py
	echo
}

function kres_is_meson_configured {
	if [ ! -d .build ]; then
		echo
		echo Knot Resolver is not configured for building.
		echo "Please run './poe configure' (optionally with additional Meson arguments)".
		echo
		exit 2
	fi
}

function kres_meson_build {

	kres_is_meson_configured

	echo
	echo Building Knot Resolver C komponents
	echo -----------------------------------
	echo -e "${blue}In case of an compilation error, run this command to try to fix it:${reset}"
	echo -e "\t${blue}rm -r $install_dir $build_dir${reset}"
	echo
	ninja -C $build_dir
	ninja install -C $build_dir
	echo
}
