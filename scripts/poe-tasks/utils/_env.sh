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
build_dir="$gitroot/.build"
build_doc_dir="$gitroot/.build_doc"
install_dir="$gitroot/.install"

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

# Set enviromental variables if not
if [ -z "${KRES_INSTALL_DIR:-}" ]; then
	KRES_INSTALL_DIR="$install_dir"
fi
if [ -z "${KRES_CONFIG_FILE:-}" ]; then
    KRES_CONFIG_FILE="$gitroot/etc/config/config.dev.yaml"
fi
export KRES_INSTALL_DIR
export KRES_CONFIG_FILE

function meson_setup_configure {
	reconfigure=''
	if [ -d .build ]; then
		reconfigure='--reconfigure'
	fi
	echo
	echo ---------------------------------------
	echo Configuring build directory using Meson
	echo ---------------------------------------
	meson setup \
		$build_dir \
		$reconfigure \
		--prefix=$KRES_INSTALL_DIR \
		-D user=$(id -un) \
		-D group=$(id -gn) \
		"$@"
	echo
	echo -----------------------------------------------
	echo Copying constants.py module configured by Meson
	echo -----------------------------------------------
	cp -v $build_dir/python/constants.py $gitroot/python/knot_resolver/constants.py
	echo
}

function is_buil_dir_configured {
	if [ ! -d .build ]; then
		echo
		echo Knot Resolver build directory is not configured by Meson.
		echo "Please run './poe configure' (optionally with additional Meson arguments)".
		echo
		exit 2
	fi
}

function ninja_install {

	is_buil_dir_configured

	echo
	echo --------------------------------------------
	echo Building/installing C komponents using ninja
	echo --------------------------------------------
	ninja -C $build_dir
	ninja install -C $build_dir

	mkdir -vp $KRES_INSTALL_DIR/run/knot-resolver $KRES_INSTALL_DIR/var/cache/knot-resolver
	echo
}
