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
build_dev_dir="$gitroot/.build_dev"
install_dev_dir="$gitroot/.install_dev"

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

# aggregated return value
aggregated_rv=0

# fail even on unbound variables
set -o nounset

# Set enviromental variables if not
if [ -z "${KRES_DEV_INSTALL_DIR:-}" ]; then
    KRES_DEV_INSTALL_DIR="$install_dev_dir"
fi
if [ -z "${KRES_DEV_CONFIG_FILE:-}" ]; then
    KRES_DEV_CONFIG_FILE="$gitroot/etc/config/${CONFIG_FILE_NAME:-config.dev.yaml}"
fi
export KRES_DEV_INSTALL_DIR
export KRES_DEV_CONFIG_FILE

function meson_setup_configure {
    local reconfigure=''
    if [ -d $build_dir ]; then
        reconfigure='--reconfigure'
    fi
    echo ---------------------------------------
    echo Configuring build directory using Meson
    echo ---------------------------------------
    meson setup \
        $build_dir \
        $reconfigure \
        --prefix=/usr \
        "$@"
}

function meson_setup_configure_dev {
    local reconfigure=''
    if [ -d $build_dev_dir ]; then
        reconfigure='--reconfigure'
    fi
    echo ---------------------------------------
    echo Configuring build directory using Meson
    echo ---------------------------------------
    meson setup \
        $build_dev_dir \
        $reconfigure \
        --prefix=$KRES_DEV_INSTALL_DIR \
        -D user=$(id -un) \
        -D group=$(id -gn) \
        "$@"
}

function is_build_dev_dir_configured {
    if [ ! -d $build_dev_dir ]; then
        echo
        echo Knot Resolver build directory is not configured by Meson.
        echo "Please run './poe configure' (optionally with additional Meson arguments)".
        echo
        exit 2
    fi
}

function ninja_dev_install {

    is_build_dev_dir_configured

    echo
    echo --------------------------------------------
    echo Building/installing C komponents using Ninja
    echo --------------------------------------------
    ninja -C $build_dev_dir
    ninja install -C $build_dev_dir
}

function check_rv {
    if test "$1" -eq 0; then
        echo -e "  ${green}OK${reset}"
    else
        echo -e "  ${red}FAIL${reset}"
    fi
    aggregated_rv=$(( $aggregated_rv + $1 ))
}

function fancy_message {
    if test "$aggregated_rv" -eq "0"; then
        echo -e "${green}Everything looks great!${reset}"
    else
        echo -e "${red}Failure.${reset}"
        echo -e "${red}These commands might help you:${reset}"
        echo -e "${red}\tpoe format${reset}"
        echo -e "${red}\tpoe gen-setuppy${reset}"
        echo -e "${red}\tpoe gen-constantspy${reset}"
        echo -e "${red}\tpoe gen-schema${reset}"
        echo -e "${red}That's not great. Could you please fix that?${reset} 😲😟"
    fi
}
