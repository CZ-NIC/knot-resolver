#!/bin/bash

################################################################################
#
# Debugging harness for Knot Resolver
#
# Convenience script for running kresd with different tools and configurations.
# Always automatically builds kresd before running, deletes kresd's caches,
# optionally cleans the build directory, etc.
#
# For more info about the script's options, run it with '--help'.
#
# The recommended way of using this script is to create a simple wrapper script,
# which may look something like this:
#
#   #!/bin/bash
#   export KRDBG_SCRIPT_FILE="$(realpath "${BASH_SOURCE[0]}")"
#   export KRDBG_WORKING_DIR="/tmp/krwd"
#   export KRDBG_NINJA_PATH="/path/to/knot-resolver/build_dir"
#   export KRDBG_PREFIX="/path/to/install/prefix"
#   source "/path/to/this/script.sh"
#
# Note that KRDBG_PREFIX must match the one configured by Meson in
# KRDBG_NINJA_PATH.
#
# KRDBG_WORKING_DIR is the working directory for kresd, where its cache and
# potentially other data is stored. It is recommended for it to be in tmpfs.
#
################################################################################


## Help ########################################################################

short_help_text=$(cat << EOF
Debugging harness for Knot Resolver
USAGE: $0 [options] -- [kresd args]
EOF
)

help_text=$(cat << EOF
$short_help_text

Available options:
	-a, --vim-debug [executable]
		Runs kresd under Termdebug in the specified version of Vim
		(vim by default). Termdebug must be enabled for this to work
		(:packadd termdebug).

	-b, --debug [debugger]
		Runs kresd under the specified debugger (gdb by default)

	-c, --clean
		Cleans the Ninja directory before running

	-d, --no-run
		Performs all the preparation steps, but does not run kresd
		itself (may be used for extra cleanup if the user forgot about
		something the last time)

	-g, --valgrind
		Runs kresd under Valgrind Memcheck

	-h, --help
		Displays this help and exits

	-l, --callgrind [args]
		Runs kresd under Valgrind Callgrind, optionally with the
		specified arguments, with default output to
		'callgrind.out.kresd' in the wrapper script directory

	-m, --massif [args]
		Runs kresd under Valgrind Massif, optionally with the specified
		arguments, with default output to 'massif.out.kresd' in
		the wrapper script directory

	-n, --no-delete
		Does not delete kresd's working directory data before running

	-p, --caps
		Uses setcap to set XDP capabilities for kresd and, optionally,
		the debugger if --debug is specified

	-r, --rr [args]
		Records kresd's run using rr, optionally with the specified
		arguments

	-s, --sudo
		Runs kresd with sudo

	-x, --xdp-if <interfaces>
		Sets interfaces to clean up XDP on after kresd ends. Multiple
		interfaces are comma-separated.
EOF
)


## Basic script setup ##########################################################

set -e

kill_and_wait_all () {
	JOBS=$(jobs -p)
	if [ -n "$JOBS" ]; then
		kill $JOBS
		wait $JOBS
	fi
}

trap "kill_and_wait_all" EXIT


## Process environment variables ###############################################

if [ -z "$KRDBG_NINJA_PATH" ]; then
	echo '$KRDBG_NINJA_PATH missing - set it to the Ninja build directory of kresd' >&2
	exit 1
fi
build_path="$KRDBG_NINJA_PATH"

if [ -z "$KRDBG_PREFIX" ]; then
	# TODO - could potentially be automated
	echo '$KRDBG_PREFIX missing - set it to the prefix where Ninja installs kresd' >&2
	exit 1
fi
kresd_path="$KRDBG_PREFIX/sbin/kresd"

if [ -z "$KRDBG_WORKING_DIR" ]; then
	echo '$KRDBG_WORKING_DIR missing - set it to the desired working directory of kresd' >&2
	exit 1
fi
wd_dir="$KRDBG_WORKING_DIR"

if [ -z "$KRDBG_SCRIPT_FILE" ]; then
	echo '$KRDBG_SCRIPT_FILE missing - set it to the path to the script that executes the harness' >&2
	exit 1
fi
script_file=$(realpath "$KRDBG_SCRIPT_FILE")
script_dir=$(cd -- "$(dirname -- "$script_file")" && pwd)

if [ -z "$KRDBG_CONFIG" ]; then
	config="$script_dir/kresd.conf"
else
	config="$(realpath $KRDBG_CONFIG)"
fi


## Process CLI arguments #######################################################

GETOPT=$(getopt \
	--options     'a::b::cdghl::m::npr::sx'\
	--longoptions 'vim-debug::,debug::,clean,no-run,valgrind,help,callgrind::,massif::,no-delete,caps,rr::,sudo,xdp-if:'\
	--name 'krdbg'\
	-- "$@")

if [ $? -ne 0 ]; then
	echo "$short_help_text" >&2
	echo 'Terminating...' >&2
	exit 1
fi

eval set -- "$GETOPT"
unset GETOPT

while true; do
	case "$1" in
		'-a'|'--vim-debug')
			vim_debug=1
			if [ -z "$2" ]; then
				dbgvim="vim"
			else
				dbgvim="$2"
			fi
			shift 2
			continue
			;;
		'-b'|'--debug')
			debug=1
			if [ -z "$2" ]; then
				debugger="gdb --args"
			else
				debugger="$2"
			fi
			shift 2
			continue
			;;
		'-c'|'--clean')
			clean=1
			shift
			continue
			;;
		'-d'|'--no-run')
			no_run=1
			shift
			continue
			;;
		'-g'|'--valgrind')
			valgrind=1
			shift
			continue
			;;
		'-h'|'--help')
			echo "$help_text"
			exit 0
			;;
		'-l'|'--callgrind')
			callgrind=1
			callgrind_args="$2"
			shift 2
			continue
			;;
		'-m'|'--massif')
			massif=1
			massif_args="$2"
			shift 2
			continue
			;;
		'-n'|'--no-delete')
			no_delete=1
			shift
			continue
			;;
		'-p'|'--caps')
			caps=1
			shift
			continue
			;;
		'-r'|'--rr')
			rr=1
			rr_args="$2"
			shift 2
			continue
			;;
		'-s'|'--sudo')
			sudo=1
			shift
			continue
			;;
		'-x'|'--xdp-if')
			xdp_if="$2"
			shift 2
			continue
			;;
		'--')
			shift
			break
			;;
		*)
			echo 'Internal error!' >&2
			exit 1
			;;
	esac
done


## Validate options ############################################################

if [ "$vim_debug" == "1" -a "$debug" == "1" ]; then
	echo '--debug and --vim-debug are mutually exclusive!' >&2
	exit 1
fi


## Prepare kresd ###############################################################

mkdir -p "$wd_dir"
cd "$wd_dir"

if [ "$clean" == "1" ]; then
	ninja clean -C "$build_path"
fi

ninja -C "$build_path"
ninja install -C "$build_path"

kr_command="\"$kresd_path\" --config=\"$config\" $@"

if [ -z "$no_delete" -o "$no_delete" == "0" ]; then
	rm_command="rm -rf control data.mdb lock.mdb"
	$rm_command || sudo $rm_command
fi

caps_string=$(cat << EOF
	CAP_NET_BIND_SERVICE=+eip
	CAP_NET_RAW=+eip
	CAP_NET_ADMIN=+eip
	CAP_SYS_ADMIN=+eip
	CAP_IPC_LOCK=+eip
	CAP_SYS_RESOURCE=+eip
	CAP_SYS_PTRACE=+eip
EOF
)

if [ "$caps" == "1" ]; then
	sudo setcap "$caps_string" "$kresd_path"
	sudo setcap -v "$caps_string" "$kresd_path"
fi


## Prepare the kresd command ###################################################

if [ "$rr" == "1" ]; then
	if [ "$caps" == "1" ]; then
		kr_command="sudo -EP --preserve-env=HOME rr record --setuid-sudo $rr_args $kr_command"
	else
		kr_command="rr record $rr_args $kr_command"
	fi
fi
if [ "$vim_debug" == "1" ]; then
	kr_command="$dbgvim -c ':cd $build_path' -c ':TermdebugCommand $(eval "echo $kr_command")'"
fi
if [ "$debug" == "1" ]; then
	kr_command="${debugger[@]} $kr_command"
fi
if [ "$callgrind" == "1" ]; then
	kr_command="valgrind --tool=callgrind --callgrind-out-file=\"$script_dir/callgrind.out.kresd\" $callgrind_args -- $kr_command"
fi
if [ "$massif" == "1" ]; then
	kr_command="valgrind --tool=massif --massif-out-file=\"$script_dir/massif.out.kresd\" $massif_args -- $kr_command"
fi
if [ "$valgrind" == "1" ]; then
	kr_command="valgrind -- $kr_command"
fi
if [ "$sudo" == "1" ]; then
	kr_command="sudo $kr_command"
fi


## Run kresd ###################################################################

export ASAN_OPTIONS="$ASAN_OPTIONS:disable_coredump=0:unmap_shadow_on_exit=1:abort_on_error=1"
set +e
echo "Command: $kr_command"

if [ -z "$no_run" -o "$no_run" == 0 ]; then
	eval $kr_command
	echo "Exited with $?"
else
	echo "--no-run specified - skipping kresd"
fi


## Clean up ####################################################################

if [ -n "$xdp_if" ]; then
	for ifc in $(echo $xdp_if | tr ',' ' '); do
		echo "Disabling XDP for $ifc"
		sudo ip link set dev "$ifc" xdp off
	done
fi

