#!/bin/bash

if test -z "$DATA_SIZE"; then
    DATA_SIZE=25000
fi

if test -z "$(which meson)" || test -z "$(which ninja)" || test -z "$(which sysrepocfg)" || test -z "$(which time)"
then
    echo "Missing dependency - these are required:"
    echo "meson, ninja, sysrepo, time"
    exit 1
fi

time="$(which time) -f %U -o /dev/stdout -a"

# build knot
# rm -rf build_dir /tmp/kr
meson build_dir --prefix=/tmp/kr --default-library=static
ninja -C build_dir
ninja -C build_dir install > /dev/null

# init sysrepo
git clone https://gitlab.labs.nic.cz/labs/resolvers-yang.git
cd resolvers-yang
git checkout sysrepo-test
cd ..
sysrepoctl -i resolvers-yang/yang-modules/cznic-test-sysrepo.yang

echo
echo "Generating dataset"
rm input*
python3 resolvers-yang/data_generator.py -n $DATA_SIZE -f input
mv $(eval "echo input*") input.json
echo

echo
echo "Loading data into sysrepo"
sysrepo_load=$($time sysrepocfg -C input.json)
echo "Elapsed $sysrepo_load"
echo

echo
SECONDS=0
echo "Starting Knot Resolver, output file out.log" 
rm kresd_input
mkfifo kresd_input
rm out.log
<kresd_input /tmp/kr/sbin/kresd -a ::@5353 >out.log 2>&1 &
cat > kresd_input <<END
os = require("os")
start = os.clock()
modules.load("sysrepo-lua")
elapsed = os.clock() - start
print("Module loaded in " .. tostring(elapsed) .. " seconds")
END

# wait for resolver to load data
while ! grep "Module loaded in" out.log > /dev/null; do
    sleep 1
done
knot_apply=$(grep "Data loading finished in" out.log | grep -o "[0-9.]* sec" | cut -d" " -f1)
knot_module_load=$(grep "Module loaded in " out.log | grep -o "[0-9.]* sec" | cut -d" " -f1)
knot_startup_whole=$SECONDS
echo "Config application: $knot_apply"
echo "Module load: $knot_module_load"
echo "Whole startup: $knot_startup_whole"
echo

echo
echo "Requesting data"
sysrepo_get=$($time sysrepocfg --export=/dev/null --format json -d operational -t 30)
echo "Elapsed $sysrepo_get"
echo

# wait for resolver to complete the serialization
echo
echo "Waiting for kresd to log about serialization"
while ! grep "Data serialization finished" out.log > /dev/null; do
    sleep 1
done
echo "Log of kresd says:"
knot_serialize=$(grep "Data serialization finished" out.log | grep -o "[0-9.]* sec" | cut -f1 -d" ")
echo "Data serialization took $knot_serialize"
echo

echo
echo "Cleaning up"
echo 'modules.unload("sysrepo-lua")' > kresd_input
echo "quit()" > kresd_input
sleep 1
killall -SIGKILL kresd
sysrepoctl -u cznic-test-sysrepo
rm -rf /tmp/kr input.json kresd_input
rm -rf /dev/shm/sr*

echo "If the script gets stuck next time its run, please delete repository of sysrepo"
echo "Output of the resolver left in a file out.log"

if test -z "$1"; then
    statfile="/dev/stdout"
else
    statfile="$1"
fi

echo
echo "$DATA_SIZE;$sysrepo_load;$sysrepo_get;$knot_apply;$knot_serialize;$knot_module_load;$knot_startup_whole" >> $statfile

