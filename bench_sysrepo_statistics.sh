#!/bin/bash

SAMPLES_PER_SIZE=2
SIZES=$(seq 500 500 50000)

echo "DATA_SIZE;sysrepo_load;sysrepo_get;knot_apply;knot_serialize;knot_module_load;knot_startup_whole" > stat.csv

# DATA_SIZE - počet položek v datasetu
# sysrepo_load - jak dlouho trvalo načíst data do sysrepa ze souboru pomocí programu sysrepocfg
# sysrepo_get - jak dlouho trvalo získat data z operational datastoru programem sysrepocfg
# knot_apply - jak dlouho trval v resolveru callback zpracovavajici data
# knot_serialize - jak dlouho trval callback v resolveru serializujici data
# knot_module_load - jak dlouho trvalo volani modules.load("sysrepo-lua"). Obsahuje knot_apply
# knot_startup_whole - jak dlouho trvalo nastartovat resolver, pouze cele sekundy, melo by byt stejne jako knot_module_load

for size in $SIZES; do
    for i in $(seq $SAMPLES_PER_SIZE); do
        DATA_SIZE="$size" ./bench_sysrepo.sh stat.csv
    done
done
