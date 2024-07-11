#!/bin/bash

# ensure consistent behaviour
scripts_dir="$(dirname "$(realpath "$0")")"

# change dir to 'manager'
cd $scripts_dir
cd ..

echo "building the Manager ..."
python3 setup.py install
