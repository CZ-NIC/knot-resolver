#!/bin/bash
set -o nounset
cd "$(dirname $0)/.."

# Get date from NEWS if possible (regular release)
head -n1 < NEWS | sed 's/.*(\(.*\)).*/\1/' | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$$'

if [[ $? -ne 0 ]]; then
    # or use last modification time of NEWS (dev versions)
    date -u -r NEWS +%F
fi
