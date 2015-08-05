#!/bin/bash

CFG_NAME="$SOCKET_WRAPPER_DIR/config"

echo "net.listen('$CONFIG_CHILD_ADDR',53)" > $CFG_NAME
echo "cache.size = 10*MB" >> $CFG_NAME
echo "modules = {'hints'}" >> $CFG_NAME
echo "hints.root({['k.root-servers.net'] = '$CONFIG_SELF_ADDR'})" >> $CFG_NAME
if [ "$CONFIG_NO_MINIMIZE" == "1" ];
then
  echo "option('NO_MINIMIZE', true)" >> $CFG_NAME
else
  echo "option('NO_MINIMIZE', false)" >> $CFG_NAME
fi
echo  "option('ALLOW_LOCAL', true)"  >> $CFG_NAME

