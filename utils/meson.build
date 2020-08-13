# utils
# SPDX-License-Identifier: GPL-3.0-or-later

build_utils = get_option('utils') != 'disabled'

subdir('watcher')
subdir('client')
if build_sysrepo
  subdir('cache_gc')
endif
subdir('upgrade')
