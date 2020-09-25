# etc
# SPDX-License-Identifier: GPL-3.0-or-later

etc_files = []

if install_root_hints
  etc_files += 'root.hints'
endif

if managed_ta
  etc_files += 'icann-ca.pem'
endif

if install_root_keys
  root_keys_path = keyfile_default.split('/')
  root_keys_filename = root_keys_path[-1]
  root_keys_dir = []
  foreach el : root_keys_path
    if el != root_keys_filename
      root_keys_dir += el
    endif
  endforeach
  install_data(
    sources: 'root.keys',
    rename: root_keys_filename,
    install_dir: '/'.join(root_keys_dir)
  )
endif


subdir('config')


install_data(
  sources: etc_files,
  install_dir: etc_dir
)
