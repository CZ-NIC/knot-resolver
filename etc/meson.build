# etc

etc_files = []

if install_root_hints
  etc_files += 'root.hints'
endif

if managed_ta
  etc_files += 'icann-ca.pem'
endif

if install_root_keys
  etc_files += 'root.keys'
endif


subdir('config')


install_data(
  sources: etc_files,
  install_dir: etc_dir
)
