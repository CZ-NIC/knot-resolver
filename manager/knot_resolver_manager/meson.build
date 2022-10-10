cli_dir = 'cli'
subdir(cli_dir)

compat_dir = 'compat'
subdir(compat_dir)

datamodel_dir = 'datamodel'
subdir(datamodel_dir)

kresd_controller_dir = 'kresd_controller'
subdir(kresd_controller_dir)

utils_dir = 'utils'
subdir(utils_dir)

py3.install_sources(
    files(
        '__init__.py',
        '__main__.py',
        'config_store.py',
        'constants.py',
        'exceptions.py',
        'kres_manager.py',
        'log.py',
        'main.py',
        'server.py',
        'statistics.py',
    ),
    subdir: manager_module_dir
)
