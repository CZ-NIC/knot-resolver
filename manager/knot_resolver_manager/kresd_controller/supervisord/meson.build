plugin_dir = 'plugin'
subdir(plugin_dir)

py3.install_sources(
    files(
        '__init__.py',
        'config_file.py',
        'supervisord.conf.j2'
    ),
    subdir: manager_module_dir / kresd_controller_dir / supervisord_dir
)
