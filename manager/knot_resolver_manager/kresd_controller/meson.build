supervisord_dir = 'supervisord'
subdir(supervisord_dir)

py3.install_sources(
    files(
        '__init__.py',
        'interface.py',
    ),
    subdir: manager_module_dir / kresd_controller_dir
)
