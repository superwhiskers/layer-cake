conf = configuration_data()
conf.set('PATH_ID', path_id)

gnome.compile_resources(
  app_id,
  configure_file(
    input: 'resources.gresource.xml.in'.format(base_id),
    output: 'resources.gresource.xml'.format(app_id),
    configuration: conf,
  ),
  gresource_bundle: true,
  source_dir: meson.project_build_root() / 'data',
  install: true,
  install_dir: datadir / meson.project_name(),
)
