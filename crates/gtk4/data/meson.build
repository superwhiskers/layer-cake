# icons

subdir('icons')

# resources

subdir('resources')

# desktop file

conf = configuration_data()
conf.set('APP_ID', app_id)
conf.set('PKGNAME', meson.project_name())
conf.set('NAME', name)

desktop_file = i18n.merge_file(
  input: configure_file(
    input: '@0@.desktop.in.in'.format(base_id),
    output: '@0@.desktop.in'.format(base_id),
    configuration: conf,
  ),
  output: '@0@.desktop'.format(app_id),
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: datadir / 'applications',
)

desktop_utils = find_program('desktop-file-validate', required: false)
if desktop_utils.found()
  test(
    'validate desktop file',
    desktop_utils,
    args: [desktop_file],
  )
endif

# appdata

conf = configuration_data()
conf.set('APP_ID', app_id)
conf.set('PKGNAME', meson.project_name())
conf.set('NAME', name)

appdata_file = i18n.merge_file(
  input: configure_file(
    input: '@0@.metainfo.xml.in.in'.format(base_id),
    output: '@0@.metainfo.xml.in'.format(base_id),
    configuration: conf,
  ),
  output: '@0@.metainfo.xml'.format(app_id),
  po_dir: '../po',
  install: true,
  install_dir: datadir / 'metainfo',
)

appstreamcli = find_program('appstreamcli', required: false)
if appstreamcli.found()
  test(
    'validate appdata',
    appstreamcli,
    args: ['validate', '--nonet', appdata_file.full_path()],
  )
endif

# gschema

conf = configuration_data()
conf.set('APP_ID', app_id)
conf.set('PATH_ID', path_id)
conf.set('PKGNAME', meson.project_name())

schema = configure_file(
  input: '@0@.gschema.xml.in'.format(base_id),
  output: '@0@.gschema.xml'.format(app_id),
  configuration: conf,
  install: true,
  install_dir: datadir / 'glib-2.0' / 'schemas',
)

# finalize

gnome.post_install(
  gtk_update_icon_cache: true,
  glib_compile_schemas: true,
  update_desktop_database: true,
)
