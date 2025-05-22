project(
  'layer-cake-gui',
  'rust',
  version: '0.0.0',
  license: 'GPL-3.0-or-later',
  meson_version: '>= 0.63'
)

i18n = import('i18n')
gnome = import('gnome')

dependency('glib-2.0', version: '>= 2.74')
dependency('gio-2.0', version: '>= 2.74')
dependency('gtk4', version: '>= 4.8.0')
dependency('libadwaita-1', version: '>= 1.2.0')

name = 'layer cake'
base_id = 'io.github.superwhiskers.layer_cake'
app_id = base_id
path_id = '/io/github/superwhiskers/layer-cake'
datadir = get_option('prefix') / get_option('datadir')
bindir = get_option('prefix') / get_option('bindir')

if get_option('profile') == 'development'
  app_id = '@0@.dev'.format(app_id)
  path_id = '@0@/dev'.format(path_id)
endif

meson.add_dist_script(
  'build-aux/dist-vendor.sh',
  meson.project_source_root(),
  meson.project_build_root() / 'meson-dist' / meson.project_name() + '-' + meson.project_version(),
)

subdir('po')
subdir('data')
subdir('src')
