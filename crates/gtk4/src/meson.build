conf = configuration_data()
conf.set_quoted('PKGNAME', meson.project_name())
conf.set_quoted('APP_ID', app_id)
conf.set_quoted('PATH_ID', path_id)
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PROFILE', get_option('profile'))
conf.set_quoted(
  'VCS_TAG',
  run_command(
    'git',
    'rev-parse',
    '--short',
    'HEAD',
    check: false,
  ).stdout().strip(),
)
conf.set_quoted('DATADIR', datadir)

configure_file(
  input: 'config.rs.in',
  output: 'config.rs',
  configuration: conf,
)

run_command(
  'cp',
  meson.project_build_root() / 'src' / 'config.rs',
  meson.project_source_root() / 'src' / 'config.rs',
  check: true,
)

cargo = find_program('cargo')
cargo_env = [ 'CARGO_HOME=' + meson.project_build_root() / 'cargo-home' ]
cargo_options = [
  '--manifest-path', meson.project_source_root() / 'Cargo.toml',
  '--target-dir', meson.project_build_root() / 'target',
]

rust_target = 'debug'
if get_option('profile') == 'release'
  cargo_options += [ '--release' ]
  rust_target = 'release'
endif

cargo_release = custom_target(
  'cargo-build',
  build_by_default: true,
  build_always_stale: true,
  output: meson.project_name(),
  console: true,
  install: true,
  install_dir: bindir,
  command: [
    'env',
    cargo_env,
    cargo,
    'build',
    cargo_options,
    '&&',
    'cp',
    'target' / rust_target / meson.project_name(),
    '@OUTPUT@',
  ],
)
