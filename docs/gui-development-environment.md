# dev instructions for the gui

setting up the development environment for the gui is somewhat nonobvious. here are instructions for this

all of these assume you're in a shell within the `gui/` directory

# non-flatpak

## requirements

- meson
- java, probably
- gtk dev libraries (just look at the os you're on and work out how to install them)

## setting up

```
# either
./setup.sh

# or
meson setup --prefix="${PWD}/out" build/
```

## building

```
# this builds and installs the project to the prefix
ninja -C build/ install
```

## running

```
# either (which sets the language to en-US because of my setup quirks)
./run.sh

# or
GSETTINGS_BACKEND=memory GSETTINGS_SCHEMA_DIR=out/share/glib-2.0/schemas/ out/bin/layer-cake-gui
```

# flatpak (i haven't actually tried this in a bit)

## requirements

- flatpak
- meson
- fenv (install from https://gitlab.gnome.org/ZanderBrown/fenv) (maybe gnome builder works but i do not use this)

## installing flatpak sdk stuff

```
# add the repos
flatpak remote-add --user --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
flatpak remote-add --user --if-not-exists gnome-nightly https://nightly.gnome.org/gnome-nightly.flatpakrepo

# runtime
flatpak install --user gnome-nightly org.gnome.Sdk//master org.gnome.Platform//master

# extensions

## rust
flatpak install --user flathub org.freedesktop.Sdk.Extension.rust-stable//22.08

## openjdk17
flatpak install --user flathub org.freedesktop.Sdk.Extension.openjdk17//22.08

## openjdk8
flatpak install --user flathub org.freedesktop.Sdk.Extension.openjdk8//22.08
```

## setting up fenv

```
# set up the flatpak environment
fenv gen build-aux/io.github.superwhiskers.layer_cake.dev.yaml

# initialize the meson build directory
fenv exec -- meson setup --prefix=/app build
```

now you can test changes with

```
fenv exec -- ninja -C build install

fenv exec ./build/src/layer-cake-gui
```

this may be simplified in the future
