#!/bin/sh

ninja -C build install
GSETTINGS_BACKEND=memory GSETTINGS_SCHEMA_DIR=out/share/glib-2.0/schemas/ LANG=en-US out/bin/layer-cake-gui
