#!/bin/sh
set -eu
export RUSTFLAGS="\
    -C target-feature=+crt-static"
cargo build \
    --release \
    -p bbx \
    --target x86_64-unknown-linux-musl
