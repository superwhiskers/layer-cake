#!/bin/sh
set -eu
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="clang"
export RUSTFLAGS="\
    -C target-cpu=x86-64-v3 \
    -Z stack-protector=strong \
    -Z cf-protection=full \
    -Z sanitizer=cfi \
    -Z sanitizer=safestack \
    -C link-arg=-Wl,-z,now \
    -C link-arg=-Wl,-z,noexecstack \
    -C link-arg=-Wl,-z,separate-code \
    -C link-arg=-fuse-ld=lld \
    -C linker-plugin-lto"
cargo build \
    --profile release \
    -Z build-std=std,panic_abort \
    -Z build-std-features=panic_immediate_abort \
    "$@"
