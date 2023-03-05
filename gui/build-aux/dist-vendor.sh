#!/bin/sh

export SOURCE_ROOT="${1}"
export DIST="${2}"

cd "${SOURCE_ROOT}"
mkdir "${DIST}/.cargo"

cargo vendor | sed 's/^directory = ".*"/directory = "vendor"/g' > "${DIST}/.cargo/config"

mv vendor "${DIST}"
