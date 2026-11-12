#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Only initialize dependencies used by the combined target; each child project's
# own SDK checkout is redundant and may describe a different firmware baseline.
git submodule sync
git submodule update --init --depth 1 pico-fido pico-openpgp pico-keys-sdk third_party/lvgl
git -C pico-keys-sdk submodule sync
git -C pico-keys-sdk submodule update --init --depth 1 third-party/mbedtls third-party/tinycbor third-party/libcvc
git -C pico-keys-sdk/third-party/mbedtls submodule update --init --depth 1 framework
git submodule status
