#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
source_root="$root"
default_build="$root/build-desktop"
# Header-heavy compilation through /mnt/c or /mnt/d is slow under WSL.
# Copy changed inputs once; compile and cache on the Linux filesystem.
if [[ "$root" == /mnt/[a-z]/* && "${TDONGLE_SOURCE_CACHE:-1}" == 1 ]]; then
  source_root=$(python3 "$root/tools/cache_desktop_source.py" "$root")
  default_build="$(dirname "$source_root")/build-desktop"
fi
build="${TDONGLE_DESKTOP_BUILD_DIR:-$default_build}"
if [[ "${1:-}" == --release-test ]]; then
  command -v ykman >/dev/null || { echo 'Release regression requires ykman with script support' >&2; exit 2; }
  [[ -f "${PICO_SDK_PATH:-}/src/rp2350/hardware_regs/include/hardware/regs/otp_data.h" ]] || {
    echo 'Release regression requires PICO_SDK_PATH pointing to the device Pico SDK' >&2; exit 2;
  }
fi
if ! command -v cmake >/dev/null || ! command -v pkg-config >/dev/null || ! pkg-config --exists sdl2; then
  if [[ "$(uname -s)" == Darwin ]]; then
    printf '%s\n' 'Install build prerequisites: xcode-select --install; brew install cmake pkgconf sdl2-compat python ccache' >&2
  else
    printf '%s\n' 'Install build prerequisites: sudo apt-get install cmake build-essential pkg-config libsdl2-dev python3-venv ccache' >&2
  fi
  exit 2
fi
launcher=()
if command -v ccache >/dev/null; then
  export CCACHE_DIR="${TDONGLE_CCACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/tdongle/ccache}"
  export CCACHE_MAXSIZE=256M
  launcher=(-DCMAKE_C_COMPILER_LAUNCHER=ccache)
fi
cmake -S "$source_root" -B "$build" -DENABLE_EMULATION=ON -DENABLE_EDDSA=ON \
  -DPICO_FIDO_ESP_BOARD=tdongle-s3 -DVIDPID=Yubikey5 "${launcher[@]}"
cmake --build "$build" -j "${TDONGLE_BUILD_JOBS:-2}"
if [[ "${1:-}" == --test || "${1:-}" == --release-test ]]; then
  ctest --test-dir "$build" -R '^gui-(card-)?behavior$' --output-on-failure
  if [[ ! -x "$build/venv/bin/python" ]]; then python3 -m venv "$build/venv"; fi
  requirements="$root/tests/requirements.txt"
  installed_requirements="$build/venv/tdongle-requirements.txt"
  if ! cmp -s "$requirements" "$installed_requirements"; then
    "$build/venv/bin/python" -m pip install --disable-pip-version-check -r "$requirements"
    cp "$requirements" "$installed_requirements"
  fi
  TDONGLE_SIM_BINARY="$build/pico_fido2" "$build/venv/bin/python" "$root/tests/test_emulation.py"
  TDONGLE_SIM_BINARY="$build/pico_fido2" "$build/venv/bin/python" "$root/tests/test_legacy_upgrade.py"
  TDONGLE_SIM_BINARY="$build/pico_fido2" "$build/venv/bin/python" "$root/tests/test_openpgp_isolation.py"
  TDONGLE_SIM_BINARY="$build/pico_fido2" "$build/venv/bin/python" "$root/tests/test_yubikey_comparison.py"
  "$build/venv/bin/python" "$root/tests/test_flash_app.py"
  "$build/venv/bin/python" "$root/tests/test_gnupg_bindings.py"
  "$build/venv/bin/python" "$root/tests/test_hid_completion.py"
  "$build/venv/bin/python" "$root/tests/test_credential_bounds.py"
  "$build/venv/bin/python" "$root/tests/test_apa102.py"
  "$build/venv/bin/python" "$root/tests/test_ccid_descriptor.py"
  TDONGLE_SIM_BINARY="$build/pico_fido2" "$build/venv/bin/python" "$root/tests/test_hid_transactions.py"
  if [[ "${1:-}" == --release-test ]]; then
    TDONGLE_SIM_BINARY="$build/pico_fido2" ykman script --force --site-dir "$root/tests" "$root/tests/test_yubikey_clients.py"
    TDONGLE_SIM_BINARY="$build/pico_fido2" ykman script --force --site-dir "$root/tests" "$root/tests/test_piv_certificates.py"
    for suite in test_esp32_efuse_readonly test_rp2350_otp_readonly test_pico_led; do
      "$build/venv/bin/python" "$root/tests/$suite.py"
    done
  fi
else
  mkdir -p "$root/.cache/simulator-state"
  exec "$build/pico_fido2" --state-dir "$root/.cache/simulator-state" "$@"
fi
