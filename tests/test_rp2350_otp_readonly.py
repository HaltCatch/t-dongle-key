"""Compile the real RP2350 backend against read-only fake register banks.

Run with PICO_SDK_PATH pointing to the SDK used for the device build.
There is intentionally no OTP programming API in the test headers.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReadOnlyOtp(unittest.TestCase):
    def test_existing_legacy_missing_and_invalid_keys(self):
        sdk = Path(os.environ["PICO_SDK_PATH"])
        regs = sdk / "src/rp2350/hardware_regs/include/hardware/regs/otp_data.h"
        self.assertTrue(regs.is_file())
        with tempfile.TemporaryDirectory(prefix="rp2350-otp-test-") as temp:
            directory = Path(temp)
            headers = {
                "picokeys.h": r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define PICOKEYS_EXEC_ERROR (-1)
typedef struct { const uint8_t *data; size_t len; } const_byte_array_t;
#define CONST_BYTE_ARRAY(p,n) ((const_byte_array_t){(p),(n)})
static jmp_buf panic_env;
#define panic(...) longjmp(panic_env,1)
static uint16_t ecc[4096];
static uint32_t raw[4096];
#define OTP_DATA_BASE ((uintptr_t)ecc)
#define OTP_DATA_RAW_BASE ((uintptr_t)raw)
#define _u(x) x##u
''',
                "pico/bootrom.h": "/* No OTP write API available. */\n",
                "hardware/structs/otp.h": "/* No writable OTP registers available. */\n",
                "hardware/regs/otp_data.h": regs.read_text(),
                "random.h": "",
                "mbedtls/ecdsa.h": "",
            }
            for name, contents in headers.items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            source = ROOT / "pico-keys-sdk/src/otp/otp_rp2350.c"
            harness = '#include "' + str(source) + '"\n' + r'''
#include <assert.h>
static void fill(unsigned row, uint8_t value) {
    memset(ecc + row, value, 32);
    memset(raw + row, value, 64);
}
static void check(bool expect_panic, unsigned root, unsigned device) {
    uint16_t before_ecc[4096]; uint32_t before_raw[4096];
    memcpy(before_ecc,ecc,sizeof(ecc)); memcpy(before_raw,raw,sizeof(raw));
    const uint8_t *one=NULL,*two=NULL;
    if (setjmp(panic_env)==0) {
        otp_platform_init(&one,&two);
        assert(!expect_panic);
        assert(one==(const uint8_t *)(ecc+root));
        assert(two==(device ? (const uint8_t *)(ecc+device) : NULL));
    } else assert(expect_panic);
    for(unsigned key=0;key<7;key++) {
        assert(otp_platform_enable_secure_boot(key,false)!=0);
        assert(otp_platform_enable_secure_boot(key,true)!=0);
    }
    assert(!otp_platform_is_secure_boot_enabled(NULL));
    assert(!otp_platform_is_secure_boot_locked());
    assert(memcmp(before_ecc,ecc,sizeof(ecc))==0);
    assert(memcmp(before_raw,raw,sizeof(raw))==0);
}
int main(void) {
    check(true,0,0); /* Blank chip must not silently use serial-derived keys. */
    fill(0xef0,0x31); fill(0xed0,0x32);
    check(false,0xef0,0xed0); /* Legacy keys stay in their old rows. */
    fill(0xe90,0x41); fill(0xe80,0x42);
    check(false,0xe90,0xe80); /* Existing new rows take precedence. */
    memset(ecc,0,sizeof(ecc)); memset(raw,0,sizeof(raw));
    fill(0xe90,0x41);
    check(false,0xe90,0); /* Attestation uses encrypted flash if absent. */
    fill(0xe90,0xff);
    check(true,0,0); /* Invalidated keys must not become a new root. */
    memset(ecc+0xe90,0,32);
    check(true,0,0); /* Raw rows occupied but ECC view unreadable. */
    return 0;
}
'''
            test_source = directory / "test.c"
            test_source.write_text(harness)
            binary = directory / "test"
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(directory), str(test_source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
