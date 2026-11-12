"""Compile the actual ESP32 backend without providing any eFuse write APIs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReadOnlyEfuse(unittest.TestCase):
    def test_read_only_initialization_and_secure_boot_denial(self):
        with tempfile.TemporaryDirectory(prefix="esp-efuse-test-") as temp:
            directory = Path(temp)
            headers = {
                "picokeys.h": r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define PICOKEYS_EXEC_ERROR (-1)
static jmp_buf fatal_env;
#define abort() longjmp(fatal_env,1)
''',
                "byte_array.h": r'''
typedef struct { uint8_t *data; size_t len; } byte_array_t;
#define BYTE_ARRAY(p,n) ((byte_array_t){(p),(n)})
''',
                "esp_efuse.h": r'''
typedef int esp_err_t;
typedef int esp_efuse_block_t;
typedef int esp_efuse_purpose_t;
typedef int esp_efuse_desc_t;
enum {ESP_OK=0, ESP_FAIL=-1};
enum {EFUSE_BLK_KEY0=0, EFUSE_BLK_KEY3=3, EFUSE_BLK_KEY4=4, EFUSE_BLK_KEY_MAX=7};
enum {ESP_EFUSE_KEY_PURPOSE_USER=0, ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0=9,
      ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2,
      ESP_EFUSE_KEY_PURPOSE_MAX};
static uint8_t keys[7][32];
static bool used[7], fail_read;
static int purposes[7];
static bool esp_efuse_key_block_unused(int block) {return !used[block];}
static int esp_efuse_get_key_purpose(int block) {return purposes[block];}
static const esp_efuse_desc_t **esp_efuse_get_key(int block) {
    static int indices[]={0,1,2,3,4,5,6};
    static const int *descs[7]; descs[block]=&indices[block]; return &descs[block];
}
static int esp_efuse_read_field_blob(const esp_efuse_desc_t **desc, void *out, size_t bits) {
    if(fail_read) return ESP_FAIL;
    memcpy(out,keys[**desc],bits/8); return ESP_OK;
}
static bool esp_efuse_read_field_bit(const esp_efuse_desc_t **desc) {(void)desc;return false;}
static bool esp_efuse_get_digest_revoke(int index) {(void)index;return false;}
''',
                "esp_efuse_table.h": "#define ESP_EFUSE_SECURE_BOOT_EN NULL\n",
                "random.h": "",
                "mbedtls/ecdsa.h": "",
            }
            for name, contents in headers.items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            source = ROOT / "pico-keys-sdk/src/otp/otp_esp32.c"
            harness = '#include "' + str(source) + '"\n' + r'''
#include <assert.h>
static void check(bool expect_abort, bool device) {
    uint8_t before[sizeof(keys)]; memcpy(before,keys,sizeof(keys));
    const uint8_t *one=NULL,*two=NULL;
    if(setjmp(fatal_env)==0) {
        otp_platform_init(&one,&two); assert(!expect_abort);
        assert(memcmp(one,keys[3],32)==0);
        if(device) assert(memcmp(two,keys[4],32)==0); else assert(two==NULL);
    } else assert(expect_abort);
    for(unsigned i=0;i<4;i++) {
        assert(otp_platform_enable_secure_boot(i,false)!=0);
        assert(otp_platform_enable_secure_boot(i,true)!=0);
    }
    assert(!otp_platform_is_secure_boot_enabled(NULL));
    assert(!otp_platform_is_secure_boot_locked());
    assert(memcmp(before,keys,sizeof(keys))==0);
}
int main(void) {
    check(true,false);
    used[3]=true;memset(keys[3],0x31,32);check(false,false);
    used[4]=true;memset(keys[4],0x41,32);check(false,true);
    fail_read=true;check(true,false);fail_read=false;
    purposes[3]=9;check(true,false);purposes[3]=0;
    memset(keys[3],0xff,32);check(true,false);
    memset(keys[3],0,32);check(true,false);
    return 0;
}
'''
            test_source = directory / "test.c"
            test_source.write_text(harness)
            binary = directory / "test"
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(directory), str(test_source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
