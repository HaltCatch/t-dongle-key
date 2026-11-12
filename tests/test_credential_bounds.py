"""Compile credential envelope checks with fault-injected crypto calls."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class CredentialBounds(unittest.TestCase):
    def test_truncated_envelopes_and_crypto_failure(self):
        source = (ROOT / 'pico-fido/src/fido/credential.c').read_text()
        functions = source[source.index('static int credential_silent_tag'):source.index('int credential_create')]
        header = (ROOT / 'pico-fido/src/fido/credential.h').read_text()
        constants = '\n'.join(line for line in header.splitlines() if line.startswith('#define CRED_'))
        harness = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#define RP_ID_HASH_LEN 32
#define MBEDTLS_MD_SHA256 1
static int fail_at, calls;
static int step(void) { return ++calls == fail_at ? -99 : 0; }
typedef int mbedtls_sha256_context;
typedef int mbedtls_chachapoly_context;
typedef enum { CRED_PROTO_21=1, CRED_PROTO_22=2, CRED_PROTO_25=5 } cred_proto_t;
static const uint8_t *otp_key_1;
static uint8_t certdev_sha256[32];
static struct { uint8_t id[16]; } pico_serial;
static void mbedtls_sha256_init(int *p) { *p=0; }
static int mbedtls_sha256_starts(int *p,int n) { (void)p;(void)n;return step(); }
static int mbedtls_sha256_update(int *p,const uint8_t *d,size_t n) { (void)p;(void)d;(void)n;return step(); }
static int mbedtls_sha256_finish(int *p,uint8_t *o) { (void)p;memset(o,42,32);return step(); }
static void mbedtls_sha256_free(int *p) { (void)p; }
static void *mbedtls_md_info_from_type(int t) { (void)t;return 0; }
static int mbedtls_md_hmac(void *i,const uint8_t *k,size_t kl,const uint8_t *d,size_t n,uint8_t *o) {
 (void)i;(void)k;(void)kl;(void)d;(void)n;memset(o,42,32);return step(); }
static void mbedtls_platform_zeroize(void *p,size_t n) { memset(p,0,n); }
static int mbedtls_ct_memcmp(const void *a,const void *b,size_t n) { return memcmp(a,b,n); }
static int credential_derive_chacha_key(uint8_t *k,const uint8_t *id) { (void)k;(void)id;return step(); }
static void mbedtls_chachapoly_init(int *p) { *p=0; }
static int mbedtls_chachapoly_setkey(int *p,const uint8_t *k) { (void)p;(void)k;return 0; }
static int mbedtls_chachapoly_auth_decrypt(int *p,size_t n,const uint8_t *iv,const uint8_t *ad,size_t al,
 const uint8_t *tag,const uint8_t *in,uint8_t *out) {
 (void)p;(void)n;(void)iv;(void)ad;(void)al;(void)tag;(void)in;(void)out;return step(); }
static void mbedtls_chachapoly_free(int *p) { (void)p; }
'''+constants+'\n'+functions+r'''
int main(void) {
 uint8_t cred[64]={0},rp[32]={0},out[16];
 memcpy(cred,CRED_PROTO_25_S,4);
 for(size_t n=0;n<CRED_SILENT_ENVELOPE_OVERHEAD;n++) {
  calls=0;fail_at=0;
  assert(credential_verify(cred,n,rp,false)!=0);
  assert(credential_verify(cred,n,rp,true)!=0); assert(calls==0);
 }
 calls=0;fail_at=0;assert(credential_silent_tag(cred,sizeof(cred),rp,out)==0);
 int total=calls; assert(total==6);
 for(size_t i=0;i<sizeof(out);i++) assert(out[i]==42);
 memset(cred+sizeof(cred)-16,42,16);
 for(int failure=1;failure<=total;failure++) {
  calls=0;fail_at=failure;
  assert(credential_verify(cred,sizeof(cred),rp,true)!=0);
  calls=0;memset(out,42,sizeof(out));
  assert(credential_silent_tag(cred,sizeof(cred),rp,out)!=0);
  for(size_t i=0;i<sizeof(out);i++) assert(out[i]==0);
 }
 calls=0;fail_at=0;assert(credential_verify(cred,sizeof(cred),rp,true)==0);
 cred[sizeof(cred)-1]^=1;assert(credential_verify(cred,sizeof(cred),rp,true)!=0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);(path/'test.c').write_text(harness)
            subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-fno-omit-frame-pointer',str(path/'test.c'),'-o',str(path/'test')],check=True)
            subprocess.run([str(path/'test')],check=True,capture_output=True)

if __name__=='__main__': unittest.main()
