/* Adapt deployed CDRL key storage without modifying the public upstream tree. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "../../pico-openpgp/src/openpgp/openpgp.h"

static int tdongle_legacy_dek_decrypt(const uint8_t *key, const uint8_t *iv, byte_array_t data);
#define aes_decrypt_cfb_256 tdongle_legacy_dek_decrypt
#define check_pin upstream_check_pin
#include "../../pico-openpgp/src/openpgp/openpgp.c"
#undef check_pin
#undef aes_decrypt_cfb_256

static int tdongle_legacy_dek_decrypt(const uint8_t *key, const uint8_t *iv, byte_array_t data) {
    int result = aes_decrypt_cfb_256(key, iv, data);
    /* Deployed CDRL firmware XORs the unwrapped raw DEK with OTP key 1.
     * GCM envelopes contain the final key; only legacy CFB loading needs this. */
    if (result == PICOKEYS_OK && data.data == dek + IV_SIZE && data.len == 32 && otp_key_1)
        for (size_t i = 0; i < 32; ++i) data.data[i] ^= otp_key_1[i];
    return result;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    int status = upstream_check_pin(pin, data, len);
    if (status != 0x9000) return status;
    uint16_t fid = pin->fid == EF_PW1 ? EF_DEK_PW1 :
                   pin->fid == EF_PW3 ? EF_DEK_PW3 :
                   pin->fid == EF_PIV_PIN ? EF_DEK_PWPIV :
                   pin->fid == EF_RC ? EF_DEK_RC : 0;
    file_t *envelope = fid ? file_search(fid) : NULL;
    if (!file_has_data(envelope) || file_get_data(envelope)[0] != 2)
        return status;
    if (file_get_size(envelope) != DEK_FILE_SIZE) return SW_EXEC_ERROR();
    /* Rewrap a KDF v1 envelope only after successful PIN verification and
     * authenticated decryption; format 3 uses the current KDF. */
    uint8_t session[32], plaintext[DEK_SIZE], replacement[DEK_FILE_SIZE];
    pin_derive_session(CONST_BYTE_ARRAY(data, len), session);
    int result = decrypt_with_aad(session,
        CONST_BYTE_ARRAY(file_get_data(envelope) + 1, DEK_AAD_SIZE), PIN_KDF_V1, plaintext);
    replacement[0] = 3;
    if (result == PICOKEYS_OK)
        result = encrypt_with_aad(session, CONST_BYTE_ARRAY(plaintext, sizeof(plaintext)),
                                  PIN_KDF_DEFAULT_VERSION, replacement + 1);
    if (result == PICOKEYS_OK)
        result = file_put_data(envelope, CONST_BYTE_ARRAY(replacement, sizeof(replacement)));
    mbedtls_platform_zeroize(session, sizeof(session));
    mbedtls_platform_zeroize(plaintext, sizeof(plaintext));
    mbedtls_platform_zeroize(replacement, sizeof(replacement));
    if (result != PICOKEYS_OK) {
        has_pw1 = has_pw2 = has_pw3 = has_pwpiv = has_rc = false;
        isUserAuthenticated = false;
        return SW_EXEC_ERROR();
    }
    flash_commit();
    return status;
}

/* The combined device reports one firmware release across its applications.
 * Reporting the standalone OpenPGP module's 5.2 version triggers a Yubico
 * client workaround for a commercial 5.2-5.6 algorithm-table defect. */
void openpgp_app_version(uint8_t version[3]) {
    extern uint8_t (*get_version_major)(void);
    extern uint8_t (*get_version_minor)(void);
    if (get_version_major && get_version_minor) {
        version[0] = get_version_major();
        version[1] = get_version_minor();
        version[2] = 0;
    }
}
