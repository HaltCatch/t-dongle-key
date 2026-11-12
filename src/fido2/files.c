/* Combined upstream file tables; preserve OpenPGP/PIV parent indices. */
#include <stdlib.h>
#include "fido/files.h"
#undef _FILES_H_
#undef EF_VAULT_KEY
/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "files.h"

extern const uint8_t openpgp_aid[];
extern const uint8_t openpgp_aid_full[];

extern int parse_ch_data(const file_t *f, int mode);
extern int parse_sec_tpl(const file_t *f, int mode);
extern int parse_ch_cert(const file_t *f, int mode);
extern int parse_gfm(const file_t *f, int mode);
extern int parse_fp(const file_t *f, int mode);
extern int parse_cafp(const file_t *f, int mode);
extern int parse_ts(const file_t *f, int mode);
extern int parse_keyinfo(const file_t *f, int mode);
extern int parse_algoinfo(const file_t *f, int mode);
extern int parse_app_data(const file_t *f, int mode);
extern int parse_discrete_do(const file_t *f, int mode);
extern int parse_pw_status(const file_t *f, int mode);
extern int piv_parse_discovery(const file_t *f);

uint8_t historical_bytes[] = {
    10, 0,
    0x00,
    0x31, 0x84,         /* Full DF name, GET DATA, MF */
    0x73,
    0x80, 0x01, 0xC0,   /* Full DF name */
    /* 1-byte */
    /* Command chaining, No extended Lc and Le */
    0x05,
    0x90, 0x00          /* Status info */
};

uint8_t extended_capabilities[] = {
    10, 0,
    0x7f,           /*
                     * No Secure Messaging supported
                     * GET CHALLENGE supported
                     * Key import supported
                     * PW status byte can be put
                     * private_use_DO
                     * Algorithm attrs are changable
                     * ENC/DEC with AES
                     * KDF-DO available
                     */
    0,        /* Secure Messaging Algorithm: N/A (TDES=0, AES=1) */
    (uint8_t)(OPENPGP_MAX_CHALLENGE_SIZE >> 8), (uint8_t)OPENPGP_MAX_CHALLENGE_SIZE, /* Max size of GET CHALLENGE */
    (uint8_t)(OPENPGP_MAX_DO_SIZE >> 8), (uint8_t)OPENPGP_MAX_DO_SIZE,
    (uint8_t)(OPENPGP_MAX_DO_SIZE >> 8), (uint8_t)OPENPGP_MAX_DO_SIZE,
    0x00, 0x1
};

uint8_t exlen_info[] = {
    8, 0,
    0x2, 0x2, 0x07, 0xf6,
    0x2, 0x2, 0x07, 0xf6,
};

file_entry_t file_entries[] = {
#include "openpgp_file_entries.inc"
    { .fid = EF_KEY_DEV, .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_KEY_DEV_ENC, .parent = 0, .name = NULL,.type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_EE_DEV,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_EE_DEV_EA,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_VAULT_LABEL, .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_COUNTER,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_PIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_AUTHTOKEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_PAUTHTOKEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_MINPINLEN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_PIN_COMPLEXITY_POLICY,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_DEV_STATE,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_OPTS,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_LARGEBLOB,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_OTP_PIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = EF_PIN_ADMIN,  .parent = 0, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE },
    { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_NOT_KNOWN, .data = NULL,
               .ef_structure = 0, .acl = ACL_NONE }
};

enum { OPENPGP_STATIC_FILE_COUNT = sizeof((file_entry_t[]){
#include "openpgp_file_entries.inc"
}) / sizeof(file_entry_t) };

const file_t *MF = &file_entries[0].file;
const file_t *file_openpgp = NULL;
INITIALIZER(combined_file_table_init) {
    for (file_entry_t *entry = file_entries; entry->type != FILE_TYPE_NOT_KNOWN; ++entry) {
        if (entry->name == openpgp_aid) {
            file_openpgp = &entry->file;
            break;
        }
    }
    if (!file_openpgp) abort();
}
const file_entry_t *file_last = &file_entries[sizeof(file_entries) / sizeof(file_entry_t) - 1];

file_t *ef_keydev = NULL;
file_t *ef_certdev = NULL;
file_t *ef_counter = NULL;
file_t *ef_pin = NULL;
file_t *ef_pin_admin = NULL;
file_t *ef_authtoken = NULL;
file_t *ef_keydev_enc = NULL;
file_t *ef_largeblob = NULL;
file_t *ef_vault_key = NULL;

/* The OpenPGP table precedes the FIDO-only entries in this combined table. */
bool tdongle_openpgp_static_file(const file_t *file) {
    for (size_t i = 0; i < OPENPGP_STATIC_FILE_COUNT; ++i)
        if (file == &file_entries[i].file) return true;
    return false;
}
