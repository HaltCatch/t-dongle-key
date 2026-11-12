/* Keep the upstream OpenPGP record identifiers used in authenticated data.
 * The combined firmware assigns their physical files a separate FID range. */
#include "picokeys.h"
#include "object_container_store.h"
#include "openpgp/key_container.h"
#include "openpgp/object_provider.h"

#define OPENPGP_LEGACY_FIRST_FID 0xd000u
#define OPENPGP_LEGACY_LAST_FID  0xd5ffu
#define OPENPGP_STORAGE_DELTA   0x2000u
#define STORAGE_COMMIT_TIMEOUT_MS 5000u

uint16_t picokey_object_storage_fid(uint16_t namespace_id, uint16_t fid) {
    if (namespace_id == OPENPGP_OBJECT_NAMESPACE &&
        fid >= OPENPGP_LEGACY_FIRST_FID && fid <= OPENPGP_LEGACY_LAST_FID) {
        return fid + OPENPGP_STORAGE_DELTA;
    }
    return fid;
}

static file_t *openpgp_storage_search(uint16_t fid) {
    return file_search(picokey_object_storage_fid(OPENPGP_OBJECT_NAMESPACE, fid));
}

#define file_search openpgp_storage_search
#define openpgp_key_container_physical_fid openpgp_key_container_logical_fid
#include "../../pico-openpgp/src/openpgp/key_container.c"
#undef openpgp_key_container_physical_fid
#undef file_search

bool openpgp_key_container_physical_fid(uint16_t fid) {
    if (fid < OPENPGP_LEGACY_FIRST_FID + OPENPGP_STORAGE_DELTA ||
        fid > OPENPGP_LEGACY_LAST_FID + OPENPGP_STORAGE_DELTA) {
        return false;
    }
    return openpgp_key_container_logical_fid(fid - OPENPGP_STORAGE_DELTA);
}

static int copy_legacy_file(uint16_t fid, const_byte_array_t bytes) {
    uint16_t destination = picokey_object_storage_fid(OPENPGP_OBJECT_NAMESPACE, fid);
    file_t *target = file_search(destination);
    /* Flash reads may refer to a reusable cache page. */
    uint8_t *copy = malloc(bytes.len);
    if (!copy) return PICOKEYS_ERR_NO_MEMORY;
    memcpy(copy, bytes.data, bytes.len);
    if (file_has_data(target)) {
        bool identical = file_get_size(target) == bytes.len &&
                         memcmp(file_get_data(target), copy, bytes.len) == 0;
        free(copy);
        return identical ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
    }
    if (!target) target = file_new(destination);
    int status = target ? file_put_data(target, CONST_BYTE_ARRAY(copy, bytes.len)) : PICOKEYS_ERR_NO_MEMORY;
    if (status == PICOKEYS_OK && (!flash_commit_sync(STORAGE_COMMIT_TIMEOUT_MS) ||
        file_get_size(target) != bytes.len || memcmp(file_get_data(target), copy, bytes.len) != 0)) {
        status = PICOKEYS_ERR_MEMORY_FATAL;
    }
    free(copy); // Manifest and records are authenticated or already encrypted.
    return status;
}

static int move_legacy_container(uint16_t fid, uint8_t slot, bool cleanup) {
    uint16_t manifest_fid = openpgp_key_manifest_fid(fid, slot);
    file_t *legacy = file_search(manifest_fid);
    if (!file_has_data(legacy) || file_get_size(legacy) < FILE_OBJECT_MANIFEST_HEADER_SIZE ||
        memcmp(file_get_data(legacy), "PKOC", 4) != 0) return PICOKEYS_OK;

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) return PICOKEYS_EXEC_ERROR;
    file_object_manifest_t manifest;
    int status = file_object_manifest_parse(
        CONST_BYTE_ARRAY(file_get_data(legacy), file_get_size(legacy)),
        crypto.auth, NULL, NULL, &manifest);
    /* The legacy range also contains FIDO files. Ownership is established by
     * the OpenPGP manifest authenticator before copying or removing anything. */
    if (status == PICOKEYS_WRONG_DATA || status == PICOKEYS_WRONG_SIGNATURE) return PICOKEYS_OK;
    if (status != PICOKEYS_OK) return status;
    if (manifest.namespace_id != OPENPGP_OBJECT_NAMESPACE ||
        manifest.container_kind != OPENPGP_KEY_CONTAINER_KIND ||
        manifest.container_id != fid) return PICOKEYS_WRONG_DATA;

    for (uint16_t i = 0; i < manifest.object_count; i++) {
        const file_object_descriptor_t *object = &manifest.objects[i];
        if (!openpgp_key_layout_descriptor_valid(NULL, fid, object)) return PICOKEYS_WRONG_DATA;
        uint16_t record_fid = (uint16_t)object->record_id;
        file_t *record = file_search(record_fid);
        file_t *destination = openpgp_storage_search(record_fid);
        file_object_record_info_t header;
        if (file_has_data(record)) {
            const_byte_array_t bytes = CONST_BYTE_ARRAY(file_get_data(record), file_get_size(record));
            status = file_object_record_header_parse(bytes, object, &header);
            if (status == PICOKEYS_OK) {
                status = copy_legacy_file(record_fid, bytes);
                if (status != PICOKEYS_OK) return status;
                if (cleanup) {
                    status = file_delete_no_commit(record);
                    if (status != PICOKEYS_OK) return status;
                }
                continue;
            }
        }
        /* Recovery after power loss during cleanup: the new file may already
         * be the only copy, or the old FID may now belong to FIDO. */
        if (!file_has_data(destination)) return PICOKEYS_WRONG_DATA;
        status = file_object_record_header_parse(
            CONST_BYTE_ARRAY(file_get_data(destination), file_get_size(destination)),
            object, &header);
        if (status != PICOKEYS_OK) return status;
    }
    /* Copy all generations before deleting any source. Keep the old manifest
     * until last so a restart can finish cleanup using the same descriptors. */
    status = copy_legacy_file(manifest_fid,
        CONST_BYTE_ARRAY(file_get_data(legacy), file_get_size(legacy)));
    if (status != PICOKEYS_OK || !cleanup) return status;
    status = file_delete_no_commit(legacy);
    if (status != PICOKEYS_OK) return status;
    return flash_commit_sync(STORAGE_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

int picokey_prepare_storage(void) {
    for (unsigned pass = 0; pass < 2; pass++) {
        for (unsigned low = 0; low <= UINT8_MAX; low++) {
            uint16_t fid = low;
            if (low >= (EF_PK_SIG & UINT8_MAX) && low <= (EF_PK_AUT & UINT8_MAX)) fid |= 0x1000u;
            if (!openpgp_key_container_supported(fid)) continue;
            for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
                int status = move_legacy_container(fid, slot, pass != 0);
                if (status != PICOKEYS_OK) return status;
            }
        }
    }
    return PICOKEYS_OK;
}
