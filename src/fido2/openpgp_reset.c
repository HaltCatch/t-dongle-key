/* Upstream's OpenPGP-only reset sweeps its whole file table. In the combined
 * firmware, restrict that sweep to the OpenPGP/PIV portion of the table and
 * to OpenPGP key containers. Upstream still applies its PIV preservation rules. */
#include "picokeys.h"
#include "openpgp/key_container.h"

extern bool tdongle_openpgp_static_file(const file_t *file);

static file_delete_result_t delete_openpgp_file(file_t *file) {
    if (tdongle_openpgp_static_file(file) || openpgp_key_container_physical_fid(file->fid))
        return file_delete_no_commit_parts(file);
    return (file_delete_result_t){.value = PICOKEYS_OK, .metadata = PICOKEYS_OK};
}

#define file_delete_no_commit_parts delete_openpgp_file
#include "../../pico-openpgp/src/openpgp/cmd_terminate_df.c"
