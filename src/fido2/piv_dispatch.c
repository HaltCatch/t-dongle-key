/* Preserve a deployed PIV PIN and management key when the old shared DEK
 * exists. Upstream otherwise treats a missing new envelope as provisioning. */
#include "../../pico-openpgp/src/piv/piv.h"
static bool tdongle_piv_has_data(const file_t *file) {
    if (file && file->fid == EF_DEK_PWPIV && file_has_data(file_search(EF_PIV_PIN)))
        return true;
    return file_has_data(file);
}
#define file_has_data tdongle_piv_has_data
int piv_cmd_version(void);
#define cmd_version piv_cmd_version
#include "../../pico-openpgp/src/openpgp/piv.c"
