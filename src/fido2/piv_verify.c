/* Migrate the deployed PIN/DEK on successful verification, without resetting
 * credentials merely because the new upstream envelope is not present yet. */
#define cmd_piv_verify upstream_cmd_piv_verify
#include "../../pico-openpgp/src/piv/cmd_verify.c"
#undef cmd_piv_verify

int cmd_piv_verify(void) {
    file_t *pin = file_search(EF_PIV_PIN);
    if (P1(apdu) == 0 && P2(apdu) == 0x80 && apdu.nc == PIV_PIN_WIRE_SIZE &&
        file_has_data(pin) && (file_get_size(pin) == 33 ||
        (file_has_data(file_search(EF_DEK_PWPIV)) && file_get_data(file_search(EF_DEK_PWPIV))[0] == 2))) {
        has_pwpiv = false;
        return check_pin(pin, apdu.data, apdu.nc);
    }
    return upstream_cmd_piv_verify();
}
