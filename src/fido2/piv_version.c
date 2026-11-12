/* FIDO and PIV each export cmd_version; keep both protocol implementations. */
#define cmd_version piv_cmd_version
#include "../../pico-openpgp/src/piv/cmd_version.c"
