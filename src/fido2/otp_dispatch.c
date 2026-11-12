/* Compose the upstream OTP initialization with the T-Dongle board hook. */
#if defined(ESP_PLATFORM) && defined(PICO_BOARD_TDONGLE_S3)
#define picokey_init tdongle_otp_init
#endif
#include "../../pico-fido/src/fido/otp.c"
