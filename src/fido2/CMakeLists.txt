idf_build_get_property(selected_board PICOKEYS_BOARD)
set(BOARD_SOURCES)
set(BOARD_REQUIRES)
if(selected_board STREQUAL "tdongle-s3")
    list(APPEND BOARD_SOURCES board_tdongle.c gui/gui_port.c gui/gui_platform_esp.c gui/gui_controller.c gui/gui_screens.c gui/gui_anim.c gui/gui_sprites.c)
    list(APPEND BOARD_REQUIRES esp_driver_spi esp_driver_ledc esp_driver_tsens esp_timer esp_lcd lvgl)
    if(DEFINED CONFIG_ESP_MAIN_TASK_STACK_SIZE AND CONFIG_ESP_MAIN_TASK_STACK_SIZE LESS 8192)
        message(FATAL_ERROR "T-Dongle startup needs CONFIG_ESP_MAIN_TASK_STACK_SIZE >= 8192; update the existing sdkconfig")
    endif()
endif()

idf_component_register(
    SRCS ${BOARD_SOURCES} ${SOURCES}
    INCLUDE_DIRS . ../../pico-fido/src ../../pico-openpgp/src ../../pico-openpgp/src/openpgp ../../pico-openpgp/src/piv gui
    REQUIRES esp_driver_gpio esp_tinyusb mbedtls efuse pico-keys-sdk spi_flash ${BOARD_REQUIRES}
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
