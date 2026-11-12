 #
 # This file is part of the Pico FIDO2 distribution (https://github.com/polhenarejos/pico-fido2).
 # Copyright (c) 2025 Pol Henarejos.
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, version 3.
 #
 # This program is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program. If not, see <http://www.gnu.org/licenses/>.
 #

cmake_minimum_required(VERSION 3.16)
set(USB_VID "0x2E8A" CACHE STRING "USB vendor ID")
set(USB_PID "0x10FE" CACHE STRING "USB product ID")
set(VIDPID "None" CACHE STRING "USB identity profile")
set(PICO_FIDO_ESP_BOARD "generic" CACHE STRING "ESP32 board support package")
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
set(PICOKEYS_COMPONENTS fido2)
if(ENABLE_EMULATION OR PICO_FIDO_ESP_BOARD STREQUAL "tdongle-s3")
    option(ENABLE_EDDSA "Enable EdDSA support" ON)
endif()
if(ESP_PLATFORM)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()
    if(NOT ENABLE_EMULATION)
        include(pico_sdk_import.cmake)
    endif()
    project(pico_fido2 C CXX ASM)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)
    add_executable(pico_fido2)
endif()
include(pico-keys-sdk/cmake/options.cmake)
option(ENABLE_POWER_ON_RESET "Require power cycle for reset" ON)
option(ENABLE_OATH_APP "Enable OATH" ON)
option(ENABLE_OTP_APP "Enable OTP" ON)
option(ENABLE_ADMINLESS_MODE "Gnuk-compatible admin-less PIN mode" ON)
foreach(option ENABLE_POWER_ON_RESET ENABLE_OATH_APP ENABLE_OTP_APP ENABLE_ADMINLESS_MODE)
    if(${option})
        add_compile_definitions(${option}=1)
    endif()
endforeach()
set(USB_ITF_HID 1)
set(USB_ITF_CCID 1)
set(USB_ITF_WCID 1)
set(ENABLE_LIBCVC 1)
# Desktop tests use an explicitly isolated software OTP backend, never the host TPM.
set(PICOKEYS_EMULATION_SOFTWARE_OTP ON)
include(pico-keys-sdk/picokeys_sdk_import.cmake)
if(PICO_RP2350 AND PICOKEYS_RP2350_OTP_WRITES)
    message(FATAL_ERROR "This project forbids irreversible RP2350 OTP writes; configure PICOKEYS_RP2350_OTP_WRITES=OFF")
endif()
if(ESP_PLATFORM AND PICOKEYS_ESP32_EFUSE_WRITES)
    message(FATAL_ERROR "This project forbids irreversible ESP32 eFuse writes; configure PICOKEYS_ESP32_EFUSE_WRITES=OFF")
endif()
# Keep the USB rescue build number independent of Git history.
set(TDONGLE_BUILD_NUMBER 130)
message(STATUS "Build number: ${TDONGLE_BUILD_NUMBER}")
add_compile_definitions(PICO_BUILD_NUMBER=${TDONGLE_BUILD_NUMBER} TDONGLE_SPLIT_OPENPGP_STORAGE=1)
if(ESP_PLATFORM AND PICO_FIDO_ESP_BOARD STREQUAL "tdongle-s3")
    add_compile_definitions(PICO_BOARD_TDONGLE_S3=1)
endif()
set(SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/files.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/fido.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/object_authorization.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/object_provider.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/resident_container.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_register.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_authenticate.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_get_info.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_make_credential.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/event.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/known_apps.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_client_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/credential.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_get_assertion.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_selection.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_cred_mgmt.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_config.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_vendor.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/fido_vault.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/cbor_large_blobs.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/management.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/defs.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/oath_container.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/otp_container.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/openpgp_compat.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/object_provider.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/openpgp_storage.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/openpgp_vault.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/piv_dispatch.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/piv_version.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_select.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_get_serial.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/piv_verify.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_get_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_get_metadata.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_authenticate.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_asym_keygen.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_put_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_set_mgmkey.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_move_key.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_change_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_reset_retry.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_set_retries.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_attestation.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv/cmd_import_asym.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_select.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_get_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_verify.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_put_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_select_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_import_data.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_version.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_change_pin.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_mse.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_internal_aut.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_challenge.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_activate_file.c
    ${CMAKE_CURRENT_LIST_DIR}/src/fido2/openpgp_reset.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_pso.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_keypair_gen.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/cmd_reset_retry.c
    ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp/do.c
)
if(ENABLE_OATH_APP)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/oath.c)
endif()
if(ENABLE_OTP_APP)
    list(APPEND SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/fido2/otp_dispatch.c)
endif()
SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/pico-fido/src/fido/version.h")
if(ESP_PLATFORM)
    # IDF expands component requirements in a separate CMake process.
    idf_build_set_property(PICOKEYS_BOARD "${PICO_FIDO_ESP_BOARD}")
    project(pico_fido2)
    # Neopixel 1.0.10 declares the legacy driver umbrella. IDF 6 no longer
    # exports the I2S driver through it.
    idf_component_get_property(neopixel_lib zorxx__neopixel COMPONENT_LIB)
    target_link_libraries(${neopixel_lib} PRIVATE idf::esp_driver_i2s)
else()
    target_sources(pico_fido2 PRIVATE ${SOURCES})
    target_include_directories(pico_fido2 PRIVATE
        ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/pico-fido/src
        ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src
        ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/openpgp
        ${CMAKE_CURRENT_LIST_DIR}/pico-openpgp/src/piv)
    target_compile_options(pico_fido2 PRIVATE -Wall -Werror)
    if(ENABLE_EMULATION)
        target_link_libraries(pico_fido2 PRIVATE picokeys_sdk mbedtls pthread m)
        option(ENABLE_DESKTOP_GUI "Build the shared device GUI with SDL" ON)
        if(ENABLE_DESKTOP_GUI)
            enable_testing()
            add_subdirectory(desktop)
        endif()
    else()
        target_link_libraries(pico_fido2 PRIVATE picokeys_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id pico_aon_timer tinyusb_device tinyusb_board)
        if(PICO_RP2350)
            if(NOT COMMAND pico_set_linker_script_var)
                message(FATAL_ERROR "RP2350 builds require Pico SDK 2.3 or newer for the reserved startup stack")
            endif()
            # The ROM partition scan alone uses 4 KiB. Reserve a real 16 KiB
            # core-0 stack outside the heap, using the SDK's linker variables.
            # Core 1 uses the SDK wrapper's separately allocated worker stack.
            pico_set_linker_script_var(pico_fido2 RAM_LENGTH "496k")
            pico_set_linker_script_var(pico_fido2 SCRATCH_Y_ORIGIN "0x2007c000")
            pico_set_linker_script_var(pico_fido2 SCRATCH_Y_LENGTH "16k")
            target_compile_definitions(pico_fido2 PRIVATE
                PICO_STACK_SIZE=16384 PICO_CORE1_STACK_SIZE=0 PICO_USE_STACK_GUARDS=1)
        endif()
        pico_add_extra_outputs(pico_fido2)
    endif()
endif()
