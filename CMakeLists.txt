 #
 # This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 # Copyright (c) 2022 Pol Henarejos.
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

cmake_minimum_required(VERSION 3.13)

if(ENABLE_EMULATION)
else()
include(pico_sdk_import.cmake)
endif()

project(pico_hsm C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(ENABLE_EMULATION)
else()
pico_sdk_init()
endif()

add_executable(pico_hsm)

set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/sc_hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_select.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_list_keys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_read_binary.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_verify.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_reset_retry.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_challenge.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_external_authenticate.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_mse.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_initialize.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_key_domain.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_key_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_keypair_gen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_update_ef.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_delete_file.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_change_pin.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_key_gen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_signature.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_key_unwrap.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_decrypt_asym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_cipher_sym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_derive_asym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_extras.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_general_authenticate.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_session_pin.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_puk_auth.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_pso.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cmd_bip_slip.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cvc.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/kek.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/oid.c

        )
set(USB_ITF_CCID 1)
include(pico-hsm-sdk/pico_hsm_sdk_import.cmake)

set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm
        )

target_sources(pico_hsm PUBLIC ${SOURCES})
target_include_directories(pico_hsm PUBLIC ${INCLUDES})

target_compile_options(pico_hsm PUBLIC
    -Wall
    -Werror
)

if(ENABLE_EMULATION)

target_compile_options(pico_hsm PUBLIC
        -fdata-sections
        -ffunction-sections
        )
if(APPLE)
target_link_options(pico_hsm PUBLIC
        -Wl,-dead_strip
        )
else()
target_link_options(pico_hsm PUBLIC
        -Wl,--gc-sections
        )
endif (APPLE)
else()
pico_add_extra_outputs(pico_hsm)

target_link_libraries(pico_hsm PRIVATE pico_hsm_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)
endif()
