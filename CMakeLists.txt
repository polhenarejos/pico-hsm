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

if(ESP_PLATFORM)
    set(EXTRA_COMPONENT_DIRS src pico-keys-sdk/src)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()
    if(NOT ENABLE_EMULATION)
        set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
        include(pico_sdk_import.cmake)
    endif()

    project(pico_hsm C CXX ASM)

    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)

    if(NOT DEFINED __FOR_CI)
        set(__FOR_CI 0)
    endif()
    if(__FOR_CI)
        add_definitions(-D__FOR_CI)
    endif()

    add_executable(pico_hsm)
endif()
set(USB_ITF_CCID 1)
set(USB_ITF_WCID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)
if(NOT ESP_PLATFORM)
    set(SOURCES ${PICO_KEYS_SOURCES})
endif()
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
)

SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/hsm/version.h" 2)

if(ESP_PLATFORM)
    project(pico_hsm)
endif()

set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/hsm
)
if(NOT ESP_PLATFORM)
    target_sources(pico_hsm PUBLIC ${SOURCES})
    target_include_directories(pico_hsm PUBLIC ${INCLUDES})

    target_compile_options(pico_hsm PUBLIC
        -Wall
    )
    if(NOT MSVC)
        target_compile_options(pico_hsm PUBLIC
            -Werror
        )
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            target_compile_options(pico_hsm PUBLIC
                -fdata-sections
                -ffunction-sections
            )
        endif()
        if(APPLE)
            target_link_options(pico_hsm PUBLIC
                -Wl,-dead_strip
            )
        elseif(MSVC)
            target_compile_options(pico_hsm PUBLIC
                -WX
            )

            target_link_libraries(pico_hsm PUBLIC wsock32 ws2_32 Bcrypt)
        else()
            target_link_options(pico_hsm PUBLIC
                -Wl,--gc-sections
            )
        endif(APPLE)
        target_link_libraries(pico_hsm PRIVATE pthread m)
    else()
        pico_add_extra_outputs(${CMAKE_PROJECT_NAME})
    endif()
endif()
