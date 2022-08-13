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

include(pico_sdk_import.cmake)

project(pico_hsm C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_hsm)

if (NOT DEFINED USB_VID)
    set(USB_VID 0xFEFF)
endif()
add_definitions(-DUSB_VID=${USB_VID})
if (NOT DEFINED USB_PID)
    set(USB_PID 0xFCFD)
endif()
add_definitions(-DUSB_PID=${USB_PID})

find_package( PythonInterp 3.7 REQUIRED )
        
if (NOT EXISTS ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cvcerts.h)
    execute_process(COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/burn-cvcerts.py ${CMAKE_CURRENT_LIST_DIR})
    message("Burning CVCert")
endif()

configure_file(${CMAKE_CURRENT_LIST_DIR}/pico-ccid/config/mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/include/mbedtls COPYONLY)

target_sources(pico_hsm PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/usb/usb.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/usb/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/ccid2040.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/asn1.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng/neug.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/crypto_utils.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/eac.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/sc_hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cvc.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/kek.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/oid.c
        
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/asn1write.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/bignum.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/cmac.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/cipher.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/cipher_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/constant_time.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/ecp.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/ecp_curves.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/hkdf.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/md.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/md5.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/oid.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/platform_util.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/ripemd160.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/rsa.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/rsa_alt_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/sha1.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/sha256.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library/sha512.c
        )

target_include_directories(pico_hsm PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/usb
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/include
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/mbedtls/library
        )

target_compile_options(pico_hsm PUBLIC
    -Wall
    -Werror
)

pico_add_extra_outputs(pico_hsm)

target_link_libraries(pico_hsm PRIVATE pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc tinyusb_device tinyusb_board)

#
#project(flash_nuke C CXX ASM)
#add_executable(flash_nuke nuke.c)
#target_link_libraries(flash_nuke
#        pico_stdlib
#        hardware_flash
#        )
#pico_set_binary_type(flash_nuke no_flash)
#
#pico_add_extra_outputs(flash_nuke)

#project(memory C CXX ASM)
#add_executable(memory memory.c)
#target_link_libraries(memory
#        pico_stdlib
#        hardware_flash
#        )
#pico_set_binary_type(memory no_flash)
#
#pico_add_extra_outputs(memory)
