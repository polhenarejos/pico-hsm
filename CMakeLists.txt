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

set_source_files_properties(
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/ctx.c
        PROPERTIES COMPILE_DEFINITIONS "PACKAGE_VERSION=\"0.22.0\";OPENSC_CONF_PATH=\".\"" 
        )
        

find_package( PythonInterp 3.7 REQUIRED )
        
if (NOT EXISTS ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cvcerts.h)
    execute_process(COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/burn-cvcerts.py ${CMAKE_CURRENT_LIST_DIR})
    message("Burning CVCert")
endif()

target_sources(pico_hsm PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/ccid2040.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/sc_hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/usb/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng/neug.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/files.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/crypto_utils.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/dkek.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid/eac.c
        
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha256.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha512.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/bignum.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/platform_util.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/oid.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/rsa_alt_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/constant_time.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecp_curves.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/asn1write.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hmac_drbg.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/md5.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ripemd160.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/sha1.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cmac.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/cipher_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chachapoly.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/camellia.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/chacha20.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/aria.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/poly1305.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/gcm.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/ccm.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/des.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/nist_kw.c
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/hkdf.c
        
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-prkey.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-algo.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-cert.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-data.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-pin.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-pubkey.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-sec.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-skey.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/asn1.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/log.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/errors.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/sc.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/ctx.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/pkcs15-sc-hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/OpenSC/src/libopensc/padding.c
        )

target_include_directories(pico_hsm PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/fs
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/ccid
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/rng
        ${CMAKE_CURRENT_LIST_DIR}/pico-ccid/src/usb
        ${CMAKE_CURRENT_LIST_DIR}/opensc/src
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
        )
        
pico_add_extra_outputs(pico_hsm)

#target_compile_definitions(pico_hsm PRIVATE MBEDTLS_ECDSA_DETERMINISTIC=1)

target_link_libraries(pico_hsm PRIVATE pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc)

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
