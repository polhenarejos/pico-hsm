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

target_sources(pico_hsm PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm2040.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/sc_hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/src/usb/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/src/rng/neug.c
        
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
        ${CMAKE_CURRENT_LIST_DIR}/src/fs
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm
        ${CMAKE_CURRENT_LIST_DIR}/src/rng
        ${CMAKE_CURRENT_LIST_DIR}/src/usb
        ${CMAKE_CURRENT_LIST_DIR}/opensc/src
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
        ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library
        )

pico_add_extra_outputs(pico_hsm)

#target_compile_definitions(pico_hsm PRIVATE MBEDTLS_ECDSA_DETERMINISTIC=1)

target_link_libraries(pico_hsm PRIVATE pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id)

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
