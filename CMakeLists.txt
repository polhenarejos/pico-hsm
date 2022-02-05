cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(hsm2040 C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(hsm2040)

target_sources(hsm2040 PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/hsm2040.c
        ${CMAKE_CURRENT_LIST_DIR}/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/openpgp.c
        ${CMAKE_CURRENT_LIST_DIR}/debug.c
        ${CMAKE_CURRENT_LIST_DIR}/openpgp-do.c
        ${CMAKE_CURRENT_LIST_DIR}/ac.c
        ${CMAKE_CURRENT_LIST_DIR}/file.c
        ${CMAKE_CURRENT_LIST_DIR}/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/call-rsa.c
        ${CMAKE_CURRENT_LIST_DIR}/call-ec_p256k1.c
        ${CMAKE_CURRENT_LIST_DIR}/ecc-ed25519.c
        ${CMAKE_CURRENT_LIST_DIR}/ecc-ed448.c
        ${CMAKE_CURRENT_LIST_DIR}/random.c
        ${CMAKE_CURRENT_LIST_DIR}/ecc-mont.c
        ${CMAKE_CURRENT_LIST_DIR}/ecc-x448.c
        ${CMAKE_CURRENT_LIST_DIR}/sha256.c
        ${CMAKE_CURRENT_LIST_DIR}/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/sha512.c
        ${CMAKE_CURRENT_LIST_DIR}/shake256.c
        ${CMAKE_CURRENT_LIST_DIR}/rsa.c
        ${CMAKE_CURRENT_LIST_DIR}/bignum.c
        ${CMAKE_CURRENT_LIST_DIR}/neug.c
        ${CMAKE_CURRENT_LIST_DIR}/ec_p256k1.c
        ${CMAKE_CURRENT_LIST_DIR}/bn.c
        ${CMAKE_CURRENT_LIST_DIR}/mod.c
        ${CMAKE_CURRENT_LIST_DIR}/jpc_p256k1.c
        ${CMAKE_CURRENT_LIST_DIR}/modp256k1.c
        ${CMAKE_CURRENT_LIST_DIR}/p448.c
        ${CMAKE_CURRENT_LIST_DIR}/mod25638.c
        ${CMAKE_CURRENT_LIST_DIR}/platform_util.c
        ${CMAKE_CURRENT_LIST_DIR}/md.c
        ${CMAKE_CURRENT_LIST_DIR}/oid.c
        ${CMAKE_CURRENT_LIST_DIR}/rsa_alt_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/constant_time.c
        )

target_include_directories(hsm2040 PUBLIC
        ${CMAKE_CURRENT_LIST_DIR})

pico_add_extra_outputs(hsm2040)
target_link_libraries(hsm2040 PRIVATE pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc)

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
