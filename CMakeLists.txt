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
        )

target_include_directories(hsm2040 PUBLIC
        ${CMAKE_CURRENT_LIST_DIR})

pico_add_extra_outputs(hsm2040)
target_link_libraries(hsm2040 PRIVATE pico_stdlib tinyusb_device tinyusb_board)