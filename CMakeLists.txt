cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(hsm2040 C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(hsm2040
  hsm2040.c
)

pico_add_extra_outputs(hsm2040)
target_link_libraries(hsm2040 PRIVATE pico_stdlib hardware_resets hardware_irq)