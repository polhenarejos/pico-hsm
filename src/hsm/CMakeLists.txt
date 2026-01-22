idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    REQUIRES mbedtls efuse pico-keys-sdk
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
