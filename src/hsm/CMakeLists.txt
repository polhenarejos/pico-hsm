set(HSM_REQUIRES
    mbedtls
    efuse
    pico-keys-sdk
)

if(ENABLE_PQC)
    list(APPEND HSM_REQUIRES
        mlkem512
        mlkem768
        mlkem1024
    )
endif()

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    REQUIRES ${HSM_REQUIRES}
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
