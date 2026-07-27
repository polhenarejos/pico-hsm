/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _CVC_H_
#define _CVC_H_

#include <stdlib.h>
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#else
#include <stdbool.h>
#endif
#include "mbedtls/ecp.h"
#include "../../pico-keys-sdk/third-party/libcvc/include/cvc.h"

typedef struct PUK {
    const uint8_t *puk;
    uint16_t puk_len;
    const uint8_t *car;
    uint16_t car_len;
    const uint8_t *chr;
    uint16_t chr_len;
    const uint8_t *cvcert;
    uint16_t cvcert_len;
    bool copied;
} PUK;

#define MAX_PUK_STORE_ENTRIES 4

extern uint16_t asn1_cvc_cert(const mbedtls_pk_context *subject, byte_buffer_t output, const_byte_array_t extension, bool full);
extern uint16_t asn1_cvc_aut(const mbedtls_pk_context *subject, byte_buffer_t output, const_byte_array_t extension);
extern uint16_t asn1_build_cert_description(const_byte_array_t label, const_byte_array_t puk, uint16_t fid, byte_buffer_t output);
extern int cvc_verify(const_byte_array_t cert, const_byte_array_t ca);
extern mbedtls_ecp_group_id cvc_inherite_ec_group(const_byte_array_t ca);
extern int puk_verify(const_byte_array_t sig, const_byte_array_t hash, const_byte_array_t ca);
extern uint16_t asn1_build_prkd_ecc(const_byte_array_t label, const_byte_array_t keyid, uint16_t keysize, byte_buffer_t output);
extern uint16_t asn1_build_prkd_rsa(const_byte_array_t label, const_byte_array_t keyid, uint16_t keysize, byte_buffer_t output);
extern uint16_t asn1_build_prkd_aes(const_byte_array_t label, const_byte_array_t keyid, uint16_t keysize, byte_buffer_t output);
extern uint16_t asn1_build_prkd_generic(const_byte_array_t label, const_byte_array_t keyid, uint16_t keysize, int key_type, byte_buffer_t output);
#endif
