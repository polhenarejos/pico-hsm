/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CVC_H_
#define _CVC_H_

#include <stdlib.h>
#ifndef ENABLE_EMULATION
#include "pico/stdlib.h"
#else
#include <stdbool.h>
#endif
#include "mbedtls/ecp.h"

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

extern uint16_t asn1_cvc_cert(void *rsa_ecdsa,
                            uint8_t key_type,
                            uint8_t *buf,
                            uint16_t buf_len,
                            const uint8_t *ext,
                            uint16_t ext_len,
                            bool full);
extern uint16_t asn1_cvc_aut(void *rsa_ecdsa,
                           uint8_t key_type,
                           uint8_t *buf,
                           uint16_t buf_len,
                           const uint8_t *ext,
                           uint16_t ext_len);
extern uint16_t asn1_build_cert_description(const uint8_t *label,
                                          uint16_t label_len,
                                          const uint8_t *puk,
                                          uint16_t puk_len,
                                          uint16_t fid,
                                          uint8_t *buf,
                                          uint16_t buf_len);
extern const uint8_t *cvc_get_field(const uint8_t *data, uint16_t len, uint16_t *olen, uint16_t tag);
extern const uint8_t *cvc_get_car(const uint8_t *data, uint16_t len, uint16_t *olen);
extern const uint8_t *cvc_get_chr(const uint8_t *data, uint16_t len, uint16_t *olen);
extern const uint8_t *cvc_get_pub(const uint8_t *data, uint16_t len, uint16_t *olen);
extern const uint8_t *cvc_get_ext(const uint8_t *data, uint16_t len, uint16_t *olen);
extern int cvc_verify(const uint8_t *cert, uint16_t cert_len, const uint8_t *ca, uint16_t ca_len);
extern mbedtls_ecp_group_id cvc_inherite_ec_group(const uint8_t *ca, uint16_t ca_len);
extern int puk_verify(const uint8_t *sig,
                      uint16_t sig_len,
                      const uint8_t *hash,
                      uint16_t hash_len,
                      const uint8_t *ca,
                      uint16_t ca_len);
extern uint16_t asn1_build_prkd_ecc(const uint8_t *label,
                                  uint16_t label_len,
                                  const uint8_t *keyid,
                                  uint16_t keyid_len,
                                  uint16_t keysize,
                                  uint8_t *buf,
                                  uint16_t buf_len);
extern uint16_t asn1_build_prkd_rsa(const uint8_t *label,
                                  uint16_t label_len,
                                  const uint8_t *keyid,
                                  uint16_t keyid_len,
                                  uint16_t keysize,
                                  uint8_t *buf,
                                  uint16_t buf_len);
extern uint16_t asn1_build_prkd_aes(const uint8_t *label,
                                  uint16_t label_len,
                                  const uint8_t *keyid,
                                  uint16_t keyid_len,
                                  uint16_t keysize,
                                  uint8_t *buf,
                                  uint16_t buf_len);
extern uint16_t asn1_build_prkd_generic(const uint8_t *label,
                                  uint16_t label_len,
                                  const uint8_t *keyid,
                                  uint16_t keyid_len,
                                  uint16_t keysize,
                                  int key_tpe,
                                  uint8_t *buf,
                                  uint16_t buf_len);
#endif
