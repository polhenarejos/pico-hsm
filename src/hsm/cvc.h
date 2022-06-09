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
#include "pico/stdlib.h"

typedef struct PUK {
    const uint8_t *puk;
    size_t puk_len;
    const uint8_t *car;
    size_t car_len;
    const uint8_t *chr;
    size_t chr_len;
    const uint8_t *cvcert;
    size_t cvcert_len;
    uint8_t up;
} PUK;

#define MAX_PUK_STORE_ENTRIES 4

extern size_t asn1_cvc_cert(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len);
extern size_t asn1_cvc_aut(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len);
extern const uint8_t *cvc_get_field(const uint8_t *data, size_t len, size_t *olen, uint16_t tag);
extern const uint8_t *cvc_get_car(const uint8_t *data, size_t len, size_t *olen);
extern const uint8_t *cvc_get_chr(const uint8_t *data, size_t len, size_t *olen);
extern const uint8_t *cvc_get_pub(const uint8_t *data, size_t len, size_t *olen);
extern int cvc_verify(const uint8_t *cert, size_t cert_len, const uint8_t *ca, size_t ca_len);

#endif
