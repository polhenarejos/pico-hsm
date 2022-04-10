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

#include "eac.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/cmac.h"

static uint8_t nonce[8];
static uint8_t auth_token[8];
static uint8_t sm_kmac[16];
static uint8_t sm_kenc[16];
static MSE_protocol sm_protocol;

bool is_secured_apdu() {
    return (CLA(apdu) & 0xC);
}

void sm_derive_key(const uint8_t *input, size_t input_len, uint8_t counter, const uint8_t *nonce, size_t nonce_len, uint8_t *out) {
    uint8_t *b = (uint8_t *)calloc(1, input_len+nonce_len+4);
    if (input)
        memcpy(b, input, input_len);
    if (nonce)
        memcpy(b+input_len, nonce, nonce_len);
    b[input_len+nonce_len+3] = counter;
    uint8_t digest[20];
    generic_hash(MBEDTLS_MD_SHA1, b, input_len+nonce_len+4, digest);
    memcpy(out, digest, 16);
    free(b);
}

void sm_derive_all_keys(const uint8_t *derived, size_t derived_len) {
    memcpy(nonce, random_bytes_get(8), 8);
    sm_derive_key(derived, derived_len, 1, nonce, sizeof(nonce), sm_kenc);
    sm_derive_key(derived, derived_len, 2, nonce, sizeof(nonce), sm_kmac);
}

void sm_set_protocol(MSE_protocol proto) {
    sm_protocol = proto;
}

MSE_protocol sm_get_protocol() {
    return sm_protocol;
}

uint8_t *sm_get_nonce() {
    return nonce;
}

int sm_sign(uint8_t *in, size_t in_len, uint8_t *out) {
    return mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB), sm_kmac, 128, in, in_len, out);
}

