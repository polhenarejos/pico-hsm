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

#ifndef _HASH_UTILS_H_
#define _HASH_UTILS_H_

#include "stdlib.h"
#include "pico/stdlib.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define HSM_KEY_RSA                 0x1
#define HSM_KEY_EC                  0x10
#define HSM_KEY_AES                 0x100
#define HSM_KEY_AES_128             0x300
#define HSM_KEY_AES_192             0x500
#define HSM_KEY_AES_256             0x900

#define HSM_AES_MODE_CBC            1
#define HSM_AES_MODE_CFB            2

extern void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]);
extern void hash256(const uint8_t *input, size_t len, uint8_t output[32]);
extern void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output);
extern int aes_encrypt(const uint8_t *key, const uint8_t *iv, int key_size, int mode, uint8_t *data, int len);
extern int aes_decrypt(const uint8_t *key, const uint8_t *iv, int key_size, int mode, uint8_t *data, int len);
extern int aes_encrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len);
extern int aes_decrypt_cfb_256(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len);
extern mbedtls_ecp_group_id ec_get_curve_from_prime(const uint8_t *prime, size_t prime_len);

#endif
