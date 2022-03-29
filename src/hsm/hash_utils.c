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

#include <pico/unique_id.h>
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "hash_utils.h"
#include "sc_hsm.h"

void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]) {
    uint8_t o1[32];
    hash_multi(pin, len, o1);
    for (int i = 0; i < sizeof(o1); i++)
        o1[i] ^= pin[i%len];
    hash_multi(o1, sizeof(o1), output);
}

void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int iters = 256;
    pico_unique_board_id_t unique_id;
    
    pico_get_unique_board_id(&unique_id);
    
    mbedtls_sha256_starts (&ctx, 0);
    mbedtls_sha256_update (&ctx, unique_id.id, sizeof(unique_id.id));
    
    while (iters > len)
    {
        mbedtls_sha256_update (&ctx, input, len);
        iters -= len;
    }
    if (iters > 0) // remaining iterations
        mbedtls_sha256_update (&ctx, input, iters);
    mbedtls_sha256_finish (&ctx, output);
    mbedtls_sha256_free (&ctx);
}

void hash256(const uint8_t *input, size_t len, uint8_t output[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    
    mbedtls_sha256_starts (&ctx, 0);
    mbedtls_sha256_update (&ctx, input, len);

    mbedtls_sha256_finish (&ctx, output);
    mbedtls_sha256_free (&ctx);
}

void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md);
    mbedtls_md_setup(&ctx, md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, input, len);
    mbedtls_md_finish(&ctx, output);
    mbedtls_md_free(&ctx);   
}

int aes_encrypt(const uint8_t *key, const uint8_t *iv, int key_size, uint8_t *data, int len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t tmp_iv[IV_SIZE];
    memset(tmp_iv, 0, IV_SIZE);
    if (iv)
        memcpy(tmp_iv, iv, IV_SIZE);
    int r = mbedtls_aes_setkey_enc(&aes, key, key_size);
    if (r != 0)
        return HSM_EXEC_ERROR;
    return mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, tmp_iv, data, data);
}

int aes_decrypt(const uint8_t *key, const uint8_t *iv, int key_size, uint8_t *data, int len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    uint8_t tmp_iv[IV_SIZE];
    memset(tmp_iv, 0, IV_SIZE);
    if (iv)
        memcpy(tmp_iv, iv, IV_SIZE);
    int r = mbedtls_aes_setkey_dec(&aes, key, key_size);
    if (r != 0)
        return HSM_EXEC_ERROR;
    return mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, tmp_iv, data, data);
}