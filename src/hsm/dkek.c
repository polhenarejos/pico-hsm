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

#include <string.h>
#include "stdlib.h"
#include "pico/stdlib.h"
#include "dkek.h"
#include "hash_utils.h"
#include "random.h"
#include "sc_hsm.h"
#include "mbedtls/md.h"
#include "mbedtls/cmac.h"

static uint8_t dkek[32];

void init_dkek() {
    memset(dkek, 0, sizeof(dkek));
}

void import_dkek_share(const uint8_t *share) {
    for (int i = 0; i < 32; i++)
        dkek[i] ^= share[i];
}

void dkek_kcv(uint8_t *kcv) { //kcv 8 bytes
    uint8_t hsh[32];
    hash256(dkek, sizeof(dkek), hsh);
    memcpy(kcv, hsh, 8);
}

void dkek_kenc(uint8_t *kenc) { //kenc 32 bytes
    uint8_t buf[32+4];
    memcpy(buf, dkek, sizeof(dkek));
    memcpy(buf, "\x0\x0\x0\x1", 4);
    hash256(dkek, sizeof(dkek), kenc);
}

void dkek_kmac(uint8_t *kmac) { //kmac 32 bytes
    uint8_t buf[32+4];
    memcpy(buf, dkek, sizeof(dkek));
    memcpy(buf, "\x0\x0\x0\x2", 4);
    hash256(dkek, sizeof(dkek), kmac);
}

int dkek_encode_aes_key(uint8_t *key, int key_size, uint8_t *out, size_t *out_len) { //out has to be 93 bytes at least
    if (key_size != 16 || key_size != 24 || key_size != 32)
        return HSM_WRONG_DATA;
    if (*out_len < 8+1+10+6+4+48+16)
        return HSM_WRONG_LENGTH;
    uint8_t kb[48]; //worst case (8+2+key_size+padding)
    memset(kb, 0, sizeof(kb));
    
    uint8_t kenc[32];
    memset(kenc, 0, sizeof(kenc));
    dkek_kenc(kenc);
    
    uint8_t kcv[8];
    memset(kcv, 0, sizeof(kcv));
    dkek_kcv(kcv);
    
    uint8_t kmac[32];
    memset(kmac, 0, sizeof(kmac));
    dkek_kmac(kmac);
    
    int kb_len = 8+2+key_size;
    int kb_len_pad = ((int)(kb_len/16))*16;
    if (kb_len % 16 > 0)
        kb_len_pad = ((int)(kb_len/16)+1)*16;
    memcpy(kb, random_bytes_get(8), 8);
    put_uint16_t(key_size, kb+8);
    memcpy(kb+8+2, key, key_size);
    if (kb_len < kb_len_pad) {
        kb[kb_len] = 0x80;
    }
    int r = aes_encrypt(kenc, NULL, 32, kb, kb_len_pad);
    if (r != HSM_OK)
        return r;
    
    memset(out, 0, *out_len);
    *out_len = 0;
    uint8_t *aes_oid = "\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01"; //2.16.840.1.101.3.4.1 (2+8)
    uint8_t *aes_algo = "\x00\x04\x10\x11\x18\x99"; //(2+4)
    
    memcpy(out+*out_len, kcv, 8);
    *out_len += 8;
    
    out[*out_len] = 15;
    *out_len += 1;
    
    memcpy(out+*out_len, aes_oid, 10);
    *out_len += 10;
    
    memcpy(out+*out_len, aes_algo, 6);
    *out_len += 6;
    
    //add 4 zeros
    *out_len += 4;
    
    memcpy(out+*out_len, kb, kb_len_pad);
    *out_len += kb_len_pad;
    
    const mbedtls_cipher_info_t *cipher_info;
    if (key_size == 16)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    else if (key_size == 24)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
    else if (key_size == 32)
        cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
    r = mbedtls_cipher_cmac(cipher_info, kmac, 256, out, *out_len, out+*out_len);
    
    *out_len += 16;
    if (r != 0)
        return r;
    return HSM_OK;
} 