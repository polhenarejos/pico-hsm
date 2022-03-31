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
#include "common.h"
#include "stdlib.h"
#include "pico/stdlib.h"
#include "dkek.h"
#include "crypto_utils.h"
#include "random.h"
#include "sc_hsm.h"
#include "mbedtls/md.h"
#include "mbedtls/cmac.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"

static uint8_t dkek[IV_SIZE+32];
static uint8_t tmp_dkek[32];
extern bool has_session_pin;
extern uint8_t session_pin[32];

int load_dkek() {
    if (has_session_pin == false)
        return HSM_NO_LOGIN;
    file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
    if (!tf)
        return HSM_ERR_FILE_NOT_FOUND;
    memcpy(dkek, file_read(tf->data+sizeof(uint16_t)), IV_SIZE+32);
    int ret = aes_decrypt_cfb_256(session_pin, dkek, dkek+IV_SIZE, 32);
    if (ret != 0)
        return HSM_EXEC_ERROR;
    return HSM_OK;
}

void release_dkek() {
    memset(dkek, 0, sizeof(dkek));
}

void init_dkek() {
    release_dkek();
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
}

int store_dkek_key() {
    aes_encrypt_cfb_256(session_pin, dkek, dkek+IV_SIZE, 32);
    file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
    if (!tf)
        return HSM_ERR_FILE_NOT_FOUND;
    flash_write_data_to_file(tf, dkek, sizeof(dkek));
    low_flash_available();
    release_dkek();
    return HSM_OK;
}

int save_dkek_key(const uint8_t *key) {
    const uint8_t *iv = random_bytes_get(32);
    memcpy(dkek, iv, IV_SIZE);
    if (!key)
        key = tmp_dkek;
    memcpy(dkek+IV_SIZE, key, 32);
    return store_dkek_key();
}

void import_dkek_share(const uint8_t *share) {
    for (int i = 0; i < 32; i++)
        tmp_dkek[i] ^= share[i];
}

int dkek_kcv(uint8_t *kcv) { //kcv 8 bytes
    uint8_t hsh[32];
    int r = load_dkek();
    if (r != HSM_OK)
        return r;
    hash256(dkek+IV_SIZE, 32, hsh);
    release_dkek();
    memcpy(kcv, hsh, 8);
    return HSM_OK;
}

int dkek_kenc(uint8_t *kenc) { //kenc 32 bytes
    uint8_t buf[32+4];
    int r = load_dkek();
    if (r != HSM_OK)
        return r;
    memcpy(buf, dkek+IV_SIZE, 32);
    release_dkek();
    memcpy(buf+32, "\x0\x0\x0\x1", 4);
    hash256(buf, sizeof(buf), kenc);
    memset(buf, 0, sizeof(buf));
    return HSM_OK;
}

int dkek_kmac(uint8_t *kmac) { //kmac 32 bytes
    uint8_t buf[32+4];
    int r = load_dkek();
    if (r != HSM_OK)
        return r;
    memcpy(buf, dkek+IV_SIZE, 32);
    release_dkek();
    memcpy(buf+32, "\x0\x0\x0\x2", 4);
    hash256(buf, sizeof(buf), kmac);
    memset(buf, 0, sizeof(buf));
    return HSM_OK;
}

int dkek_encrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dkek()) != HSM_OK)
        return r;
    r = aes_encrypt_cfb_256(dkek+IV_SIZE, dkek, data, len);
    release_dkek();
    return r;
}

int dkek_decrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dkek()) != HSM_OK)
        return r;
    r = aes_decrypt_cfb_256(dkek+IV_SIZE, dkek, data, len);
    release_dkek();
    return r;
}

int dkek_encode_key(void *key_ctx, int key_type, uint8_t *out, size_t *out_len) {
    if (!(key_type & HSM_KEY_RSA) && !(key_type & HSM_KEY_EC) && !(key_type & HSM_KEY_AES))
        return HSM_WRONG_DATA;
        
    uint8_t kb[8+2*4+2*4096/8+3+13]; //worst case: RSA-4096  (plus, 13 bytes padding)
    memset(kb, 0, sizeof(kb));
    int kb_len = 0;
    uint8_t *algo = NULL;
    uint8_t algo_len = 0;
    uint8_t *allowed = NULL;
    uint8_t allowed_len = 0;
    uint8_t kenc[32];
    memset(kenc, 0, sizeof(kenc));
    dkek_kenc(kenc);
    
    uint8_t kcv[8];
    memset(kcv, 0, sizeof(kcv));
    dkek_kcv(kcv);
    
    uint8_t kmac[32];
    memset(kmac, 0, sizeof(kmac));
    dkek_kmac(kmac);
    
    if (key_type & HSM_KEY_AES) {
        if (key_type & HSM_KEY_AES_128)
            kb_len = 16;
        else if (key_type & HSM_KEY_AES_192)
            kb_len = 24;
        else if (key_type & HSM_KEY_AES_256)
            kb_len = 32;
            
        if (kb_len != 16 && kb_len != 24 && kb_len != 32)
            return HSM_WRONG_DATA;
        if (*out_len < 8+1+10+6+4+(2+32+14)+16)
            return HSM_WRONG_LENGTH;
        
        put_uint16_t(kb_len, kb+8);
        memcpy(kb+10, key_ctx, kb_len);
        kb_len += 2;
        
        algo = "\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01"; //2.16.840.1.101.3.4.1 (2+8)
        algo_len = 10;
        allowed = "\x00\x04\x10\x11\x18\x99"; //(2+4)
        allowed_len = 6;
    }
    else if (key_type & HSM_KEY_RSA) {
        if (*out_len < 8+1+12+6+(8+2*4+2*4096/8+3+13)+16) //13 bytes pading 
            return HSM_WRONG_LENGTH;
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)key_ctx;
        kb_len = 0;
        put_uint16_t(mbedtls_rsa_get_len(rsa)*8, kb+8+kb_len); kb_len += 2;
        
        put_uint16_t(mbedtls_mpi_size(&rsa->D), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&rsa->D, kb+8+kb_len, mbedtls_mpi_size(&rsa->D)); kb_len += mbedtls_mpi_size(&rsa->D);
        put_uint16_t(mbedtls_mpi_size(&rsa->N), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&rsa->N, kb+8+kb_len, mbedtls_mpi_size(&rsa->N)); kb_len += mbedtls_mpi_size(&rsa->N);
        put_uint16_t(mbedtls_mpi_size(&rsa->E), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&rsa->E, kb+8+kb_len, mbedtls_mpi_size(&rsa->E)); kb_len += mbedtls_mpi_size(&rsa->E);
        
        algo = "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02";
        algo_len = 12;
    }
    else if (key_type & HSM_KEY_EC) {
        if (*out_len < 8+1+12+6+(8+2*8+9*66+2+4)+16) //4 bytes pading 
            return HSM_WRONG_LENGTH;
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *)key_ctx;
        kb_len = 0;
        put_uint16_t(mbedtls_mpi_size(&ecdsa->grp.P)*8, kb+8+kb_len); kb_len += 2;
        put_uint16_t(mbedtls_mpi_size(&ecdsa->grp.A), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&ecdsa->grp.A, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.A)); kb_len += mbedtls_mpi_size(&ecdsa->grp.A);
        put_uint16_t(mbedtls_mpi_size(&ecdsa->grp.B), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&ecdsa->grp.B, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.B)); kb_len += mbedtls_mpi_size(&ecdsa->grp.B);
        put_uint16_t(mbedtls_mpi_size(&ecdsa->grp.P), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&ecdsa->grp.P, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.P)); kb_len += mbedtls_mpi_size(&ecdsa->grp.P);
        put_uint16_t(mbedtls_mpi_size(&ecdsa->grp.N), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&ecdsa->grp.N, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.N)); kb_len += mbedtls_mpi_size(&ecdsa->grp.N);
        put_uint16_t(1+mbedtls_mpi_size(&ecdsa->grp.G.X)+mbedtls_mpi_size(&ecdsa->grp.G.Y), kb+8+kb_len); kb_len += 2;
        kb[8+kb_len++] = 0x4;
        mbedtls_mpi_write_binary(&ecdsa->grp.G.X, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.G.X)); kb_len += mbedtls_mpi_size(&ecdsa->grp.G.X);
        mbedtls_mpi_write_binary(&ecdsa->grp.G.Y, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->grp.G.Y)); kb_len += mbedtls_mpi_size(&ecdsa->grp.G.Y);
        put_uint16_t(mbedtls_mpi_size(&ecdsa->d), kb+8+kb_len); kb_len += 2;
        mbedtls_mpi_write_binary(&ecdsa->d, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->d)); kb_len += mbedtls_mpi_size(&ecdsa->d);
        put_uint16_t(1+mbedtls_mpi_size(&ecdsa->Q.X)+mbedtls_mpi_size(&ecdsa->Q.Y), kb+8+kb_len); kb_len += 2;
        kb[8+kb_len++] = 0x4;
        mbedtls_mpi_write_binary(&ecdsa->Q.X, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->Q.X)); kb_len += mbedtls_mpi_size(&ecdsa->Q.X);
        mbedtls_mpi_write_binary(&ecdsa->Q.Y, kb+8+kb_len, mbedtls_mpi_size(&ecdsa->Q.Y)); kb_len += mbedtls_mpi_size(&ecdsa->Q.Y);
        
        algo = "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03";
        algo_len = 12;
    }
    memset(out, 0, *out_len);
    *out_len = 0;
    
    memcpy(out+*out_len, kcv, 8);
    *out_len += 8;
    
    if (key_type & HSM_KEY_AES)
        out[*out_len] = 15;
    else if (key_type & HSM_KEY_RSA)
        out[*out_len] = 5;
    else if (key_type & HSM_KEY_EC)
        out[*out_len] = 12;
    *out_len += 1;
    
    if (algo) {
        memcpy(out+*out_len, algo, algo_len);
        *out_len += algo_len;
    }
    else
        *out_len += 2;
    
    if (allowed) {
        memcpy(out+*out_len, allowed, allowed_len);
        *out_len += allowed_len;
    }
    else
        *out_len += 2;
    //add 4 zeros
    *out_len += 4;
        
    memcpy(kb, random_bytes_get(8), 8);
    kb_len += 8; //8 random bytes
    int kb_len_pad = ((int)(kb_len/16))*16;
    if (kb_len % 16 > 0)
        kb_len_pad = ((int)(kb_len/16)+1)*16;
    //key already copied at kb+10
    if (kb_len < kb_len_pad) {
        kb[kb_len] = 0x80;
    }
    int r = aes_encrypt(kenc, NULL, 256, HSM_AES_MODE_CBC, kb, kb_len_pad);
    if (r != HSM_OK)
        return r;
    
    memcpy(out+*out_len, kb, kb_len_pad);
    *out_len += kb_len_pad;

    r = mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB), kmac, 256, out, *out_len, out+*out_len);
    
    *out_len += 16;
    if (r != 0)
        return r;
    return HSM_OK;
}

int dkek_type_key(const uint8_t *in) {
    if (in[8] == 5 || in[8] == 6)
        return HSM_KEY_RSA;
    else if (in[8] == 12)
        return HSM_KEY_EC;
    else if (in[8] == 15)
        return HSM_KEY_AES;
    return 0x0;
}

int dkek_decode_key(void *key_ctx, const uint8_t *in, size_t in_len, int *key_size_out) {
    uint8_t kcv[8];
    memset(kcv, 0, sizeof(kcv));
    dkek_kcv(kcv);
    
    uint8_t kmac[32];
    memset(kmac, 0, sizeof(kmac));
    dkek_kmac(kmac);
    
    uint8_t kenc[32];
    memset(kenc, 0, sizeof(kenc));
    dkek_kenc(kenc);
    
    if (memcmp(kcv, in, 8) != 0)
        return HSM_WRONG_DKEK;
        
    uint8_t signature[16];
    int r = mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB), kmac, 256, in, in_len-16, signature);
    if (r != 0)
        return HSM_WRONG_SIGNATURE;
    if (memcmp(signature, in+in_len-16, 16) != 0)
        return HSM_WRONG_SIGNATURE;
        
    int key_type = in[8];
    if (key_type != 5 && key_type != 6 && key_type != 12 && key_type != 15)
        return HSM_WRONG_DATA;
    
    if ((key_type == 5 || key_type == 6) && memcmp(in+9, "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02", 12) != 0)
        return HSM_WRONG_DATA;
        
    if (key_type == 12 && memcmp(in+9, "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03", 12) != 0)
        return HSM_WRONG_DATA;
        
    if (key_type == 15 && memcmp(in+9, "\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01", 10) != 0)
        return HSM_WRONG_DATA;
        
    size_t ofs = 9;
    
    //OID
    size_t len = get_uint16_t(in, ofs);
    ofs += len+2;
    
    //Allowed algorithms
    len = get_uint16_t(in, ofs);
    ofs += len+2;
    
    //Access conditions
    len = get_uint16_t(in, ofs);
    ofs += len+2;
    
    //Key OID
    len = get_uint16_t(in, ofs);
    ofs += len+2;
    
    if ((in_len-16-ofs) % 16 != 0)
        return HSM_WRONG_PADDING;
    uint8_t kb[8+2*4+2*4096/8+3+13]; //worst case: RSA-4096  (plus, 13 bytes padding)
    memset(kb, 0, sizeof(kb));
    memcpy(kb, in+ofs, in_len-16-ofs);
    r = aes_decrypt(kenc, NULL, 256, HSM_AES_MODE_CBC, kb, in_len-16-ofs);
    if (r != HSM_OK)
        return r;
    
    int key_size = get_uint16_t(kb, 8);
    if (key_size_out)
        *key_size_out = key_size;
    ofs = 10;
    if (key_type == 5 || key_type == 6) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)key_ctx;
        mbedtls_rsa_init(rsa);
        if (key_type == 5) {
            len = get_uint16_t(kb, ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->D, kb+ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_WRONG_DATA;
            }
            
            len = get_uint16_t(kb, ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->N, kb+ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_WRONG_DATA;
            }
        }
        else if (key_type == 6) {
            //DP-1
            len = get_uint16_t(kb, ofs); ofs += len+2;
            
            //DQ-1
            len = get_uint16_t(kb, ofs); ofs += len+2;
            
            len = get_uint16_t(kb, ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->P, kb+ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_WRONG_DATA;
            }
            
            //PQ
            len = get_uint16_t(kb, ofs); ofs += len+2;
            
            len = get_uint16_t(kb, ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->Q, kb+ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_WRONG_DATA;
            }
            //N
            len = get_uint16_t(kb, ofs); ofs += len+2;
        }
        
        len = get_uint16_t(kb, ofs); ofs += 2;
        r = mbedtls_mpi_read_binary(&rsa->E, kb+ofs, len); ofs += len;
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return HSM_WRONG_DATA;
        }
        
        if (key_type == 5) {
            r = mbedtls_rsa_import(rsa, &rsa->N, NULL, NULL, &rsa->D, &rsa->E);
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_EXEC_ERROR;
            }
        }
        else if (key_type == 6) {
            r = mbedtls_rsa_import(rsa, NULL, &rsa->P, &rsa->Q, NULL, &rsa->E);
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return HSM_EXEC_ERROR;
            }
        }
        
        r = mbedtls_rsa_complete(rsa);
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return HSM_EXEC_ERROR;
        }
        r = mbedtls_rsa_check_privkey(rsa);
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return HSM_EXEC_ERROR;
        }
    }
    else if (key_type == 12) {
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *)key_ctx;
        mbedtls_ecdsa_init(ecdsa);
        
        //A
        len = get_uint16_t(kb, ofs); ofs += len+2;
        
        //B
        len = get_uint16_t(kb, ofs); ofs += len+2;
        
        //P
        len = get_uint16_t(kb, ofs); ofs += 2;
        mbedtls_ecp_group_id ec_id = ec_get_curve_from_prime(kb+ofs, len);
        if (ec_id == MBEDTLS_ECP_DP_NONE) {
            mbedtls_ecdsa_free(ecdsa);
            return HSM_WRONG_DATA;
        }
        ofs += len;
        
        //N
        len = get_uint16_t(kb, ofs); ofs += len+2;
        
        //G
        len = get_uint16_t(kb, ofs); ofs += len+2;
        
        //d
        len = get_uint16_t(kb, ofs); ofs += 2;
        r = mbedtls_ecp_read_key(ec_id, ecdsa, kb+ofs, len);
        if (r != 0) {
            mbedtls_ecdsa_free(ecdsa);
            return HSM_EXEC_ERROR;
        }
    }
    else if (key_type == 15) {
        memcpy(key_ctx, kb+ofs, key_size);
    }
    return HSM_OK;
}