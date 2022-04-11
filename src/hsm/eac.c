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
#include "sc_hsm.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/cmac.h"

static uint8_t nonce[8];
static uint8_t auth_token[8];
static uint8_t sm_kmac[16];
static uint8_t sm_kenc[16];
static MSE_protocol sm_protocol = MSE_NONE;
static mbedtls_mpi sm_mSSC;
static uint8_t sm_blocksize = 0;
static uint8_t sm_iv[16];
size_t sm_session_pin_len = 0;
uint8_t sm_session_pin[16];

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
    mbedtls_mpi_init(&sm_mSSC);
    mbedtls_mpi_grow(&sm_mSSC, sm_blocksize);
    mbedtls_mpi_lset(&sm_mSSC, 0);
    memset(sm_iv, 0, sizeof(sm_iv));
}

void sm_set_protocol(MSE_protocol proto) {
    sm_protocol = proto;
    if (proto == MSE_AES)
        sm_blocksize = 16;
    else if (proto == MSE_3DES)
        sm_blocksize = 8;
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

int sm_unwrap() {
    uint8_t sm_indicator = (CLA(apdu) >> 2) & 0x3;
    if (sm_indicator == 0)
        return HSM_OK;
    int r = sm_verify();
    if (r != HSM_OK)
        return r;
    int le = sm_get_le();
    if (le >= 0)
        apdu.expected_res_size = le;
    const uint8_t *p = apdu.cmd_apdu_data;
    uint8_t *body = NULL;
    size_t body_size = 0;
    bool is87 = false;
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        uint8_t tag = *p++;
        uint16_t tag_len = *p++;
        if (tag_len == 0x82) {
            tag_len = *p++ << 8;
            tag_len |= *p++;
        }
        else if (tag_len == 0x81) {
            tag_len = *p++;
        }
        if (tag == 0x87 || tag == 0x85) {
            body = (uint8_t *)p;
            body_size = tag_len;
            if (tag == 0x87) {
                is87 = true;
                body_size--;
            }
        }
        p += tag_len;
    }
    if (!body)
        return HSM_WRONG_DATA;
    if (is87 && *body++ != 0x1) {
        return HSM_WRONG_PADDING;
    }
    sm_update_iv();
    aes_decrypt(sm_kenc, sm_iv, 128, HSM_AES_MODE_CBC, body, body_size);
    memmove(apdu.cmd_apdu_data, body, body_size);
    apdu.cmd_apdu_data_len = sm_remove_padding(apdu.cmd_apdu_data, body_size);
    DEBUG_PAYLOAD(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
    return HSM_OK;
}

int sm_wrap() {
    uint8_t sm_indicator = (CLA(apdu) >> 2) & 0x3;
    if (sm_indicator == 0)
        return HSM_OK;
    uint8_t input[1024];
    size_t input_len = 0;
    memset(input, 0, sizeof(input));
    mbedtls_mpi ssc;
    mbedtls_mpi_init(&ssc);
    mbedtls_mpi_add_int(&ssc, &sm_mSSC, 1);
    mbedtls_mpi_copy(&sm_mSSC, &ssc);
    int r = mbedtls_mpi_write_binary(&ssc, input, sm_blocksize);
    input_len += sm_blocksize;
    mbedtls_mpi_free(&ssc);
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = 0x80;
        memset(res_APDU+res_APDU_size, 0, (sm_blocksize - (res_APDU_size%sm_blocksize)));
        res_APDU_size += (sm_blocksize - (res_APDU_size%sm_blocksize));
        DEBUG_PAYLOAD(res_APDU, res_APDU_size);
        sm_update_iv();
        aes_encrypt(sm_kenc, sm_iv, 128, HSM_AES_MODE_CBC, res_APDU, res_APDU_size);
        memmove(res_APDU+1, res_APDU, res_APDU_size);
        res_APDU[0] = 0x1;
        res_APDU_size++;
        if (res_APDU_size < 128) {
            memmove(res_APDU+2, res_APDU, res_APDU_size);
            res_APDU[1] = res_APDU_size;
            res_APDU_size += 2;
        }
        else if (res_APDU_size < 256) {
            memmove(res_APDU+3, res_APDU, res_APDU_size);
            res_APDU[1] = 0x81;
            res_APDU[2] = res_APDU_size;
            res_APDU_size += 3;
        }
        else {
            memmove(res_APDU+4, res_APDU, res_APDU_size);
            res_APDU[1] = 0x82;
            res_APDU[2] = res_APDU_size >> 8;
            res_APDU[3] = res_APDU_size & 0xff;
            res_APDU_size += 4;
        }
        res_APDU[0] = 0x87;
    }
    res_APDU[res_APDU_size++] = 0x99;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = apdu.sw >> 8;
    res_APDU[res_APDU_size++] = apdu.sw & 0xff;
    memcpy(input+input_len, res_APDU, res_APDU_size);
    input_len += res_APDU_size;
    input[input_len++] = 0x80;
    input_len += (sm_blocksize - (input_len%sm_blocksize));
    r = sm_sign(input, input_len, res_APDU+res_APDU_size+2);
    res_APDU[res_APDU_size++] = 0x8E;
    res_APDU[res_APDU_size++] = 8;
    res_APDU_size += 8;
    if (apdu.expected_res_size > 0)
        apdu.expected_res_size = res_APDU_size;
    return HSM_OK;
}

int sm_get_le() {
    const uint8_t *p = apdu.cmd_apdu_data;
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        uint8_t tag = *p++;
        uint16_t tag_len = *p++;
        if (tag_len == 0x82) {
            tag_len = *p++ << 8;
            tag_len |= *p++;
        }
        else if (tag_len == 0x81) {
            tag_len = *p++;
        }
        if (tag == 0x97) {
            uint32_t le = 0;
            for (int t = 1; t <= tag_len; t++)
                le |= (*p++) << (tag_len-t);
            return le;
        }
        p += tag_len;
    }
    return -1;
}

void sm_update_iv() {
    uint8_t tmp_iv[16], sc_counter[16];
    memset(tmp_iv, 0, sizeof(tmp_iv)); //IV is always 0 for encryption of IV based on counter
    mbedtls_mpi_write_binary(&sm_mSSC, sc_counter, sizeof(sc_counter));
    aes_encrypt(sm_kenc, tmp_iv, 128, HSM_AES_MODE_CBC, sc_counter, sizeof(sc_counter));
    memcpy(sm_iv, sc_counter, sizeof(sc_counter));
}

int sm_verify() {
    uint8_t input[1024];
    memset(input, 0, sizeof(input));
    int input_len = 0, r = 0;
    bool add_header = (CLA(apdu) & 0xC) == 0xC;
    int data_len = (int)(apdu.cmd_apdu_data_len/sm_blocksize)*sm_blocksize;
    if (data_len % sm_blocksize)
        data_len += sm_blocksize;
    if (data_len+(add_header ? sm_blocksize : 0) > 1024)
        return HSM_WRONG_LENGTH;
    mbedtls_mpi ssc;
    mbedtls_mpi_init(&ssc);
    mbedtls_mpi_add_int(&ssc, &sm_mSSC, 1);
    mbedtls_mpi_copy(&sm_mSSC, &ssc);
    r = mbedtls_mpi_write_binary(&ssc, input, sm_blocksize);
    input_len += sm_blocksize;
    mbedtls_mpi_free(&ssc);
    if (r != 0)
        return HSM_EXEC_ERROR;
    if (add_header) {
        input[input_len++] = CLA(apdu);
        input[input_len++] = INS(apdu);
        input[input_len++] = P1(apdu);
        input[input_len++] = P2(apdu);
        input[input_len++] = 0x80;
        input_len += sm_blocksize-5;
    }
    bool some_added = false;
    const uint8_t *p = apdu.cmd_apdu_data, *mac = NULL, *initag = NULL;
    size_t mac_len = 0;
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        initag = p;
        uint8_t tag = *p++;
        uint16_t tag_len = *p++;
        if (tag_len == 0x82) {
            tag_len = *p++ << 8;
            tag_len |= *p++;
        }
        else if (tag_len == 0x81) {
            tag_len = *p++;
        }
        if (tag & 0x1) {
            memcpy(input+input_len, initag, tag_len+(p-initag));
            input_len += tag_len+(p-initag);
            some_added = true;
        }
        if (tag == 0x8E) {
            mac = p;
            mac_len = tag_len;
        }
        p += tag_len;
    }
    if (!mac)
        return HSM_WRONG_DATA;
    if (some_added) {
        input[input_len++] = 0x80;
        input_len += (sm_blocksize - (input_len%sm_blocksize));
    }
    uint8_t signature[16];
    r = sm_sign(input, input_len, signature);
    if (r != 0)
        return HSM_EXEC_ERROR;
    if (memcmp(signature, mac, mac_len) == 0)
        return HSM_OK;
    return HSM_VERIFICATION_FAILED;
}

int sm_remove_padding(const uint8_t *data, size_t data_len) {
    int i = data_len-1;
    for (; i >= 0 && data[i] == 0; i--);
    if (i < 0 || data[i] != 0x80)
        return -1;
    return i;
}