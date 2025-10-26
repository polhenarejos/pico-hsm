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

#include "sc_hsm.h"
#include "stdlib.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "kek.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/md.h"
#include "mbedtls/cmac.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/chachapoly.h"
#include "files.h"
#include "otp.h"

extern bool has_session_pin, has_session_sopin;
extern uint8_t session_pin[32], session_sopin[32];
uint8_t mkek_mask[MKEK_KEY_SIZE];
bool has_mkek_mask = false;
uint8_t pending_save_dkek = 0xff;

#define POLY 0xedb88320

uint32_t crc32c(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xffffffff;
    while (len--) {
        crc ^= *buf++;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (POLY & (0 - (crc & 1)));
        }
    }
    return ~crc;
}

void mkek_masked(uint8_t *mkek, const uint8_t *mask) {
    if (mask) {
        for (int i = 0; i < MKEK_KEY_SIZE; i++) {
            MKEK_KEY(mkek)[i] ^= mask[i];
        }
    }
}

int load_mkek(uint8_t *mkek) {
    if (has_session_pin == false && has_session_sopin == false) {
        return PICOKEY_NO_LOGIN;
    }
    const uint8_t *pin = NULL;
    if (pin == NULL && has_session_pin == true) {
        file_t *tf = search_file(EF_MKEK);
        if (file_has_data(tf)) {
            memcpy(mkek, file_get_data(tf), MKEK_SIZE);
            pin = session_pin;
        }
    }
    if (pin == NULL && has_session_sopin == true) {
        file_t *tf = search_file(EF_MKEK_SO);
        if (file_has_data(tf)) {
            memcpy(mkek, file_get_data(tf), MKEK_SIZE);
            pin = session_sopin;
        }
    }
    if (pin == NULL) { //Should never happen
        return PICOKEY_EXEC_ERROR;
    }

    if (has_mkek_mask) {
        mkek_masked(mkek, mkek_mask);
    }

    int ret = aes_decrypt_cfb_256(pin, MKEK_IV(mkek), MKEK_KEY(mkek), MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE);
    if (ret != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (crc32c(MKEK_KEY(mkek), MKEK_KEY_SIZE) != *(uint32_t *) MKEK_CHECKSUM(mkek)) {
        return PICOKEY_WRONG_DKEK;
    }
    if (otp_key_1) {
        mkek_masked(mkek, otp_key_1);
    }
    return PICOKEY_OK;
}

mse_t mse = { .init = false };

int mse_decrypt_ct(uint8_t *data, size_t len) {
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, mse.key_enc + 12);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, len - 16, mse.key_enc, mse.Qpt, 65, data + len - 16, data, data);
    mbedtls_chachapoly_free(&chatx);
    return ret;
}

int load_dkek(uint8_t id, uint8_t *dkek) {
    file_t *tf = search_file(EF_DKEK + id);
    if (!file_has_data(tf)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    memcpy(dkek, file_get_data(tf), DKEK_KEY_SIZE);
    return mkek_decrypt(dkek, DKEK_KEY_SIZE);
}

void release_mkek(uint8_t *mkek) {
    mbedtls_platform_zeroize(mkek, MKEK_SIZE);
}

int store_mkek(const uint8_t *mkek) {
    if (has_session_pin == false && has_session_sopin == false) {
        return PICOKEY_NO_LOGIN;
    }
    uint8_t tmp_mkek[MKEK_SIZE];
    if (mkek == NULL) {
        const uint8_t *rd = random_bytes_get(MKEK_IV_SIZE + MKEK_KEY_SIZE);
        memcpy(tmp_mkek, rd, MKEK_IV_SIZE + MKEK_KEY_SIZE);
    }
    else {
        memcpy(tmp_mkek, mkek, MKEK_SIZE);
    }
    if (otp_key_1) {
        mkek_masked(tmp_mkek, otp_key_1);
    }
    *(uint32_t *) MKEK_CHECKSUM(tmp_mkek) = crc32c(MKEK_KEY(tmp_mkek), MKEK_KEY_SIZE);
    if (has_session_pin) {
        uint8_t tmp_mkek_pin[MKEK_SIZE];
        memcpy(tmp_mkek_pin, tmp_mkek, MKEK_SIZE);
        file_t *tf = search_file(EF_MKEK);
        if (!tf) {
            release_mkek(tmp_mkek);
            release_mkek(tmp_mkek_pin);
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        aes_encrypt_cfb_256(session_pin, MKEK_IV(tmp_mkek_pin), MKEK_KEY(tmp_mkek_pin), MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE);
        file_put_data(tf, tmp_mkek_pin, MKEK_SIZE);
        release_mkek(tmp_mkek_pin);
    }
    if (has_session_sopin) {
        uint8_t tmp_mkek_sopin[MKEK_SIZE];
        memcpy(tmp_mkek_sopin, tmp_mkek, MKEK_SIZE);
        file_t *tf = search_file(EF_MKEK_SO);
        if (!tf) {
            release_mkek(tmp_mkek);
            release_mkek(tmp_mkek_sopin);
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        aes_encrypt_cfb_256(session_sopin, MKEK_IV(tmp_mkek_sopin), MKEK_KEY(tmp_mkek_sopin), MKEK_KEY_SIZE + MKEK_KEY_CS_SIZE);
        file_put_data(tf, tmp_mkek_sopin, MKEK_SIZE);
        release_mkek(tmp_mkek_sopin);
    }
    low_flash_available();
    release_mkek(tmp_mkek);
    return PICOKEY_OK;
}

int store_dkek_key(uint8_t id, uint8_t *dkek) {
    file_t *tf = search_file(EF_DKEK + id);
    if (!tf) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int r = mkek_encrypt(dkek, DKEK_KEY_SIZE);
    if (r != PICOKEY_OK) {
        return r;
    }
    file_put_data(tf, dkek, DKEK_KEY_SIZE);
    low_flash_available();
    return PICOKEY_OK;
}

int save_dkek_key(uint8_t id, const uint8_t *key) {
    uint8_t dkek[DKEK_KEY_SIZE];
    if (!key) {
        file_t *tf = search_file(EF_DKEK + id);
        if (!tf) {
            return PICOKEY_ERR_FILE_NOT_FOUND;
        }
        memcpy(dkek, file_get_data(tf), DKEK_KEY_SIZE);
    }
    else {
        memcpy(dkek, key, DKEK_KEY_SIZE);
    }
    return store_dkek_key(id, dkek);
}

int import_dkek_share(uint8_t id, const uint8_t *share) {
    uint8_t tmp_dkek[DKEK_KEY_SIZE];
    file_t *tf = search_file(EF_DKEK + id);
    if (!tf) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
    if (file_get_size(tf) == DKEK_KEY_SIZE) {
        memcpy(tmp_dkek, file_get_data(tf), DKEK_KEY_SIZE);
    }
    for (int i = 0; i < DKEK_KEY_SIZE; i++) {
        tmp_dkek[i] ^= share[i];
    }
    file_put_data(tf, tmp_dkek, DKEK_KEY_SIZE);
    low_flash_available();
    return PICOKEY_OK;
}

int dkek_kcv(uint8_t id, uint8_t *kcv) { //kcv 8 bytes
    uint8_t hsh[32], dkek[DKEK_KEY_SIZE];
    memset(kcv, 0, 8);
    memset(hsh, 0, sizeof(hsh));
    int r = load_dkek(id, dkek);
    if (r != PICOKEY_OK) {
        return r;
    }
    hash256(dkek, DKEK_KEY_SIZE, hsh);
    mbedtls_platform_zeroize(dkek, sizeof(dkek));
    memcpy(kcv, hsh, 8);
    return PICOKEY_OK;
}

int dkek_kenc(uint8_t id, uint8_t *kenc) { //kenc 32 bytes
    uint8_t dkek[DKEK_KEY_SIZE + 4];
    memset(kenc, 0, 32);
    int r = load_dkek(id, dkek);
    if (r != PICOKEY_OK) {
        return r;
    }
    memcpy(dkek + DKEK_KEY_SIZE, "\x0\x0\x0\x1", 4);
    hash256(dkek, sizeof(dkek), kenc);
    mbedtls_platform_zeroize(dkek, sizeof(dkek));
    return PICOKEY_OK;
}

int dkek_kmac(uint8_t id, uint8_t *kmac) { //kmac 32 bytes
    uint8_t dkek[DKEK_KEY_SIZE + 4];
    memset(kmac, 0, 32);
    int r = load_dkek(id, dkek);
    if (r != PICOKEY_OK) {
        return r;
    }
    memcpy(dkek + DKEK_KEY_SIZE, "\x0\x0\x0\x2", 4);
    hash256(dkek, DKEK_KEY_SIZE + 4, kmac);
    mbedtls_platform_zeroize(dkek, sizeof(dkek));
    return PICOKEY_OK;
}

int mkek_encrypt(uint8_t *data, uint16_t len) {
    int r;
    uint8_t mkek[MKEK_SIZE + 4];
    if ((r = load_mkek(mkek)) != PICOKEY_OK) {
        return r;
    }
    r = aes_encrypt_cfb_256(MKEK_KEY(mkek), MKEK_IV(mkek), data, len);
    release_mkek(mkek);
    return r;
}

int mkek_decrypt(uint8_t *data, uint16_t len) {
    int r;
    uint8_t mkek[MKEK_SIZE + 4];
    if ((r = load_mkek(mkek)) != PICOKEY_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(MKEK_KEY(mkek), MKEK_IV(mkek), data, len);
    release_mkek(mkek);
    return r;
}

int dkek_encode_key(uint8_t id, void *key_ctx, int key_type, uint8_t *out, uint16_t *out_len, const uint8_t *allowed, uint16_t allowed_len) {
    if (!(key_type & PICO_KEYS_KEY_RSA) && !(key_type & PICO_KEYS_KEY_EC) && !(key_type & PICO_KEYS_KEY_AES)) {
        return PICOKEY_WRONG_DATA;
    }

    uint8_t kb[8 + 2 * 4 + 2 * 4096 / 8 + 3 + 13]; //worst case: RSA-4096  (plus, 13 bytes padding)
    memset(kb, 0, sizeof(kb));
    uint16_t kb_len = 0;
    int r = 0;
    uint8_t *algo = NULL;
    uint8_t algo_len = 0;
    uint8_t kenc[32];
    memset(kenc, 0, sizeof(kenc));
    r = dkek_kenc(id, kenc);
    if (r != PICOKEY_OK) {
        return r;
    }

    uint8_t kcv[8];
    memset(kcv, 0, sizeof(kcv));
    r = dkek_kcv(id, kcv);
    if (r != PICOKEY_OK) {
        return r;
    }

    uint8_t kmac[32];
    memset(kmac, 0, sizeof(kmac));
    r = dkek_kmac(id, kmac);
    if (r != PICOKEY_OK) {
        return r;
    }

    if (key_type & PICO_KEYS_KEY_AES) {
        if (key_type & PICO_KEYS_KEY_AES_128) {
            kb_len = 16;
        }
        else if (key_type & PICO_KEYS_KEY_AES_192) {
            kb_len = 24;
        }
        else if (key_type & PICO_KEYS_KEY_AES_256) {
            kb_len = 32;
        }
        else if (key_type & PICO_KEYS_KEY_AES_512) {
            kb_len = 64;
        }

        if (kb_len != 16 && kb_len != 24 && kb_len != 32 && kb_len != 64) {
            return PICOKEY_WRONG_DATA;
        }
        if (*out_len < 8 + 1 + 10 + 6 + (2 + 64 + 14) + 16) { // 14 bytes padding
            return PICOKEY_WRONG_LENGTH;
        }

        put_uint16_t_be(kb_len, kb + 8);
        memcpy(kb + 10, key_ctx, kb_len);
        kb_len += 2;

        algo = (uint8_t *) "\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01"; //2.16.840.1.101.3.4.1 (2+8)
        algo_len = 10;
    }
    else if (key_type & PICO_KEYS_KEY_RSA) {
        if (*out_len < 8 + 1 + 12 + 6 + (8 + 2 * 4 + 2 * 4096 / 8 + 3 + 13) + 16) { //13 bytes pading
            return PICOKEY_WRONG_LENGTH;
        }
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        kb_len = 0;
        kb_len += put_uint16_t_be((uint16_t)mbedtls_rsa_get_len(rsa) * 8, kb + 8 + kb_len);

        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&rsa->D), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&rsa->D, kb + 8 + kb_len, mbedtls_mpi_size(&rsa->D));
        kb_len += (uint16_t)mbedtls_mpi_size(&rsa->D);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&rsa->N), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&rsa->N, kb + 8 + kb_len, mbedtls_mpi_size(&rsa->N));
        kb_len += (uint16_t)mbedtls_mpi_size(&rsa->N);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&rsa->E), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&rsa->E, kb + 8 + kb_len, mbedtls_mpi_size(&rsa->E));
        kb_len += (uint16_t)mbedtls_mpi_size(&rsa->E);

        algo = (uint8_t *) "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02";
        algo_len = 12;
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        if (*out_len < 8 + 1 + 12 + 6 + (8 + 2 * 8 + 9 * 66 + 2 + 4) + 16) { //4 bytes pading
            return PICOKEY_WRONG_LENGTH;
        }
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *) key_ctx;
        kb_len = 0;
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->grp.P) * 8, kb + 8 + kb_len);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->grp.A), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&ecdsa->grp.A, kb + 8 + kb_len, mbedtls_mpi_size(&ecdsa->grp.A));
        kb_len += (uint16_t)mbedtls_mpi_size(&ecdsa->grp.A);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->grp.B), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&ecdsa->grp.B, kb + 8 + kb_len, mbedtls_mpi_size(&ecdsa->grp.B));
        kb_len += (uint16_t)mbedtls_mpi_size(&ecdsa->grp.B);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->grp.P), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&ecdsa->grp.P, kb + 8 + kb_len, mbedtls_mpi_size(&ecdsa->grp.P));
        kb_len += (uint16_t)mbedtls_mpi_size(&ecdsa->grp.P);
        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->grp.N), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&ecdsa->grp.N, kb + 8 + kb_len, mbedtls_mpi_size(&ecdsa->grp.N));
        kb_len += (uint16_t)mbedtls_mpi_size(&ecdsa->grp.N);

        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, kb + 8 + kb_len + 2, sizeof(kb) - 8 - kb_len - 2);
        kb_len += put_uint16_t_be((uint16_t)olen, kb + 8 + kb_len);
        kb_len += (uint16_t)olen;

        kb_len += put_uint16_t_be((uint16_t)mbedtls_mpi_size(&ecdsa->d), kb + 8 + kb_len);
        mbedtls_mpi_write_binary(&ecdsa->d, kb + 8 + kb_len, mbedtls_mpi_size(&ecdsa->d));
        kb_len += (uint16_t)mbedtls_mpi_size(&ecdsa->d);

        mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, kb + 8 + kb_len + 2, sizeof(kb) - 8 - kb_len - 2);
        kb_len += put_uint16_t_be((uint16_t)olen, kb + 8 + kb_len);
        kb_len += (uint16_t)olen;

        algo = (uint8_t *) "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03";
        algo_len = 12;
    }
    memset(out, 0, *out_len);
    *out_len = 0;

    memcpy(out + *out_len, kcv, 8);
    *out_len += 8;

    if (key_type & PICO_KEYS_KEY_AES) {
        out[*out_len] = 15;
    }
    else if (key_type & PICO_KEYS_KEY_RSA) {
        out[*out_len] = 5;
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        out[*out_len] = 12;
    }
    *out_len += 1;

    if (algo) {
        memcpy(out + *out_len, algo, algo_len);
        *out_len += algo_len;
    }
    else {
        *out_len += 2;
    }

    if (allowed && allowed_len > 0) {
        *out_len += put_uint16_t_be(allowed_len, out + *out_len);
        memcpy(out + *out_len, allowed, allowed_len);
        *out_len += allowed_len;
    }
    else {
        *out_len += 2;
    }
    //add 4 zeros
    *out_len += 4;

    memcpy(kb, random_bytes_get(8), 8);
    kb_len += 8; //8 random bytes
    uint16_t kb_len_pad = ((uint16_t) (kb_len / 16)) * 16;
    if (kb_len % 16 > 0) {
        kb_len_pad = ((int) (kb_len / 16) + 1) * 16;
    }
    //key already copied at kb+10
    if (kb_len < kb_len_pad) {
        kb[kb_len] = 0x80;
    }
    r = aes_encrypt(kenc, NULL, 256, PICO_KEYS_AES_MODE_CBC, kb, kb_len_pad);
    if (r != PICOKEY_OK) {
        return r;
    }

    memcpy(out + *out_len, kb, kb_len_pad);
    *out_len += kb_len_pad;

    r = mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB), kmac, 256, out, *out_len, out + *out_len);

    *out_len += 16;
    if (r != 0) {
        return r;
    }
    return PICOKEY_OK;
}

int dkek_type_key(const uint8_t *in) {
    if (in[8] == 5 || in[8] == 6) {
        return PICO_KEYS_KEY_RSA;
    }
    else if (in[8] == 12) {
        return PICO_KEYS_KEY_EC;
    }
    else if (in[8] == 15) {
        return PICO_KEYS_KEY_AES;
    }
    return 0x0;
}

int dkek_decode_key(uint8_t id, void *key_ctx, const uint8_t *in, uint16_t in_len, int *key_size_out, uint8_t **allowed, uint16_t *allowed_len) {
    uint8_t kcv[8];
    int r = 0;
    memset(kcv, 0, sizeof(kcv));
    r = dkek_kcv(id, kcv);
    if (r != PICOKEY_OK) {
        return r;
    }

    uint8_t kmac[32];
    memset(kmac, 0, sizeof(kmac));
    r = dkek_kmac(id, kmac);
    if (r != PICOKEY_OK) {
        return r;
    }

    uint8_t kenc[32];
    memset(kenc, 0, sizeof(kenc));
    r = dkek_kenc(id, kenc);
    if (r != PICOKEY_OK) {
        return r;
    }

    if (memcmp(kcv, in, 8) != 0) {
        return PICOKEY_WRONG_DKEK;
    }

    uint8_t signature[16];
    r = mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB), kmac, 256, in, in_len - 16, signature);
    if (r != 0) {
        return PICOKEY_WRONG_SIGNATURE;
    }
    if (memcmp(signature, in + in_len - 16, 16) != 0) {
        return PICOKEY_WRONG_SIGNATURE;
    }

    int key_type = in[8];
    if (key_type != 5 && key_type != 6 && key_type != 12 && key_type != 15) {
        return PICOKEY_WRONG_DATA;
    }

    if ((key_type == 5 || key_type == 6) &&
        memcmp(in + 9, "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02", 12) != 0) {
        return PICOKEY_WRONG_DATA;
    }

    if (key_type == 12 &&
        memcmp(in + 9, "\x00\x0A\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03", 12) != 0) {
        return PICOKEY_WRONG_DATA;
    }

    if (key_type == 15 && memcmp(in + 9, "\x00\x08\x60\x86\x48\x01\x65\x03\x04\x01", 10) != 0) {
        return PICOKEY_WRONG_DATA;
    }

    uint16_t ofs = 9;

    //OID
    uint16_t len = get_uint16_t_be(in + ofs);
    ofs += len + 2;

    //Allowed algorithms
    len = get_uint16_t_be(in + ofs);
    *allowed = (uint8_t *) (in + ofs + 2);
    *allowed_len = len;
    ofs += len + 2;

    //Access conditions
    len = get_uint16_t_be(in + ofs);
    ofs += len + 2;

    //Key OID
    len = get_uint16_t_be(in + ofs);
    ofs += len + 2;

    if ((in_len - 16 - ofs) % 16 != 0) {
        return PICOKEY_WRONG_PADDING;
    }
    uint8_t kb[8 + 2 * 4 + 2 * 4096 / 8 + 3 + 13]; //worst case: RSA-4096  (plus, 13 bytes padding)
    memset(kb, 0, sizeof(kb));
    memcpy(kb, in + ofs, in_len - 16 - ofs);
    r = aes_decrypt(kenc, NULL, 256, PICO_KEYS_AES_MODE_CBC, kb, in_len - 16 - ofs);
    if (r != PICOKEY_OK) {
        return r;
    }

    int key_size = get_uint16_t_be(kb + 8);
    if (key_size_out) {
        *key_size_out = key_size;
    }
    ofs = 10;
    if (key_type == 5 || key_type == 6) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        mbedtls_rsa_init(rsa);
        if (key_type == 5) {
            len = get_uint16_t_be(kb + ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->D, kb + ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_WRONG_DATA;
            }

            len = get_uint16_t_be(kb + ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->N, kb + ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_WRONG_DATA;
            }
        }
        else if (key_type == 6) {
            //DP-1
            len = get_uint16_t_be(kb + ofs); ofs += len + 2;

            //DQ-1
            len = get_uint16_t_be(kb + ofs); ofs += len + 2;

            len = get_uint16_t_be(kb + ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->P, kb + ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_WRONG_DATA;
            }

            //PQ
            len = get_uint16_t_be(kb + ofs); ofs += len + 2;

            len = get_uint16_t_be(kb + ofs); ofs += 2;
            r = mbedtls_mpi_read_binary(&rsa->Q, kb + ofs, len); ofs += len;
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_WRONG_DATA;
            }
            //N
            len = get_uint16_t_be(kb + ofs); ofs += len + 2;
        }

        len = get_uint16_t_be(kb + ofs); ofs += 2;
        r = mbedtls_mpi_read_binary(&rsa->E, kb + ofs, len); ofs += len;
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return PICOKEY_WRONG_DATA;
        }

        if (key_type == 5) {
            r = mbedtls_rsa_import(rsa, &rsa->N, NULL, NULL, &rsa->D, &rsa->E);
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_EXEC_ERROR;
            }
        }
        else if (key_type == 6) {
            r = mbedtls_rsa_import(rsa, NULL, &rsa->P, &rsa->Q, NULL, &rsa->E);
            if (r != 0) {
                mbedtls_rsa_free(rsa);
                return PICOKEY_EXEC_ERROR;
            }
        }

        r = mbedtls_rsa_complete(rsa);
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return PICOKEY_EXEC_ERROR;
        }
        r = mbedtls_rsa_check_privkey(rsa);
        if (r != 0) {
            mbedtls_rsa_free(rsa);
            return PICOKEY_EXEC_ERROR;
        }
    }
    else if (key_type == 12) {
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *) key_ctx;
        mbedtls_ecdsa_init(ecdsa);

        //A
        len = get_uint16_t_be(kb + ofs); ofs += len + 2;

        //B
        len = get_uint16_t_be(kb + ofs); ofs += len + 2;

        //P
        len = get_uint16_t_be(kb + ofs); ofs += 2;
        mbedtls_ecp_group_id ec_id = ec_get_curve_from_prime(kb + ofs, len);
        if (ec_id == MBEDTLS_ECP_DP_NONE) {
            mbedtls_ecdsa_free(ecdsa);
            return PICOKEY_WRONG_DATA;
        }
        ofs += len;

        //N
        len = get_uint16_t_be(kb + ofs); ofs += len + 2;

        //G
        len = get_uint16_t_be(kb + ofs);
#ifdef MBEDTLS_EDDSA_C
        if (ec_id == MBEDTLS_ECP_DP_CURVE25519 && kb[ofs + 2] != 0x09) {
            ec_id = MBEDTLS_ECP_DP_ED25519;
        }
        else if (ec_id == MBEDTLS_ECP_DP_CURVE448 && (len != 56 || kb[ofs + 2] != 0x05)) {
            ec_id = MBEDTLS_ECP_DP_ED448;
        }
#endif
        ofs += len + 2;

        //d
        len = get_uint16_t_be(kb + ofs); ofs += 2;
        r = mbedtls_ecp_read_key(ec_id, ecdsa, kb + ofs, len);
        if (r != 0) {
            mbedtls_ecdsa_free(ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
        ofs += len;

        //Q
        len = get_uint16_t_be(kb + ofs); ofs += 2;
        r = mbedtls_ecp_point_read_binary(&ecdsa->grp, &ecdsa->Q, kb + ofs, len);
        if (r != 0) {
#ifdef MBEDTLS_EDDSA_C
            if (mbedtls_ecp_get_type(&ecdsa->grp) == MBEDTLS_ECP_TYPE_EDWARDS) {
                r = mbedtls_ecp_point_edwards(&ecdsa->grp, &ecdsa->Q, &ecdsa->d, random_gen, NULL);
            }
            else
#endif
            {
                r = mbedtls_ecp_mul(&ecdsa->grp, &ecdsa->Q, &ecdsa->d, &ecdsa->grp.G, random_gen, NULL);
            }
            if (r != 0) {
                mbedtls_ecdsa_free(ecdsa);
                return PICOKEY_EXEC_ERROR;
            }
        }
        r = mbedtls_ecp_check_pub_priv(ecdsa, ecdsa, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
    }
    else if (key_type == 15) {
        memcpy(key_ctx, kb + ofs, key_size);
    }
    return PICOKEY_OK;
}
