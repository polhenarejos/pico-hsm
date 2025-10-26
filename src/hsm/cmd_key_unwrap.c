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
#include "crypto_utils.h"
#include "kek.h"
#include "cvc.h"

int cmd_key_unwrap() {
    uint8_t key_id = P1(apdu);
    int r = 0;
    if (P2(apdu) != 0x93) {
        return SW_WRONG_P1P2();
    }
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t *data = apdu.data;
    uint16_t data_len = apdu.nc;
    if (data_len == 0) { // New style
        file_t *tef = search_file(0x2F10);
        if (!file_has_data(tef)) {
            return SW_FILE_NOT_FOUND();
        }
        data = file_get_data(tef);
        data_len = file_get_size(tef);
    }
    int key_type = dkek_type_key(data);
    uint8_t *allowed = NULL;
    int16_t kdom = -1;
    uint16_t allowed_len = 0;
    if (key_type == 0x0) {
        return SW_DATA_INVALID();
    }
    if (key_type & PICO_KEYS_KEY_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        do {
            r = dkek_decode_key((uint8_t)++kdom, &ctx, data, data_len, NULL, &allowed, &allowed_len);
        } while ((r == PICOKEY_ERR_FILE_NOT_FOUND || r == PICOKEY_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, PICO_KEYS_KEY_RSA, key_id);
        if ((res_APDU_size = (uint16_t)asn1_cvc_aut(&ctx, PICO_KEYS_KEY_RSA, res_APDU, MAX_APDU_DATA, NULL, 0)) == 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_rsa_free(&ctx);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        mbedtls_ecp_keypair ctx;
        mbedtls_ecp_keypair_init(&ctx);
        do {
            r = dkek_decode_key((uint8_t)++kdom, &ctx, data, data_len, NULL, &allowed, &allowed_len);
        } while ((r == PICOKEY_ERR_FILE_NOT_FOUND || r == PICOKEY_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != PICOKEY_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, PICO_KEYS_KEY_EC, key_id);
        if ((res_APDU_size = (uint16_t)asn1_cvc_aut(&ctx, PICO_KEYS_KEY_EC, res_APDU, MAX_APDU_DATA, NULL, 0)) == 0) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecp_keypair_free(&ctx);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (key_type & PICO_KEYS_KEY_AES) {
        uint8_t aes_key[64];
        int key_size = 0, aes_type = 0;
        do {
            r = dkek_decode_key((uint8_t)++kdom,
                                aes_key,
                                data,
                                data_len,
                                &key_size,
                                &allowed,
                                &allowed_len);
        } while ((r == PICOKEY_ERR_FILE_NOT_FOUND || r == PICOKEY_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        if (key_size == 64) {
            aes_type = PICO_KEYS_KEY_AES_512;
        }
        else if (key_size == 32) {
            aes_type = PICO_KEYS_KEY_AES_256;
        }
        else if (key_size == 24) {
            aes_type = PICO_KEYS_KEY_AES_192;
        }
        else if (key_size == 16) {
            aes_type = PICO_KEYS_KEY_AES_128;
        }
        else {
            return SW_EXEC_ERROR();
        }
        r = store_keys(aes_key, aes_type, key_id);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    if ((allowed != NULL && allowed_len > 0) || kdom >= 0) {
        uint16_t meta_len = (allowed_len > 0 ? 2 + allowed_len : 0) + (kdom >= 0 ? 3 : 0);
        uint8_t *meta = (uint8_t *) calloc(1, meta_len), *m = meta;
        if (allowed_len > 0) {
            *m++ = 0x91;
            *m++ = (uint8_t)allowed_len;
            memcpy(m, allowed, allowed_len); m += allowed_len;
        }
        if (kdom >= 0) {
            *m++ = 0x92;
            *m++ = 1;
            *m++ = (uint8_t)kdom;
        }
        r = meta_add((KEY_PREFIX << 8) | key_id, meta, meta_len);
        free(meta);
        if (r != PICOKEY_OK) {
            return r;
        }
    }
    if (res_APDU_size > 0) {
        file_t *fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
        r = file_put_data(fpk, res_APDU, res_APDU_size);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = 0;
    }
    low_flash_available();
    return SW_OK();
}
