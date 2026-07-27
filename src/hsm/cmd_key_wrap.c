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

#include "crypto_utils.h"
#include "sc_hsm.h"
#include "kek.h"
#include "key_container.h"
#include "files.h"

int cmd_key_wrap(void) {
    int r = 0;
    uint8_t key_id = P1(apdu);
    if (P2(apdu) != 0x92) {
        return SW_WRONG_P1P2();
    }
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *ef = hsm_key_search(key_id);
    if (!ef) {
        return SW_FILE_NOT_FOUND();
    }
    uint8_t kdom = get_key_domain(ef);
    if (kdom == 0xff) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *tf_kd = file_search(EF_KEY_DOMAIN);
    uint8_t *kdata = file_get_data(tf_kd), dkeks = kdata ? kdata[2 * kdom] : 0,
            current_dkeks = kdata ? kdata[2 * kdom + 1] : 0;
    if (dkeks != current_dkeks || dkeks == 0 || dkeks == 0xff) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_has_purpose(ef, ALGO_WRAP) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    uint8_t prkd_data[4096 / 8];
    const uint8_t *dprkd = NULL;
    file_t *prkd = file_search((PRKD_PREFIX << 8) | key_id);
    if (hsm_key_container_is_marker(ef)) {
        uint32_t prkd_size = 0;
        byte_buffer_t prkd_buffer = BYTE_BUFFER(prkd_data, sizeof(prkd_data));
        if (hsm_key_container_object_size(key_id, HSM_KEY_OBJECT_PRKD, true, &prkd_size) != PICOKEYS_OK || prkd_size == 0 || prkd_size > sizeof(prkd_data) || hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRKD, FILE_OBJECT_OPERATION_READ, true, &prkd_buffer) != PICOKEYS_OK || prkd_buffer.len != prkd_size) {
            return SW_FILE_NOT_FOUND();
        }
        dprkd = prkd_data;
    }
    else {
        if (!file_has_data(prkd)) {
            return SW_FILE_NOT_FOUND();
        }
        dprkd = file_get_data(prkd);
    }
    byte_buffer_t wrapped_key = BYTE_BUFFER(res_APDU, MAX_DKEK_ENCODE_KEY_BUFFER);
    const_byte_array_t meta_tag = get_meta_tag(ef, 0x91);
    if (*dprkd == P15_KEYTYPE_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef, FILE_OBJECT_OPERATION_EXPORT, false);
        if (r != PICOKEYS_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == PICOKEYS_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, PICOKEYS_KEY_RSA, &wrapped_key, meta_tag);
        mbedtls_rsa_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_ECC) {
        mbedtls_ecp_keypair ctx;
        mbedtls_ecp_keypair_init(&ctx);
        r = load_private_key_ec(&ctx, ef, FILE_OBJECT_OPERATION_EXPORT, false);
        if (r != PICOKEYS_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            if (r == PICOKEYS_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, PICOKEYS_KEY_EC, &wrapped_key, meta_tag);
        mbedtls_ecp_keypair_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_AES) {
        uint8_t kdata_aes[64]; //maximum AES key size
        if (wait_button_pressed() == true) { //timeout
            return SW_SECURE_MESSAGE_EXEC_ERROR();
        }

        byte_buffer_t key = BYTE_BUFFER(kdata_aes, sizeof(kdata_aes));
        uint16_t aes_type = PICOKEYS_KEY_AES;
        if (mkek_load_key_file(ef, &key, FILE_OBJECT_OPERATION_EXPORT, false) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        if (key.len == 64) {
            aes_type = PICOKEYS_KEY_AES_512;
        }
        else if (key.len == 32) {
            aes_type = PICOKEYS_KEY_AES_256;
        }
        else if (key.len == 24) {
            aes_type = PICOKEYS_KEY_AES_192;
        }
        else if (key.len == 16) {
            aes_type = PICOKEYS_KEY_AES_128;
        }
        r = dkek_encode_key(kdom, kdata_aes, aes_type, &wrapped_key, meta_tag);
        mbedtls_platform_zeroize(kdata_aes, sizeof(kdata_aes));
    }
    if (r != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = (uint16_t)wrapped_key.len;
    return SW_OK();
}
