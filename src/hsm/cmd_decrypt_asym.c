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
#include "mbedtls/ecdh.h"
#include "crypto_utils.h"
#include "kek.h"
#include "files.h"
#include "asn1.h"
#include "cvc.h"
#include "random.h"
#include "oid.h"

int cmd_decrypt_asym() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *ef = search_file((KEY_PREFIX << 8) | key_id);
    if (!ef) {
        return SW_FILE_NOT_FOUND();
    }
    if (get_key_counter(ef) == 0) {
        return SW_FILE_FULL();
    }
    if (key_has_purpose(ef, p2) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (p2 >= ALGO_RSA_DECRYPT && p2 <= ALGO_RSA_DECRYPT_OEP) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        if (p2 == ALGO_RSA_DECRYPT_OEP) {
            mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
        }
        int r = load_private_key_rsa(&ctx, ef);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == PICOKEY_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        uint16_t key_size = file_get_size(ef);
        if (apdu.nc < key_size) { //needs padding
            memset(apdu.data + apdu.nc, 0, key_size - apdu.nc);
        }
        if (p2 == ALGO_RSA_DECRYPT_PKCS1 || p2 == ALGO_RSA_DECRYPT_OEP) {
            size_t olen = apdu.nc;
            r = mbedtls_rsa_pkcs1_decrypt(&ctx, random_gen, NULL, &olen, apdu.data, res_APDU, 512);
            if (r == 0) {
                res_APDU_size = (uint16_t)olen;
            }
        }
        else {
            r = mbedtls_rsa_private(&ctx, random_gen, NULL, apdu.data, res_APDU);
            if (r == 0) {
                res_APDU_size = key_size;
            }
        }
        if (r != 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_rsa_free(&ctx);
    }
    else if (p2 == ALGO_EC_DH || p2 == ALGO_EC_DH_XKEK) {
        mbedtls_ecdh_context ctx;
        if (wait_button_pressed() == true) { //timeout
            return SW_SECURE_MESSAGE_EXEC_ERROR();
        }
        uint16_t key_size = file_get_size(ef);
        uint8_t *kdata = (uint8_t *) calloc(1, key_size);
        memcpy(kdata, file_get_data(ef), key_size);
        if (mkek_decrypt(kdata, key_size) != 0) {
            mbedtls_platform_zeroize(kdata, key_size);
            free(kdata);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecdh_init(&ctx);
        mbedtls_ecp_group_id gid = kdata[0];
        int r = 0;
        r = mbedtls_ecdh_setup(&ctx, gid);
        if (r != 0) {
            mbedtls_platform_zeroize(kdata, key_size);
            mbedtls_ecdh_free(&ctx);
            free(kdata);
            return SW_DATA_INVALID();
        }
        r = mbedtls_ecp_read_key(gid, (mbedtls_ecdsa_context *)&ctx.ctx.mbed_ecdh, kdata + 1, key_size - 1);
        mbedtls_platform_zeroize(kdata, key_size);
        free(kdata);
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            return SW_DATA_INVALID();
        }
        r = -1;
        if (p2 == ALGO_EC_DH) {
            *(apdu.data - 1) = (uint8_t)apdu.nc;
            r = mbedtls_ecdh_read_public(&ctx, apdu.data - 1, apdu.nc + 1);
        }
        else if (p2 == ALGO_EC_DH_XKEK) {
            uint16_t pub_len = 0;
            const uint8_t *pub = cvc_get_pub(apdu.data, (uint16_t)apdu.nc, &pub_len);
            if (pub) {
                uint16_t t86_len = 0;
                const uint8_t *t86 = cvc_get_field(pub, pub_len, &t86_len, 0x86);
                uint8_t *t86w = (uint8_t *)t86;
                if (t86) {
                    *(t86w - 1) = (uint8_t)t86_len;
                    r = mbedtls_ecdh_read_public(&ctx, t86 - 1, t86_len + 1);
                }
            }
        }
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            return SW_DATA_INVALID();
        }
        size_t olen = 0;
        // The SmartCard-HSM returns the point result of the DH operation
        // with a leading '04'
        res_APDU[0] = 0x04;
        r =
            mbedtls_ecdh_calc_secret(&ctx, &olen, res_APDU + 1, MBEDTLS_ECP_MAX_BYTES, random_gen,
                                     NULL);
        mbedtls_ecdh_free(&ctx);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        if (p2 == ALGO_EC_DH) {
            res_APDU_size = (uint16_t)(olen + 1);
        }
        else {
            res_APDU_size = 0;
            uint16_t ext_len = 0;
            const uint8_t *ext = NULL;
            if ((ext = cvc_get_ext(apdu.data, (uint16_t)apdu.nc, &ext_len)) == NULL) {
                return SW_WRONG_DATA();
            }
            uint8_t *p = NULL;
            uint16_t tag = 0;
            asn1_ctx_t ctxi, ctxo = { 0 }, kdom_uid = { 0 };
            asn1_ctx_init((uint8_t *)ext, ext_len, &ctxi);
            while (walk_tlv(&ctxi, &p, &tag, &ctxo.len, &ctxo.data)) {
                if (tag == 0x73) {
                    asn1_ctx_t oid = {0};
                    if (asn1_find_tag(&ctxo, 0x6, &oid) == true &&
                        oid.len == strlen(OID_ID_KEY_DOMAIN_UID) &&
                        memcmp(oid.data, OID_ID_KEY_DOMAIN_UID,
                               strlen(OID_ID_KEY_DOMAIN_UID)) == 0) {
                        if (asn1_find_tag(&ctxo, 0x80, &kdom_uid) == false) {
                            return SW_WRONG_DATA();
                        }
                        break;
                    }
                }
            }
            if (asn1_len(&kdom_uid) == 0) {
                return SW_WRONG_DATA();
            }
            for (uint8_t n = 0; n < MAX_KEY_DOMAINS; n++) {
                file_t *tf = search_file(EF_XKEK + n);
                if (tf) {
                    if (file_get_size(tf) == kdom_uid.len &&
                        memcmp(file_get_data(tf), kdom_uid.data, kdom_uid.len) == 0) {
                        file_new(EF_DKEK + n);
                        if (store_dkek_key(n, res_APDU + 1) != PICOKEY_OK) {
                            return SW_EXEC_ERROR();
                        }
                        mbedtls_platform_zeroize(res_APDU, 32);
                        return SW_OK();
                    }
                }
            }
            return SW_REFERENCE_NOT_FOUND();
        }
    }
    else {
        return SW_WRONG_P1P2();
    }
    decrement_key_counter(ef);
    return SW_OK();
}
