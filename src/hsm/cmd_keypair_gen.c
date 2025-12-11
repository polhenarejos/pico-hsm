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
#include "files.h"
#include "asn1.h"
#include "cvc.h"
#include "oid.h"
#include "random.h"
#include "kek.h"

int cmd_keypair_gen() {
    uint8_t key_id = P1(apdu);
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int ret = 0;

    //sc_asn1_print_tags(apdu.data, apdu.nc);
    //DEBUG_DATA(apdu.data,apdu.nc);
    asn1_ctx_t ctxi, ctxo = { 0 };
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, 0x7f49, &ctxo) && asn1_len(&ctxo) > 0) {
        asn1_ctx_t oid = { 0 };
        if (asn1_find_tag(&ctxo, 0x6, &oid) && asn1_len(&oid) > 0) {
            if (memcmp(oid.data, OID_ID_TA_RSA_V1_5_SHA_256, oid.len) == 0) { //RSA
                asn1_ctx_t ex = { 0 }, ks = { 0 };
                uint32_t exponent = 65537, key_size = 2048;
                if (asn1_find_tag(&ctxo, 0x82, &ex) && asn1_len(&ex) > 0) {
                    exponent = asn1_get_uint(&ex);
                }
                if (asn1_find_tag(&ctxo, 0x2, &ks) && asn1_len(&ks) > 0) {
                    key_size = asn1_get_uint(&ks);
                }
                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa);
                uint8_t index = 0;
                ret = mbedtls_rsa_gen_key(&rsa, random_gen, &index, key_size, exponent);
                if (ret != 0) {
                    mbedtls_rsa_free(&rsa);
                    return SW_EXEC_ERROR();
                }
                if ((res_APDU_size = (uint16_t)asn1_cvc_aut(&rsa, PICO_KEYS_KEY_RSA, res_APDU, MAX_APDU_DATA, NULL, 0)) == 0) {
                    return SW_EXEC_ERROR();
                }
                ret = store_keys(&rsa, PICO_KEYS_KEY_RSA, key_id);
                if (ret != PICOKEY_OK) {
                    mbedtls_rsa_free(&rsa);
                    return SW_EXEC_ERROR();
                }
                mbedtls_rsa_free(&rsa);
            }
            else if (memcmp(oid.data, OID_ID_TA_ECDSA_SHA_256, MIN(oid.len, 10)) == 0) {   //ECC
                asn1_ctx_t prime = { 0 };
                if (asn1_find_tag(&ctxo, 0x81, &prime) != true) {
                    return SW_WRONG_DATA();
                }
                mbedtls_ecp_group_id ec_id = ec_get_curve_from_prime(prime.data, prime.len);
                if (ec_id == MBEDTLS_ECP_DP_NONE) {
                    return SW_FUNC_NOT_SUPPORTED();
                }
                if (ec_id == MBEDTLS_ECP_DP_CURVE25519 || ec_id == MBEDTLS_ECP_DP_CURVE448) {
                    asn1_ctx_t g = { 0 };
                    if (asn1_find_tag(&ctxo, 0x83, &g) != true) {
                        return SW_WRONG_DATA();
                    }
#ifdef MBEDTLS_EDDSA_C
                    if (ec_id == MBEDTLS_ECP_DP_CURVE25519 && (g.data[0] != 9)) {
                        ec_id = MBEDTLS_ECP_DP_ED25519;
                    }
                    else if (ec_id == MBEDTLS_ECP_DP_CURVE448 && (g.len != 56 || g.data[0] != 5)) {
                        ec_id = MBEDTLS_ECP_DP_ED448;
                    }
#endif
                }
                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);
                uint8_t index = 0;
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, &index);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                asn1_ctx_t a91 = { 0 }, ext = { 0 };
                if (asn1_find_tag(&ctxi, 0x91, &a91) && asn1_len(&a91) > 0) {
                    for (size_t n = 0; n < a91.len; n++) {
                        if (a91.data[n] == ALGO_EC_DH_XKEK) {
                            asn1_ctx_t a92 = {0};
                            if (!asn1_find_tag(&ctxi, 0x92, &a92) || asn1_len(&a92) == 0) {
                                return SW_WRONG_DATA();
                            }
                            if (a92.data[0] > MAX_KEY_DOMAINS) {
                                return SW_WRONG_DATA();
                            }
                            file_t *tf_xkek = search_file(EF_XKEK + a92.data[0]);
                            if (!tf_xkek) {
                                return SW_WRONG_DATA();
                            }
                            ext.len = 2 + 2 + (uint16_t)strlen(OID_ID_KEY_DOMAIN_UID) + 2 + file_get_size(
                                tf_xkek);
                            ext.data = (uint8_t *) calloc(1, ext.len);
                            uint8_t *pe = ext.data;
                            *pe++ = 0x73;
                            *pe++ = (uint8_t)ext.len - 2;
                            *pe++ = 0x6;
                            *pe++ = (uint8_t)strlen(OID_ID_KEY_DOMAIN_UID);
                            memcpy(pe, OID_ID_KEY_DOMAIN_UID, strlen(OID_ID_KEY_DOMAIN_UID));
                            pe += strlen(OID_ID_KEY_DOMAIN_UID);
                            *pe++ = 0x80;
                            *pe++ = (uint8_t)file_get_size(tf_xkek);
                            memcpy(pe, file_get_data(tf_xkek), file_get_size(tf_xkek));
                        }
                    }
                }
                if ((res_APDU_size = (uint16_t)asn1_cvc_aut(&ecdsa, PICO_KEYS_KEY_EC, res_APDU, MAX_APDU_DATA, ext.data, ext.len)) == 0) {
                    if (ext.data) {
                        free(ext.data);
                    }
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                if (ext.data) {
                    free(ext.data);
                }
                ret = store_keys(&ecdsa, PICO_KEYS_KEY_EC, key_id);
                mbedtls_ecdsa_free(&ecdsa);
                if (ret != PICOKEY_OK) {
                    return SW_EXEC_ERROR();
                }
            }

        }
    }
    else {
        return SW_WRONG_DATA();
    }
    if (find_and_store_meta_key(key_id) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    file_t *fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
    ret = file_put_data(fpk, res_APDU, res_APDU_size);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    if (apdu.ne == 0) {
        apdu.ne = res_APDU_size;
    }
    low_flash_available();
    return SW_OK();
}
