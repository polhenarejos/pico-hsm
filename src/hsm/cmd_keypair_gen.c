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
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    int ret = 0;

    size_t tout = 0;
    //sc_asn1_print_tags(apdu.data, apdu.nc);
    uint8_t *p = NULL;
    if (asn1_find_tag(apdu.data, apdu.nc, 0x7f49, &tout, &p) && tout > 0 && p != NULL) {
        size_t oid_len = 0;
        uint8_t *oid = NULL;
        if (asn1_find_tag(p, tout, 0x6, &oid_len, &oid) && oid_len > 0 && oid != NULL) {
            if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_256, oid_len) == 0) { //RSA
                size_t ex_len = 3, ks_len = 2;
                uint8_t *ex = NULL, *ks = NULL;
                uint32_t exponent = 65537, key_size = 2048;
                if (asn1_find_tag(p, tout, 0x82, &ex_len, &ex) && ex_len > 0 && ex != NULL) {
                    uint8_t *dt = ex;
                    exponent = 0;
                    for (int i = 0; i < ex_len; i++) {
                        exponent = (exponent << 8) | *dt++;
                    }
                }
                if (asn1_find_tag(p, tout, 0x2, &ks_len, &ks) && ks_len > 0 && ks != NULL) {
                    uint8_t *dt = ks;
                    key_size = 0;
                    for (int i = 0; i < ks_len; i++) {
                        key_size = (key_size << 8) | *dt++;
                    }
                }
                printf("KEYPAIR RSA %ld (%lx)\r\n",key_size,exponent);
                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa);
                uint8_t index = 0;
                ret = mbedtls_rsa_gen_key(&rsa, random_gen, &index, key_size, exponent);
                if (ret != 0) {
                        mbedtls_rsa_free(&rsa);
                    return SW_EXEC_ERROR();
                }
                if ((res_APDU_size = asn1_cvc_aut(&rsa, HSM_KEY_RSA, res_APDU, 4096, NULL, 0)) == 0) {
                    return SW_EXEC_ERROR();
                }
	            ret = store_keys(&rsa, HSM_KEY_RSA, key_id);
	            if (ret != CCID_OK) {
                    mbedtls_rsa_free(&rsa);
                    return SW_EXEC_ERROR();
                }
                mbedtls_rsa_free(&rsa);
            }
            else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_256,MIN(oid_len,10)) == 0) { //ECC
                size_t prime_len;
                uint8_t *prime = NULL;
                if (asn1_find_tag(p, tout, 0x81, &prime_len, &prime) != true)
                    return SW_WRONG_DATA();
                mbedtls_ecp_group_id ec_id = ec_get_curve_from_prime(prime, prime_len);
                printf("KEYPAIR ECC %d\r\n",ec_id);
                if (ec_id == MBEDTLS_ECP_DP_NONE) {
                    return SW_FUNC_NOT_SUPPORTED();
                }
                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);
                uint8_t index = 0;
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, &index);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                size_t l91 = 0, ext_len = 0;
                uint8_t *p91 = NULL, *ext = NULL;
                if (asn1_find_tag(apdu.data, apdu.nc, 0x91, &l91, &p91) && p91 != NULL && l91 > 0) {
                    for (int n = 0; n < l91; n++) {
                        if (p91[n] == ALGO_EC_DH_XKEK) {
                            size_t l92 = 0;
                            uint8_t *p92 = NULL;
                            if (!asn1_find_tag(apdu.data, apdu.nc, 0x92, &l92, &p92) || p92 == NULL || l92 == 0)
                                return SW_WRONG_DATA();
                            if (p92[0] > MAX_KEY_DOMAINS)
                                return SW_WRONG_DATA();
                            file_t *tf_xkek = search_dynamic_file(EF_XKEK+p92[0]);
                            if (!tf_xkek)
                                return SW_WRONG_DATA();
                            ext_len = 2+2+strlen(OID_ID_KEY_DOMAIN_UID)+2+file_get_size(tf_xkek);
                            ext = (uint8_t *)calloc(1, ext_len);
                            uint8_t *pe = ext;
                            *pe++ = 0x73;
                            *pe++ = ext_len-2;
                            *pe++ = 0x6;
                            *pe++ = strlen(OID_ID_KEY_DOMAIN_UID);
                            memcpy(pe, OID_ID_KEY_DOMAIN_UID, strlen(OID_ID_KEY_DOMAIN_UID));
                            pe += strlen(OID_ID_KEY_DOMAIN_UID);
                            *pe++ = 0x80;
                            *pe++ = file_get_size(tf_xkek);
                            memcpy(pe, file_get_data(tf_xkek), file_get_size(tf_xkek));
                        }
                    }
                }
                if ((res_APDU_size = asn1_cvc_aut(&ecdsa, HSM_KEY_EC, res_APDU, 4096, ext, ext_len)) == 0) {
                    if (ext)
                        free(ext);
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                if (ext)
                    free(ext);
                ret = store_keys(&ecdsa, HSM_KEY_EC, key_id);
                mbedtls_ecdsa_free(&ecdsa);
	            if (ret != CCID_OK) {
                    return SW_EXEC_ERROR();
                }
            }

        }
    }
    else
        return SW_WRONG_DATA();
    if (find_and_store_meta_key(key_id) != CCID_OK)
        return SW_EXEC_ERROR();
    file_t *fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
    ret = flash_write_data_to_file(fpk, res_APDU, res_APDU_size);
    if (ret != 0)
        return SW_EXEC_ERROR();
    //if (apdu.ne == 0)
    //    apdu.ne = res_APDU_size;
    low_flash_available();
    return SW_OK();
}
