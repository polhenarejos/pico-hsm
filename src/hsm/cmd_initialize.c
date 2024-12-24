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

#include "sc_hsm.h"
#include "crypto_utils.h"
#include "files.h"
#include "random.h"
#include "kek.h"
#include "version.h"
#include "asn1.h"
#include "cvc.h"
#include "otp.h"

extern void scan_all();

extern char __StackLimit;
int heapLeft() {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

extern void reset_puk_store();
int cmd_initialize() {
    if (apdu.nc > 0) {
        uint8_t mkek[MKEK_SIZE];
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_SECURE_LOCK && !has_mkek_mask) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        int ret_mkek = load_mkek(mkek); //Try loading MKEK with previous session
        initialize_flash(true);
        scan_all();
        has_session_pin = has_session_sopin = has_mkek_mask = false;
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL, *kds = NULL, *dkeks = NULL;
        uint16_t tag_len = 0;
        asn1_ctx_t ctxi;
        asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
        while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
            if (tag == 0x80) { //options
                file_t *tf = search_file(EF_DEVOPS);
                file_put_data(tf, tag_data, tag_len);
            }
            else if (tag == 0x81) {   //user pin
                if (file_pin1 && file_pin1->data) {
                    uint8_t dhash[33];
                    dhash[0] = (uint8_t)tag_len;
                    double_hash_pin(tag_data, tag_len, dhash + 1);
                    file_put_data(file_pin1, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_pin);
                    has_session_pin = true;
                }
            }
            else if (tag == 0x82) {   //sopin pin
                if (file_sopin && file_sopin->data) {
                    uint8_t dhash[33];
                    dhash[0] = (uint8_t)tag_len;
                    double_hash_pin(tag_data, tag_len, dhash + 1);
                    file_put_data(file_sopin, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_sopin);
                    has_session_sopin = true;
                }
            }
            else if (tag == 0x91) {   //retries user pin
                file_t *tf = search_file(EF_PIN1_MAX_RETRIES);
                if (tf && tf->data) {
                    file_put_data(tf, tag_data, tag_len);
                }
                if (file_retries_pin1 && file_retries_pin1->data) {
                    file_put_data(file_retries_pin1, tag_data, tag_len);
                }
            }
            else if (tag == 0x92) {
                dkeks = tag_data;
                file_t *tf = file_new(EF_DKEK);
                if (!tf) {
                    release_mkek(mkek);
                    return SW_MEMORY_FAILURE();
                }
                file_put_data(tf, NULL, 0);
            }
            else if (tag == 0x93) {
                file_t *ef_puk = search_file(EF_PUKAUT);
                if (!ef_puk) {
                    release_mkek(mkek);
                    return SW_MEMORY_FAILURE();
                }
                uint8_t pk_status[4], puks = MIN(tag_data[0], MAX_PUK);
                memset(pk_status, 0, sizeof(pk_status));
                pk_status[0] = puks;
                pk_status[1] = puks;
                pk_status[2] = tag_data[1];
                file_put_data(ef_puk, pk_status, sizeof(pk_status));
                for (uint8_t i = 0; i < puks; i++) {
                    file_t *tf = file_new(EF_PUK + i);
                    if (!tf) {
                        release_mkek(mkek);
                        return SW_MEMORY_FAILURE();
                    }
                    file_put_data(tf, NULL, 0);
                }
            }
            else if (tag == 0x97) {
                kds = tag_data;
                /*
                   for (int i = 0; i < MIN(*kds,MAX_KEY_DOMAINS); i++) {
                    file_t *tf = file_new(EF_DKEK+i);
                    if (!tf)
                        return SW_MEMORY_FAILURE();
                    file_put_data(tf, NULL, 0);
                   }
                 */
            }
        }
        file_t *tf_kd = search_file(EF_KEY_DOMAIN);
        if (!tf_kd) {
            release_mkek(mkek);
            return SW_EXEC_ERROR();
        }
        if (ret_mkek != PICOKEY_OK) {
            ret_mkek = load_mkek(mkek); //Try again with new PIN/SO-PIN just in case some is the same
        }
        if (store_mkek(ret_mkek == PICOKEY_OK ? mkek : NULL) != PICOKEY_OK) {
            release_mkek(mkek);
            return SW_EXEC_ERROR();
        }
        release_mkek(mkek);
        if (dkeks) {
            if (*dkeks > 0) {
                uint16_t d = *dkeks;
                if (file_put_data(tf_kd, (const uint8_t *) &d, sizeof(d)) != PICOKEY_OK) {
                    return SW_EXEC_ERROR();
                }
            }
            else {
                int r = save_dkek_key(0, random_bytes_get(32));
                if (r != PICOKEY_OK) {
                    return SW_EXEC_ERROR();
                }
                uint16_t d = 0x0101;
                if (file_put_data(tf_kd, (const uint8_t *) &d, sizeof(d)) != PICOKEY_OK) {
                    return SW_EXEC_ERROR();
                }
            }
        }
        else {
            uint16_t d = 0x0000;
            if (file_put_data(tf_kd, (const uint8_t *) &d, sizeof(d)) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        if (kds) {
            uint8_t t[MAX_KEY_DOMAINS * 2], k = MIN(*kds, MAX_KEY_DOMAINS);
            memset(t, 0xff, 2 * k);
            if (file_put_data(tf_kd, t, 2 * k) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        /* When initialized, it has all credentials */
        isUserAuthenticated = true;
        /* Create terminal private key */
        file_t *fdkey = search_file(EF_KEY_DEV);
        if (!fdkey) {
            return SW_EXEC_ERROR();
        }
        int ret = 0;
        if (ret_mkek != PICOKEY_OK || !file_has_data(fdkey)) {
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256R1;
            uint8_t key_id = 0;
            if (otp_key_2) {
                ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256K1, &ecdsa, otp_key_2, 32);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                ret = mbedtls_ecp_mul(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, &ecdsa.grp.G, random_gen, NULL);
            }
            else {
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, NULL);
            }
            if (ret != 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            ret = store_keys(&ecdsa, PICO_KEYS_KEY_EC, key_id);
            if (ret != PICOKEY_OK) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            uint16_t ee_len = 0, term_len = 0;
            if ((ee_len = asn1_cvc_aut(&ecdsa, PICO_KEYS_KEY_EC, res_APDU, MAX_APDU_DATA, NULL, 0)) == 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }

            file_t *fpk = search_file(EF_EE_DEV);
            ret = file_put_data(fpk, res_APDU, ee_len);
            if (ret != 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }

            if ((term_len = asn1_cvc_cert(&ecdsa, PICO_KEYS_KEY_EC, res_APDU + ee_len, MAX_APDU_DATA - ee_len, NULL, 0, true)) == 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdsa_free(&ecdsa);
            fpk = search_file(EF_TERMCA);
            ret = file_put_data(fpk, res_APDU, ee_len + term_len);
            if (ret != 0) {
                return SW_EXEC_ERROR();
            }

            const uint8_t *keyid = (const uint8_t *) "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",
                          *label = (const uint8_t *) "ESPICOHSMTR";
            uint16_t prkd_len = asn1_build_prkd_ecc(label, (uint16_t)strlen((const char *) label), keyid, 20, 256, res_APDU, MAX_APDU_DATA);
            fpk = search_file(EF_PRKD_DEV);
            ret = file_put_data(fpk, res_APDU, prkd_len);
        }
        if (ret != 0) {
            return SW_EXEC_ERROR();
        }
        low_flash_available();
        reset_puk_store();
    }
    else {   //free memory bytes request
        int heap_left = heapLeft();
        res_APDU_size += put_uint32_t_be(heap_left, res_APDU);
        res_APDU[4] = 0;
        res_APDU[5] = HSM_VERSION_MAJOR;
        res_APDU[6] = HSM_VERSION_MINOR;
        res_APDU_size = 7;
    }
    return SW_OK();
}
