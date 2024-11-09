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
#include "mbedtls/ecdh.h"
#include "asn1.h"
#include "random.h"
#include "oid.h"
#include "eac.h"
#include "files.h"

int cmd_general_authenticate() {
    if (P1(apdu) == 0x0 && P2(apdu) == 0x0) {
        if (apdu.data[0] == 0x7C) {
            int r = 0;
            uint16_t pubkey_len = 0;
            const uint8_t *pubkey = NULL;
            uint16_t tag = 0x0;
            uint8_t *tag_data = NULL, *p = NULL;
            uint16_t tag_len = 0;
            asn1_ctx_t ctxi;
            asn1_ctx_init(apdu.data + 2, (uint16_t)(apdu.nc - 2), &ctxi);
            while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
                if (tag == 0x80) {
                    pubkey = tag_data - 1; //mbedtls ecdh starts reading one pos before
                    pubkey_len = tag_len + 1;
                }
            }
            file_t *fkey = search_file(EF_KEY_DEV);
            if (!fkey) {
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdsa_context ectx;
            mbedtls_ecdsa_init(&ectx);
            r = load_private_key_ecdsa(&ectx, fkey);
            if (r != PICOKEY_OK) {
                mbedtls_ecdsa_free(&ectx);
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdh_context ctx;
            mbedtls_ecdh_init(&ctx);
            mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_SECP256R1;
            r = mbedtls_ecdh_setup(&ctx, gid);
            if (r != 0) {
                mbedtls_ecdsa_free(&ectx);
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_mpi_copy(&ctx.ctx.mbed_ecdh.d, &ectx.d);
            mbedtls_ecdsa_free(&ectx);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecdh_read_public(&ctx, pubkey, pubkey_len);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            uint8_t derived[MBEDTLS_ECP_MAX_BYTES];
            r = mbedtls_ecdh_calc_secret(&ctx,
                                         &olen,
                                         derived,
                                         MBEDTLS_ECP_MAX_BYTES,
                                         random_gen,
                                         NULL);
            mbedtls_ecdh_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }

            sm_derive_all_keys(derived, olen);

            uint8_t *t = (uint8_t *) calloc(1, pubkey_len + 16);
            memcpy(t, "\x7F\x49\x4F\x06\x0A", 5);
            if (sm_get_protocol() == MSE_AES) {
                memcpy(t + 5, OID_ID_CA_ECDH_AES_CBC_CMAC_128, 10);
            }
            t[15] = 0x86;
            memcpy(t + 16, pubkey, pubkey_len);

            res_APDU[res_APDU_size++] = 0x7C;
            res_APDU[res_APDU_size++] = 20;
            res_APDU[res_APDU_size++] = 0x81;
            res_APDU[res_APDU_size++] = 8;
            memcpy(res_APDU + res_APDU_size, sm_get_nonce(), 8);
            res_APDU_size += 8;
            res_APDU[res_APDU_size++] = 0x82;
            res_APDU[res_APDU_size++] = 8;

            r = sm_sign(t, pubkey_len + 16, res_APDU + res_APDU_size);

            free(t);
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size += 8;
        }
    }
    return SW_OK();
}
