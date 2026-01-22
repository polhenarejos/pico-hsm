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
#include "files.h"
#include "random.h"
#include "kek.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/chachapoly.h"
#ifdef PICO_RP2350
#include "otp.h"
#endif

#define CMD_DATETIME 0xA
#define CMD_DYNOPS 0x6
#define CMD_SECURE_LOCK 0x3A
#define CMD_REBOOT 0xFB
#define SECURE_LOCK_KEY_AGREEMENT 0x1
#define SECURE_LOCK_ENABLE 0x2
#define SECURE_LOCK_MASK 0x3
#define SECURE_LOCK_DISABLE 0x4
#define CMD_PHY 0x1B
#define CMD_OTP 0x4C
#define CMD_MEMORY 0x5

int cmd_extras() {
    int cmd = P1(apdu);
#ifndef ENABLE_EMULATION
    // Only allow change PHY without PIN
    if (!isUserAuthenticated && cmd != CMD_PHY && cmd != CMD_MEMORY) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
#endif
    //check button (if enabled)
    if (wait_button_pressed() == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    if (cmd == CMD_DYNOPS) {   //dynamic options
        if (P2(apdu) != 0x0) {
            return SW_INCORRECT_P1P2();
        }
        if (apdu.nc > sizeof(uint8_t)) {
            return SW_WRONG_LENGTH();
        }
        uint16_t opts = get_device_options();
        if (apdu.nc == 0) {
            res_APDU_size += put_uint16_t_be(opts, res_APDU);
        }
        else {
            uint8_t newopts[] = { apdu.data[0], (opts & 0xff) };
            file_t *tf = search_file(EF_DEVOPS);
            file_put_data(tf, newopts, sizeof(newopts));
            low_flash_available();
        }
    }
    else if (cmd == CMD_SECURE_LOCK) {   // secure lock
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
        if (P2(apdu) == SECURE_LOCK_KEY_AGREEMENT) { // Key Agreement
            mbedtls_ecdh_context hkey;
            mbedtls_ecdh_init(&hkey);
            mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_gen, NULL);
            mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            ret = mbedtls_ecp_point_read_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Qp, apdu.data, apdu.nc);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                return SW_WRONG_DATA();
            }
            memcpy(mse.Qpt, apdu.data, sizeof(mse.Qpt));

            uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
            size_t olen = 0;
            ret = mbedtls_ecdh_calc_secret(&hkey, &olen, buf, MBEDTLS_ECP_MAX_BYTES, random_gen, NULL);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                mbedtls_platform_zeroize(buf, sizeof(buf));
                return SW_WRONG_DATA();
            }
            ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, buf, olen, mse.Qpt, sizeof(mse.Qpt), mse.key_enc, sizeof(mse.key_enc));
            mbedtls_platform_zeroize(buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                return SW_EXEC_ERROR();
            }

            ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, res_APDU, MAX_APDU_DATA);
            mbedtls_ecdh_free(&hkey);
            if (ret != 0) {
                return SW_EXEC_ERROR();
            }
            mse.init = true;
            res_APDU_size = (uint16_t)olen;
        }
        else if (P2(apdu) == SECURE_LOCK_ENABLE || P2(apdu) == SECURE_LOCK_MASK || P2(apdu) == SECURE_LOCK_DISABLE) {
            if (mse.init == false) {
                return SW_COMMAND_NOT_ALLOWED();
            }
            uint16_t opts = get_device_options();
            int ret = mse_decrypt_ct(apdu.data, apdu.nc);
            if (ret != 0) {
                return SW_WRONG_DATA();
            }
            if (P2(apdu) == SECURE_LOCK_ENABLE || P2(apdu) == SECURE_LOCK_DISABLE) { // Enable
                uint8_t newopts[] = { opts >> 8, (opts & 0xff) };
                if ((P2(apdu) == SECURE_LOCK_ENABLE && !(opts & HSM_OPT_SECURE_LOCK)) ||
                    (P2(apdu) == SECURE_LOCK_DISABLE && (opts & HSM_OPT_SECURE_LOCK))) {
                    uint16_t tfids[] = { EF_MKEK, EF_MKEK_SO };
                    for (int t = 0; t < sizeof(tfids) / sizeof(uint16_t); t++) {
                        file_t *tf = search_file(tfids[t]);
                        if (tf) {
                            uint8_t *tmp = (uint8_t *) calloc(1, file_get_size(tf));
                            memcpy(tmp, file_get_data(tf), file_get_size(tf));
                            for (int i = 0; i < MKEK_KEY_SIZE; i++) {
                                MKEK_KEY(tmp)[i] ^= apdu.data[i];
                            }
                            file_put_data(tf, tmp, file_get_size(tf));
                            free(tmp);
                        }
                    }
                }
                if (P2(apdu) == SECURE_LOCK_ENABLE) {
                    newopts[0] |= HSM_OPT_SECURE_LOCK >> 8;
                }
                else if (P2(apdu) == SECURE_LOCK_DISABLE) {
                    newopts[0] &= ~HSM_OPT_SECURE_LOCK >> 8;
                }
                file_t *tf = search_file(EF_DEVOPS);
                file_put_data(tf, newopts, sizeof(newopts));
                low_flash_available();
            }
            else if (P2(apdu) == SECURE_LOCK_MASK && (opts & HSM_OPT_SECURE_LOCK)) {
                memcpy(mkek_mask, apdu.data, MKEK_KEY_SIZE);
                has_mkek_mask = true;
            }
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}
