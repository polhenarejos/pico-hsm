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

#include "common.h"
#include "mbedtls/ecdh.h"
#include "sc_hsm.h"
#ifndef ENABLE_EMULATION
#include "hardware/rtc.h"
#endif
#include "files.h"
#include "random.h"
#include "kek.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/chachapoly.h"

int cmd_extras() {
    if (P1(apdu) == 0xA) { //datetime operations
        if (P2(apdu) != 0x0) {
            return SW_INCORRECT_P1P2();
        }
        if (apdu.nc == 0) {
#ifndef ENABLE_EMULATION
            datetime_t dt;
            if (!rtc_get_datetime(&dt)) {
                return SW_EXEC_ERROR();
            }
            res_APDU[res_APDU_size++] = dt.year >> 8;
            res_APDU[res_APDU_size++] = dt.year & 0xff;
            res_APDU[res_APDU_size++] = dt.month;
            res_APDU[res_APDU_size++] = dt.day;
            res_APDU[res_APDU_size++] = dt.dotw;
            res_APDU[res_APDU_size++] = dt.hour;
            res_APDU[res_APDU_size++] = dt.min;
            res_APDU[res_APDU_size++] = dt.sec;
#endif
        }
        else {
            if (apdu.nc != 8) {
                return SW_WRONG_LENGTH();
            }
#ifndef ENABLE_EMULATION
            datetime_t dt;
            dt.year = (apdu.data[0] << 8) | (apdu.data[1]);
            dt.month = apdu.data[2];
            dt.day = apdu.data[3];
            dt.dotw = apdu.data[4];
            dt.hour = apdu.data[5];
            dt.min = apdu.data[6];
            dt.sec = apdu.data[7];
            if (!rtc_set_datetime(&dt)) {
                return SW_WRONG_DATA();
            }
#endif
        }
    }
    else if (P1(apdu) == 0x6) {   //dynamic options
        if (P2(apdu) != 0x0) {
            return SW_INCORRECT_P1P2();
        }
        if (apdu.nc > sizeof(uint8_t)) {
            return SW_WRONG_LENGTH();
        }
        uint16_t opts = get_device_options();
        if (apdu.nc == 0) {
            res_APDU[res_APDU_size++] = opts >> 8;
            res_APDU[res_APDU_size++] = opts & 0xff;
        }
        else {
            uint8_t newopts[] = { apdu.data[0], (opts & 0xff) };
            file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
            flash_write_data_to_file(tf, newopts, sizeof(newopts));
            low_flash_available();
        }
    }
    else if (P1(apdu) == 0x3A) {   // secure lock
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
        if (P2(apdu) == 0x01) { // Key Agreement
            mbedtls_ecdh_context hkey;
            mbedtls_ecdh_init(&hkey);
            mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp,
                                              &hkey.ctx.mbed_ecdh.d,
                                              &hkey.ctx.mbed_ecdh.Q,
                                              random_gen,
                                              NULL);
            mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            ret = mbedtls_ecp_point_read_binary(&hkey.ctx.mbed_ecdh.grp,
                                                &hkey.ctx.mbed_ecdh.Qp,
                                                apdu.data,
                                                apdu.nc);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                return SW_WRONG_DATA();
            }
            memcpy(mse.Qpt, apdu.data, sizeof(mse.Qpt));

            uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
            size_t olen = 0;
            ret = mbedtls_ecdh_calc_secret(&hkey,
                                           &olen,
                                           buf,
                                           MBEDTLS_ECP_MAX_BYTES,
                                           random_gen,
                                           NULL);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                mbedtls_platform_zeroize(buf, sizeof(buf));
                return SW_WRONG_DATA();
            }
            ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                               NULL,
                               0,
                               buf,
                               olen,
                               mse.Qpt,
                               sizeof(mse.Qpt),
                               mse.key_enc,
                               sizeof(mse.key_enc));
            mbedtls_platform_zeroize(buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                return SW_EXEC_ERROR();
            }

            ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp,
                                                 &hkey.ctx.mbed_ecdh.Q,
                                                 MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen,
                                                 res_APDU,
                                                 4096);
            mbedtls_ecdh_free(&hkey);
            if (ret != 0) {
                return SW_EXEC_ERROR();
            }
            mse.init = true;
            res_APDU_size = olen;
        }
        else if (P2(apdu) == 0x02 || P2(apdu) == 0x03 || P2(apdu) == 0x04) {
            if (mse.init == false) {
                return SW_COMMAND_NOT_ALLOWED();
            }

            int ret = mse_decrypt_ct(apdu.data, apdu.nc);
            if (ret != 0) {
                return SW_WRONG_DATA();
            }
            if (P2(apdu) == 0x02 || P2(apdu) == 0x04) { // Enable
                uint16_t opts = get_device_options();
                uint8_t newopts[] = { opts >> 8, (opts & 0xff) };
                if ((P2(apdu) == 0x02 && !(opts & HSM_OPT_SECURE_LOCK)) ||
                    (P2(apdu) == 0x04 && (opts & HSM_OPT_SECURE_LOCK))) {
                    uint16_t tfids[] = { EF_MKEK, EF_MKEK_SO };
                    for (int t = 0; t < sizeof(tfids) / sizeof(uint16_t); t++) {
                        file_t *tf = search_by_fid(tfids[t], NULL, SPECIFY_EF);
                        if (tf) {
                            uint8_t *tmp = (uint8_t *) calloc(1, file_get_size(tf));
                            memcpy(tmp, file_get_data(tf), file_get_size(tf));
                            for (int i = 0; i < MKEK_KEY_SIZE; i++) {
                                MKEK_KEY(tmp)[i] ^= apdu.data[i];
                            }
                            flash_write_data_to_file(tf, tmp, file_get_size(tf));
                            free(tmp);
                        }
                    }
                }
                if (P2(apdu) == 0x02) {
                    newopts[0] |= HSM_OPT_SECURE_LOCK >> 8;
                }
                else if (P2(apdu) == 0x04) {
                    newopts[0] &= ~HSM_OPT_SECURE_LOCK >> 8;
                }
                file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
                flash_write_data_to_file(tf, newopts, sizeof(newopts));
                low_flash_available();
            }
            else if (P2(apdu) == 0x03) {
                memcpy(mkek_mask, apdu.data, apdu.nc);
                has_mkek_mask = true;
            }
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}
