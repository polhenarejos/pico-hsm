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
#ifdef PICO_PLATFORM
#include "pico/aon_timer.h"
#else
#include <sys/time.h>
#include <time.h>
#endif
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
#define SECURE_LOCK_KEY_AGREEMENT 0x1
#define SECURE_LOCK_ENABLE 0x2
#define SECURE_LOCK_MASK 0x3
#define SECURE_LOCK_DISABLE 0x4
#define CMD_PHY 0x1B
#define CMD_OTP 0x4C

int cmd_extras() {
#ifndef ENABLE_EMULATION
    // Only allow change PHY without PIN
    if (!isUserAuthenticated && P1(apdu) != 0x1B) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
#endif
    //check button (if enabled)
    if (wait_button_pressed() == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    if (P1(apdu) == CMD_DATETIME) { //datetime operations
        if (P2(apdu) != 0x0) {
            return SW_INCORRECT_P1P2();
        }
        if (apdu.nc == 0) {
#ifdef PICO_PLATFORM
            struct timespec tv;
            aon_timer_get_time(&tv);
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
#endif
            struct tm *tm = localtime(&tv.tv_sec);
            res_APDU[res_APDU_size++] = (tm->tm_year + 1900) >> 8;
            res_APDU[res_APDU_size++] = (tm->tm_year + 1900) & 0xff;
            res_APDU[res_APDU_size++] = tm->tm_mon;
            res_APDU[res_APDU_size++] = tm->tm_mday;
            res_APDU[res_APDU_size++] = tm->tm_wday;
            res_APDU[res_APDU_size++] = tm->tm_hour;
            res_APDU[res_APDU_size++] = tm->tm_min;
            res_APDU[res_APDU_size++] = tm->tm_sec;
        }
        else {
            if (apdu.nc != 8) {
                return SW_WRONG_LENGTH();
            }
            struct tm tm;
            tm.tm_year = ((apdu.data[0] << 8) | (apdu.data[1])) - 1900;
            tm.tm_mon = apdu.data[2];
            tm.tm_mday = apdu.data[3];
            tm.tm_wday = apdu.data[4];
            tm.tm_hour = apdu.data[5];
            tm.tm_min = apdu.data[6];
            tm.tm_sec = apdu.data[7];
            time_t tv_sec = mktime(&tm);
#ifdef PICO_PLATFORM
            struct timespec tv = {.tv_sec = tv_sec, .tv_nsec = 0};
            aon_timer_set_time(&tv);
#else
            struct timeval tv = {.tv_sec = tv_sec, .tv_usec = 0};
            settimeofday(&tv, NULL);
#endif
        }
    }
    else if (P1(apdu) == CMD_DYNOPS) {   //dynamic options
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
            file_t *tf = search_file(EF_DEVOPS);
            file_put_data(tf, newopts, sizeof(newopts));
            low_flash_available();
        }
    }
    else if (P1(apdu) == CMD_SECURE_LOCK) {   // secure lock
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

            ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, res_APDU, 4096);
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

            int ret = mse_decrypt_ct(apdu.data, apdu.nc);
            if (ret != 0) {
                return SW_WRONG_DATA();
            }
            if (P2(apdu) == SECURE_LOCK_ENABLE || P2(apdu) == SECURE_LOCK_DISABLE) { // Enable
                uint16_t opts = get_device_options();
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
            else if (P2(apdu) == SECURE_LOCK_MASK) {
                memcpy(mkek_mask, apdu.data, apdu.nc);
                has_mkek_mask = true;
            }
        }
    }
#ifndef ENABLE_EMULATION
    else if (P1(apdu) == CMD_PHY) { // Set PHY
        if (apdu.nc == 0) {
            if (file_has_data(ef_phy)) {
                res_APDU_size = file_get_size(ef_phy);
                memcpy(res_APDU, file_get_data(ef_phy), res_APDU_size);
            }
        }
        else {
            uint8_t tmp[PHY_MAX_SIZE];
            memset(tmp, 0, sizeof(tmp));
            uint16_t opts = 0;
            if (file_has_data(ef_phy)) {
                memcpy(tmp, file_get_data(ef_phy), MIN(sizeof(tmp), file_get_size(ef_phy)));
                if (file_get_size(ef_phy) >= 8) {
                    opts = (tmp[PHY_OPTS] << 8) | tmp[PHY_OPTS + 1];
                }
            }
            if (P2(apdu) == PHY_VID) { // VIDPID
                if (apdu.nc != 4) {
                    return SW_WRONG_LENGTH();
                }
                memcpy(tmp + PHY_VID, apdu.data, 4);
                opts |= PHY_OPT_VPID;
            }
            else if (P2(apdu) == PHY_LED_GPIO || P2(apdu) == PHY_LED_BTNESS) {
                if (apdu.nc != 1) {
                    return SW_WRONG_LENGTH();
                }
                tmp[P2(apdu)] = apdu.data[0];
                if (P2(apdu) == PHY_LED_GPIO) {
                    opts |= PHY_OPT_GPIO;
                }
                else if (P2(apdu) == PHY_LED_BTNESS) {
                    opts |= PHY_OPT_BTNESS;
                }
            }
            else if (P2(apdu) == PHY_OPTS) {
                if (apdu.nc != 2) {
                    return SW_WRONG_LENGTH();
                }
                uint16_t opt = (apdu.data[0] << 8) | apdu.data[1];
                opts = (opts & ~PHY_OPT_MASK) | (opt & PHY_OPT_MASK);
            }
            else {
                return SW_INCORRECT_P1P2();
            }
            tmp[PHY_OPTS] = opts >> 8;
            tmp[PHY_OPTS + 1] = opts & 0xff;
            file_put_data(ef_phy, tmp, sizeof(tmp));
            low_flash_available();
        }
    }
#endif
#if PICO_RP2350
    else if (P1(apdu) == CMD_OTP) {
        if (apdu.nc < 2) {
            return SW_WRONG_LENGTH();
        }
        uint16_t row = (apdu.data[0] << 8) | apdu.data[1];
        if (apdu.nc == 2) {
            if (row > 0xbf) {
                return SW_WRONG_DATA();
            }
            memcpy(res_APDU, otp_buffer(row), apdu.ne);
            res_APDU_size = apdu.ne;
        }
        else {
            apdu.nc -= 2;
            apdu.data += 2;
            if (apdu.nc % 2) {
                return SW_WRONG_DATA();
            }
            if ((uintptr_t)apdu.data & 1) { // Not aligned
                memmove(apdu.data - 1, apdu.data, apdu.nc);
                apdu.data--;
            }
            int ret = otp_write_data(row, apdu.data, apdu.nc);
            if (ret != 0) {
                return SW_EXEC_ERROR();
            }
        }
    }
#endif
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}
