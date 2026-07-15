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
#include "files.h"
#include "cvc.h"
#include "tlv.h"

extern PUK *current_puk;

static int verify_puk_enrollment(const uint8_t *data, uint16_t data_len) {
    if (!current_puk || data_len == 0) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    const uint8_t *cert = data;
    uint16_t cert_len = data_len;
    uint8_t *wrapped = NULL;
    if (data_len < 2 || data[0] != 0x7f || data[1] != 0x21) {
        uint8_t len_len = tlv_format_len(data_len, NULL);
        cert_len = (uint16_t)(2 + len_len + data_len);
        wrapped = (uint8_t *) calloc(1, cert_len);
        if (!wrapped) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
        wrapped[0] = 0x7f;
        wrapped[1] = 0x21;
        tlv_format_len(data_len, wrapped + 2);
        memcpy(wrapped + 2 + len_len, data, data_len);
        cert = wrapped;
    }

    int r = cvc_verify(cert, cert_len, current_puk->cvcert, current_puk->cvcert_len);
    free(wrapped);
    return r;
}

int cmd_puk_auth(void) {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    file_t *ef_puk = file_search(EF_PUKAUT);
    if (!file_has_data(ef_puk)) {
        if (apdu.nc > 0) {
            return SW_FILE_NOT_FOUND();
        }
        return SW_INCORRECT_P1P2();
    }
    uint8_t *puk_data = file_get_data(ef_puk);
    if (apdu.nc > 0) {
        if (p1 == 0x0 || p1 == 0x1) {
            if (verify_puk_enrollment(apdu.data, (uint16_t)apdu.nc) != PICOKEYS_OK) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            file_t *ef = NULL;
            if (p1 == 0x0) { /* Add */
                if (p2 != 0x0) {
                    return SW_INCORRECT_P1P2();
                }
                for (uint8_t i = 0; i < puk_data[0]; i++) {
                    ef = file_search(EF_PUK + i);
                    if (!ef) { /* Never should not happen */
                        return SW_MEMORY_FAILURE();
                    }
                    if (!file_has_data(ef)) { /* found first empty slot */
                        break;
                    }
                }
                if (!ef || file_has_data(ef)) {
                    return SW_FILE_FULL();
                }
                uint8_t *tmp = (uint8_t *) calloc(file_get_size(ef_puk), sizeof(uint8_t));
                memcpy(tmp, puk_data, file_get_size(ef_puk));
                tmp[1] = puk_data[1] - 1;
                file_put_data(ef_puk, tmp, file_get_size(ef_puk));
                puk_data = file_get_data(ef_puk);
                free(tmp);
            }
            else if (p1 == 0x1) {   /* Replace */
                if (!isUserAuthenticated || !(get_device_options() & HSM_OPT_REPLACE_PKA)) {
                    return SW_SECURITY_STATUS_NOT_SATISFIED();
                }
                if (p2 >= puk_data[0]) {
                    return SW_INCORRECT_P1P2();
                }
                ef = file_search(EF_PUK + p2);
                if (!ef) { /* Never should not happen */
                    return SW_MEMORY_FAILURE();
                }
            }
            file_put_data(ef, apdu.data, (uint16_t)apdu.nc);
            flash_commit();
        }
        else {
            return SW_INCORRECT_P1P2();
        }
    }
    if (p1 == 0x2) {
        if (p2 >= puk_data[0]) {
            return SW_INCORRECT_P1P2();
        }
        file_t *ef = file_search(EF_PUK + p2);
        if (!ef) {
            return SW_INCORRECT_P1P2();
        }
        if (!file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint16_t chr_len = 0;
        const uint8_t *chr = cvc_get_chr(file_get_data(ef), file_get_size(ef), &chr_len);
        if (chr) {
            memcpy(res_APDU, chr, chr_len);
            res_APDU_size = chr_len;
        }
        return set_res_sw(0x90, puk_status[p2]);
    }
    else {
        memcpy(res_APDU, puk_data, 3);
        res_APDU[3] = 0;
        for (int i = 0; i < puk_data[0]; i++) {
            res_APDU[3] += puk_status[i];
        }
        res_APDU_size = 4;
    }
    return SW_OK();
}
