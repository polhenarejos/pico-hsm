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
#include "files.h"
#include "cvc.h"

int cmd_puk_auth()
{
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    file_t *ef_puk = search_by_fid(EF_PUKAUT, NULL, SPECIFY_EF);
    if (!file_has_data(ef_puk)) {
        return SW_FILE_NOT_FOUND();
    }
    uint8_t *puk_data = file_get_data(ef_puk);
    if (apdu.nc > 0) {
        if (p1 == 0x0 || p1 == 0x1) {
            file_t *ef = NULL;
            if (p1 == 0x0) { /* Add */
                if (p2 != 0x0) {
                    return SW_INCORRECT_P1P2();
                }
                for (int i = 0; i < puk_data[0]; i++) {
                    ef = search_dynamic_file(EF_PUK+i);
                    if (!ef) { /* Never should not happen */
                        return SW_MEMORY_FAILURE();
                    }
                    if (!file_has_data(ef)) { /* found first empty slot */
                        break;
                    }
                }
                uint8_t *tmp = (uint8_t *) calloc(file_get_size(ef_puk), sizeof(uint8_t));
                memcpy(tmp, puk_data, file_get_size(ef_puk));
                tmp[1] = puk_data[1]-1;
                flash_write_data_to_file(ef_puk, tmp, file_get_size(ef_puk));
                puk_data = file_get_data(ef_puk);
                free(tmp);
            } else if (p1 == 0x1) { /* Replace */
                if (p2 >= puk_data[0]) {
                    return SW_INCORRECT_P1P2();
                }
                ef = search_dynamic_file(EF_PUK+p2);
                if (!ef) { /* Never should not happen */
                    return SW_MEMORY_FAILURE();
                }
            }
            flash_write_data_to_file(ef, apdu.data, apdu.nc);
            low_flash_available();
        } else {
            return SW_INCORRECT_P1P2();
        }
    }
    if (p1 == 0x2) {
        if (p2 >= puk_data[0]) {
            return SW_INCORRECT_P1P2();
        }
        file_t *ef = search_dynamic_file(EF_PUK+p2);
        if (!ef) {
            return SW_INCORRECT_P1P2();
        }
        if (!file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        size_t chr_len = 0;
        const uint8_t *chr = cvc_get_chr(file_get_data(ef), file_get_size(ef), &chr_len);
        if (chr) {
            memcpy(res_APDU, chr, chr_len);
            res_APDU_size = chr_len;
        }
        return set_res_sw(0x90, puk_status[p2]);
    } else {
        memcpy(res_APDU, puk_data, 3);
        res_APDU[3] = 0;
        for (int i = 0; i < puk_data[0]; i++) {
            res_APDU[3] += puk_status[i];
        }
        res_APDU_size = 4;
    }
    return SW_OK();
}
