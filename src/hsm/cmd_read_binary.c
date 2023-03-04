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

int cmd_read_binary() {
    uint16_t fid = 0x0;
    uint32_t offset = 0;
    uint8_t ins = INS(apdu), p1 = P1(apdu), p2 = P2(apdu);
    const file_t *ef = NULL;

    if ((ins & 0x1) == 0) {
        if ((p1 & 0x80) != 0) {
            if (!(ef = search_by_fid(p1 & 0x1f, NULL, SPECIFY_EF))) {
                return SW_FILE_NOT_FOUND();
            }
            offset = p2;
        }
        else {
            offset = make_uint16_t(p1, p2) & 0x7fff;
            ef = currentEF;
        }
    }
    else {
        if (p1 == 0 && (p2 & 0xE0) == 0 && (p2 & 0x1f) != 0 && (p2 & 0x1f) != 0x1f) {
            if (!(ef = search_by_fid(p2 & 0x1f, NULL, SPECIFY_EF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else {
            uint16_t file_id = make_uint16_t(p1, p2); // & 0x7fff;
            if (file_id == 0x0) {
                ef = currentEF;
            }
            else if (!(ef =
                           search_by_fid(file_id, NULL,
                                         SPECIFY_EF)) && !(ef = search_dynamic_file(file_id))) {
                return SW_FILE_NOT_FOUND();
            }

            if (apdu.data[0] != 0x54) {
                return SW_WRONG_DATA();
            }

            offset = 0;
            for (int d = 0; d < apdu.data[1]; d++) {
                offset |= apdu.data[2 + d] << (apdu.data[1] - 1 - d) * 8;
            }
        }
    }

    if ((fid >> 8) == KEY_PREFIX || !authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            uint16_t data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *) ef, 1); //already copies content to res_APDU
            if (offset > data_len) {
                return SW_WRONG_P1P2();
            }
            uint16_t maxle = data_len - offset;
            if (apdu.ne > maxle) {
                apdu.ne = maxle;
            }
            if (offset) {
                memmove(res_APDU, res_APDU + offset, res_APDU_size - offset);
                //res_APDU += offset;
                res_APDU_size -= offset;
            }
        }
        else {
            uint16_t data_len = file_get_size(ef);
            if (offset > data_len) {
                return SW_WRONG_P1P2();
            }

            uint16_t maxle = data_len - offset;
            if (apdu.ne > maxle) {
                apdu.ne = maxle;
            }
            memcpy(res_APDU, file_get_data(ef) + offset, data_len - offset);
            res_APDU_size = data_len - offset;
        }
    }

    return SW_OK();
}
