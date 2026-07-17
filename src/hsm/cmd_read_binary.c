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
#include "key_container.h"

typedef int (*file_data_handler_t)(const file_t *f, int mode);

static bool hsm_container_object_target(uint16_t fid, uint16_t *object_type) {
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | (fid & 0xff));
    return hsm_key_container_fid_object(fid, object_type) && hsm_key_container_is_marker(marker);
}

static int hsm_read_container_object(uint16_t fid, uint16_t object_type, uint32_t offset) {
    uint32_t object_size = 0;
    int r = hsm_key_container_object_size((uint8_t)fid, object_type, false, &object_size);
    if (r == PICOKEYS_NO_LOGIN) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (r != PICOKEYS_OK) {
        return SW_FILE_NOT_FOUND();
    }
    if (offset > object_size) {
        return SW_WARNING_EOF();
    }

    uint8_t *object_data = NULL;
    if (object_size > 0) {
        object_data = (uint8_t *)calloc(1, object_size);
        if (!object_data) {
            return SW_MEMORY_FAILURE();
        }
    }
    size_t written = 0;
    r = hsm_key_container_read((uint8_t)fid, object_type, FILE_OBJECT_OPERATION_READ, false, object_data, object_size, &written);
    if (r != PICOKEYS_OK || written != object_size) {
        free(object_data);
        return r == PICOKEYS_NO_LOGIN ? SW_SECURITY_STATUS_NOT_SATISFIED() : SW_EXEC_ERROR();
    }
    uint32_t response_len = object_size - offset;
    if (apdu.ne > 0) {
        response_len = MIN(response_len, apdu.ne);
    }
    response_len = MIN(response_len, (uint32_t)MAX_APDU_DATA);
    if (response_len > 0) {
        memcpy(res_APDU, object_data + offset, response_len);
    }
    res_APDU_size = (uint16_t)response_len;
    free(object_data);
    return SW_OK();
}

int cmd_read_binary(void) {
    uint32_t offset = 0;
    uint8_t ins = INS(apdu), p1 = P1(apdu), p2 = P2(apdu);
    file_t *ef = NULL;
    uint16_t logical_fid = 0;

    if ((ins & 0x1) == 0) {
        if ((p1 & 0x80) != 0) {
            if (!(ef = file_search(p1 & 0x1f))) {
                return SW_FILE_NOT_FOUND();
            }
            logical_fid = ef->fid;
            offset = p2;
        }
        else {
            offset = make_uint16_be(p1, p2) & 0x7fff;
            ef = currentEF;
            logical_fid = ef ? ef->fid : 0;
        }
    }
    else {
        if (p1 == 0 && (p2 & 0xE0) == 0 && (p2 & 0x1f) != 0 && (p2 & 0x1f) != 0x1f) {
            if (!(ef = file_search(p2 & 0x1f))) {
                return SW_FILE_NOT_FOUND();
            }
            logical_fid = ef->fid;
        }
        else {
            uint16_t file_id = make_uint16_be(p1, p2); // & 0x7fff;
            if (file_id == 0x0) {
                ef = currentEF;
                logical_fid = ef ? ef->fid : 0;
            }
            else {
                logical_fid = file_id;
            }

            if (apdu.nc < 2 || apdu.data[0] != 0x54 || apdu.data[1] > sizeof(offset) || apdu.nc < (uint32_t)apdu.data[1] + 2) {
                return SW_WRONG_DATA();
            }
            offset = 0;
            for (size_t d = 0; d < apdu.data[1]; d++) {
                offset = (offset << 8) | apdu.data[2 + d];
            }
            if (hsm_key_container_physical_fid(logical_fid)) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            uint16_t object_type = 0;
            if (hsm_container_object_target(logical_fid, &object_type)) {
                return hsm_read_container_object(logical_fid, object_type, offset);
            }
            if (!ef && logical_fid != 0 && !(ef = file_search(logical_fid))) {
                return SW_FILE_NOT_FOUND();
            }
        }
    }

    uint16_t object_type = 0;
    if (hsm_container_object_target(logical_fid, &object_type)) {
        return hsm_read_container_object(logical_fid, object_type, offset);
    }

    if (ef == NULL) {
        return SW_FILE_NOT_FOUND();
    }

    if ((ef->fid >> 8) == KEY_PREFIX || (ef->fid >> 8) == HSM_OBJECT_PREFIX || hsm_key_container_physical_fid(ef->fid) || ((ef->fid >> 8) == PROT_DATA_PREFIX && !isUserAuthenticated) || !file_authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        if ((file_get_type(ef) & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            union {
                uint8_t *data;
                file_data_handler_t handler;
            } data_func = { .data = ef->data };
            uint16_t data_len = (uint16_t)data_func.handler((const file_t *) ef, 1); //already copies content to res_APDU
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
            uint32_t data_len = file_get_size(ef);
            if (offset > data_len) {
                return SW_WARNING_EOF();
            }
            uint32_t response_len = data_len - offset;
            if (apdu.ne > 0) {
                response_len = MIN(response_len, apdu.ne);
            }
            response_len = MIN(response_len, (uint32_t)MAX_APDU_DATA);
            if (file_read_at(ef, offset, res_APDU, response_len) != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = (uint16_t)response_len;
        }
    }

    return SW_OK();
}
