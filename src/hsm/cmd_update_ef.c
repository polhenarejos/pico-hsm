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
#include "tlv.h"

int cmd_update_ef(void) {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    uint16_t fid = (p1 << 8) | p2;
    uint8_t *data = NULL;
    uint32_t offset = 0;
    uint32_t data_len = 0;
    file_t *ef = NULL;

    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == 0x0) {
        ef = currentEF;
    }
    else {
        ef = file_search(fid);
    }
    /*
       // This should not happen
       else if (p1 != EE_CERTIFICATE_PREFIX && p1 != PRKD_PREFIX && p1 != CA_CERTIFICATE_PREFIX &&
             p1 != CD_PREFIX && p1 != DATA_PREFIX && p1 != DCOD_PREFIX &&
             p1 != PROT_DATA_PREFIX) {
        return SW_INCORRECT_P1P2();
       }
     */

    if (ef && !file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0;
    tlv_ctx_t ctxi;
    tlv_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    while (tlv_walk(&ctxi, &p, &tag, &tag_len, &tag_data)) {
        if (tag == 0x54) { // Offset data object.
            if (tag_len > sizeof(offset)) {
                return SW_WRONG_DATA();
            }
            for (size_t i = 0; i < tag_len; i++) {
                offset = (offset << 8) | *tag_data++;
            }
        }
        else if (tag == 0x53) { // Data object.
            data_len = tag_len;
            data = tag_data;
        }
    }
    if (data_len == 0 && offset == 0) { //new file
        ef = file_new(fid);
        //if ((fid & 0xff00) == (EE_CERTIFICATE_PREFIX << 8))
        //    add_file_to_chain(ef, &ef_pukdf);
        select_file(ef);
    }
    else {
        if (fid == 0x0 && !ef) {
            return SW_FILE_NOT_FOUND();
        }
        else if (fid != 0x0 && !ef) {                           //if does not exist, create it
            //return SW_FILE_NOT_FOUND();
            ef = file_new(fid);
        }
        if (offset == 0) {
            int r = file_put_data(ef, data, data_len);
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
        }
        else {
            if (!file_has_data(ef)) {
                return SW_DATA_INVALID();
            }
            if (offset > UINT32_MAX - data_len) {
                return SW_WRONG_LENGTH();
            }
            int r = file_put_data_offset(ef, data, data_len, offset);
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
        }
        flash_commit();
    }
    return SW_OK();
}
