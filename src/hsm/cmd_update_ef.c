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
#include "asn1.h"

extern void select_file(file_t *pe);

int cmd_update_ef() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    uint16_t fid = (p1 << 8) | p2;
    uint8_t *data = NULL;
    uint16_t offset = 0;
    uint16_t data_len = 0;
    file_t *ef = NULL;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (fid == 0x0)
        ef = currentEF;
    else if (p1 != EE_CERTIFICATE_PREFIX && p1 != PRKD_PREFIX && p1 != CA_CERTIFICATE_PREFIX && p1 != CD_PREFIX && p1 != DATA_PREFIX && p1 != DCOD_PREFIX && p1 != PROT_DATA_PREFIX)
        return SW_INCORRECT_P1P2();
        
    if (ef && !authenticate_action(ef, ACL_OP_UPDATE_ERASE))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
        
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    size_t tag_len = 0;    
    while (walk_tlv(apdu.data, apdu.nc, &p, &tag, &tag_len, &tag_data)) {
        if (tag == 0x54) { //ofset tag
            for (int i = 1; i <= tag_len; i++)
                offset |= (*tag_data++ << (8*(tag_len-i)));
        }
        else if (tag == 0x53) { //data 
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
        if (fid == 0x0 && !ef)
            return SW_FILE_NOT_FOUND();
        else if (fid != 0x0 && !(ef = search_by_fid(fid, NULL, SPECIFY_EF)) && !(ef = search_dynamic_file(fid))) { //if does not exist, create it
            //return SW_FILE_NOT_FOUND();
            ef = file_new(fid);
        }
        if (offset == 0) {
            int r = flash_write_data_to_file(ef, data, data_len);
            if (r != CCID_OK)
                return SW_MEMORY_FAILURE();
        }
        else {
            if (!ef->data)
                return SW_DATA_INVALID();
 
            uint8_t *data_merge = (uint8_t *)calloc(1, offset+data_len);
            memcpy(data_merge, file_get_data(ef), offset);
            memcpy(data_merge+offset, data, data_len);
            int r = flash_write_data_to_file(ef, data_merge, offset+data_len);
            free(data_merge);
            if (r != CCID_OK)
                return SW_MEMORY_FAILURE();
        }
        low_flash_available();
    }
    return SW_OK(); 
}