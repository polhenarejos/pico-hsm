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

int cmd_delete_file() {
    file_t *ef = NULL;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
        
    if (apdu.nc == 0) {
        ef = currentEF;
        if (!(ef = search_dynamic_file(ef->fid)))
            return SW_FILE_NOT_FOUND();
    }
    else {
        uint16_t fid = (apdu.data[0] << 8) | apdu.data[1];
        if (!(ef = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_DELETE_SELF))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (delete_file(ef) != CCID_OK)
        return SW_EXEC_ERROR();
    return SW_OK();
}
