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

int cmd_delete_file() {
    file_t *ef = NULL;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    if (apdu.nc == 0) {
        ef = currentEF;
        if (!(ef = search_file(ef->fid))) {
            return SW_FILE_NOT_FOUND();
        }
    }
    else {
        uint16_t fid = get_uint16_t_be(apdu.data);
        if (!(ef = search_file(fid))) {
            return SW_FILE_NOT_FOUND();
        }
    }
    if (!authenticate_action(ef, ACL_OP_DELETE_SELF)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (delete_file(ef) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}
