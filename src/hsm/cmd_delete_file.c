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
#include "object_store.h"

int cmd_delete_file(void) {
    file_t *ef = NULL;
    uint16_t logical_fid = 0;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    if (apdu.nc == 0) {
        ef = currentEF;
        if (!ef) {
            return SW_FILE_NOT_FOUND();
        }
        logical_fid = hsm_key_logical_fid(ef);
        if (!(ef = file_search(ef->fid))) {
            return SW_FILE_NOT_FOUND();
        }
    }
    else {
        logical_fid = get_uint16_be(apdu.data);
        if ((logical_fid >> 8) == HSM_OBJECT_PREFIX) {
            return SW_FILE_NOT_FOUND();
        }
        ef = (logical_fid >> 8) == KEY_PREFIX ? hsm_key_search(logical_fid & 0xff) : file_search(logical_fid);
        if (!ef) {
            return SW_FILE_NOT_FOUND();
        }
    }
    if (!file_authenticate_action(ef, ACL_OP_DELETE_SELF)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (logical_fid == EF_KEY_DEV) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((ef->fid >> 8) == HSM_OBJECT_PREFIX) {
        const file_object_id_t object_id = { .namespace_id = HSM_OBJECT_NAMESPACE, .object_type = HSM_OBJECT_KEY_MATERIAL, .fid = ef->fid };
        if (meta_delete_no_commit(logical_fid) != PICOKEYS_OK || file_object_delete_no_commit(&object_id) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        flash_commit();
    }
    else if (file_delete(ef) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}
