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
#include "key_container.h"
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
        logical_fid = ef->fid;
    }
    else {
        logical_fid = get_uint16_be(apdu.data);
        if ((logical_fid >> 8) == HSM_OBJECT_PREFIX || hsm_key_container_physical_fid(logical_fid)) {
            return SW_FILE_NOT_FOUND();
        }
    }

    uint16_t object_type = 0;
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | (logical_fid & 0xff));
    if (hsm_key_container_fid_object(logical_fid, &object_type) && hsm_key_container_is_marker(marker)) {
        int r = hsm_key_container_remove_object((uint8_t)logical_fid, object_type);
        if (r == PICOKEYS_NO_LOGIN) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        return r == PICOKEYS_OK ? SW_OK() : SW_FILE_NOT_FOUND();
    }

    ef = (logical_fid >> 8) == KEY_PREFIX ? hsm_key_search(logical_fid & 0xff) : file_search(logical_fid);
    if (!ef) {
        return SW_FILE_NOT_FOUND();
    }
    logical_fid = hsm_key_logical_fid(ef);
    if (!file_authenticate_action(ef, ACL_OP_DELETE_SELF)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (logical_fid == EF_KEY_DEV) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((ef->fid >> 8) == HSM_OBJECT_PREFIX) {
        bool container = hsm_key_container_is_marker(ef);
        const file_object_id_t object_id = { .namespace_id = HSM_OBJECT_NAMESPACE, .object_type = HSM_OBJECT_KEY_MATERIAL, .fid = ef->fid };
        int r = container ? hsm_key_container_detach_sidecars((uint8_t)ef->fid) : PICOKEYS_OK;
        if (r == PICOKEYS_OK) {
            r = meta_delete_no_commit(logical_fid);
        }
        if (r == PICOKEYS_OK) {
            r = container ? hsm_key_container_delete((uint8_t)ef->fid) : file_object_delete_no_commit(&object_id);
        }
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        if (!container) {
            flash_commit();
        }
    }
    else if (file_delete(ef) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}
