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

#include "crypto_utils.h"
#include "sc_hsm.h"
#include "cvc.h"
#include "kek.h"
#include "files.h"

uint8_t get_key_domain(file_t *fkey) {
    size_t tag_len = 0;
    const uint8_t *meta_tag = get_meta_tag(fkey, 0x92, &tag_len);
    if (meta_tag) {
        return *meta_tag;
    }
    return 0xff;
}

int cmd_key_domain() {
    //if (dkeks == 0)
    //    return SW_COMMAND_NOT_ALLOWED();
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if ((has_session_pin == false || isUserAuthenticated == false) && apdu.nc > 0 &&
        !(p1 == 0x0 && p2 == 0x0)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (p2 >= MAX_KEY_DOMAINS) {
        return SW_WRONG_P1P2();
    }
    file_t *tf_kd = search_by_fid(EF_KEY_DOMAIN, NULL, SPECIFY_EF);
    if (!tf_kd) {
        return SW_EXEC_ERROR();
    }
    uint16_t tf_kd_size = file_get_size(tf_kd);
    if (tf_kd_size == 0) {
        return SW_WRONG_P1P2();
    }
    uint8_t *kdata = file_get_data(tf_kd), dkeks = kdata ? kdata[2 * p2] : 0,
            current_dkeks = kdata ? kdata[2 * p2 + 1] : 0;
    if (p1 == 0x0) { //dkek import
        if (apdu.nc > 0) {
            file_t *tf = file_new(EF_DKEK + p2);
            if (!tf) {
                return SW_MEMORY_FAILURE();
            }
            if (apdu.nc < 32) {
                return SW_WRONG_LENGTH();
            }
            if (current_dkeks == dkeks) {
                return SW_COMMAND_NOT_ALLOWED();
            }
            import_dkek_share(p2, apdu.data);
            if (++current_dkeks >= dkeks) {
                if (save_dkek_key(p2, NULL) != CCID_OK) {
                    /* On fail, it will return to previous dkek state. */
                    import_dkek_share(p2, apdu.data);
                    return SW_FILE_NOT_FOUND();
                }
            }
            uint8_t t[MAX_KEY_DOMAINS * 2];
            memcpy(t, kdata, tf_kd_size);
            t[2 * p2 + 1] = current_dkeks;
            if (flash_write_data_to_file(tf_kd, t, tf_kd_size) != CCID_OK) {
                return SW_EXEC_ERROR();
            }
            low_flash_available();
        }
        else {
            file_t *tf = search_dynamic_file(EF_XKEK + p2);
            if (2 * p2 >= tf_kd_size) {
                return SW_INCORRECT_P1P2();
            }
            if (current_dkeks == 0xff && !tf) { //XKEK have always 0xff
                return SW_REFERENCE_NOT_FOUND();
            }
        }
    }
    else if (p1 == 0x1 || p1 == 0x3 || p1 == 0x4) {   //key domain setup
        if (p1 == 0x1 && apdu.nc != 1) {
            return SW_WRONG_LENGTH();
        }
        if (p1 == 0x3) { //if key domain is not empty, command is denied
            for (int i = 0; i < dynamic_files; i++) {
                if (get_key_domain(&dynamic_file[i]) == p2) {
                    return SW_FILE_EXISTS();
                }
            }
        }
        uint8_t t[MAX_KEY_DOMAINS * 2];
        memcpy(t, kdata, tf_kd_size);
        if (p1 == 0x1) {
            if (t[2 * p2] != 0xff && t[2 * p2 + 1] != 0xff) {
                return SW_INCORRECT_P1P2();
            }
            t[2 * p2] = dkeks = apdu.data[0];
            t[2 * p2 + 1] = current_dkeks = 0;
        }
        else if (p1 == 0x3) {
            if (t[2 * p2] == 0xff || t[2 * p2 + 1] == 0xff) {
                return SW_INCORRECT_P1P2();
            }
            t[2 * p2] = dkeks = 0xff;
            t[2 * p2 + 1] = 0xff;
        }
        else if (p1 == 0x4) {
            t[2 * p2 + 1] = current_dkeks = 0;
        }
        if (flash_write_data_to_file(tf_kd, t, tf_kd_size) != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        file_t *tf = NULL;
        if ((tf = search_dynamic_file(EF_DKEK + p2))) {
            if (delete_file(tf) != CCID_OK) {
                return SW_EXEC_ERROR();
            }
        }
        if (p1 == 0x3 && (tf = search_dynamic_file(EF_XKEK + p2))) {
            if (delete_file(tf) != CCID_OK) {
                return SW_EXEC_ERROR();
            }
        }
        low_flash_available();
        if (p1 == 0x3) {
            return SW_REFERENCE_NOT_FOUND();
        }
    }
    else if (p1 == 0x2) {   //XKEK Key Domain creation
        if (apdu.nc > 0) {
            size_t pub_len = 0;
            file_t *fterm = search_by_fid(EF_TERMCA, NULL, SPECIFY_EF);
            if (!fterm) {
                return SW_EXEC_ERROR();
            }
            const uint8_t *pub = cvc_get_pub(file_get_data(fterm), file_get_size(fterm), &pub_len);
            if (!pub) {
                return SW_EXEC_ERROR();
            }
            size_t t86_len = 0;
            const uint8_t *t86 = cvc_get_field(pub, pub_len, &t86_len, 0x86);
            if (!t86 || t86[0] != 0x4) {
                return SW_EXEC_ERROR();
            }
            size_t t54_len = 0;
            const uint8_t *t54 = cvc_get_field(apdu.data, apdu.nc, &t54_len, 0x54);
            if (!t54) {
                return SW_WRONG_DATA();
            }
            uint8_t hash[32], *input = (uint8_t *) calloc(1, (t86_len - 1) / 2 + 1);
            input[0] = 0x54;
            memcpy(input + 1, t86 + 1, (t86_len - 1) / 2);
            hash256(input, (t86_len - 1) / 2 + 1, hash);
            free(input);
            int r = puk_verify(t54, t54_len, hash, 32, apdu.data, apdu.nc);
            if (r != 0) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            file_t *tf = file_new(EF_XKEK + p2);
            if (!tf) {
                return SW_MEMORY_FAILURE();
            }

            //All checks done. Get Key Domain UID
            pub = cvc_get_pub(apdu.data, apdu.nc, &pub_len);
            if (pub) {
                size_t t86_len = 0;
                const uint8_t *t86 = cvc_get_field(pub, pub_len, &t86_len, 0x86);
                if (t86) {
                    flash_write_data_to_file(tf, t86 + 1, t86_len - 1);
                    low_flash_available();
                }
            }
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    memset(res_APDU, 0, 10);
    res_APDU[0] = dkeks;
    res_APDU[1] = dkeks > current_dkeks ? dkeks - current_dkeks : 0;
    dkek_kcv(p2, res_APDU + 2);
    res_APDU_size = 2 + 8;
    file_t *tf = search_dynamic_file(EF_XKEK + p2);
    if (tf) {
        memcpy(res_APDU + 10, file_get_data(tf), file_get_size(tf));
        res_APDU_size += file_get_size(tf);
    }
    return SW_OK();
}
