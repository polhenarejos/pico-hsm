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
#include "random.h"
#include "kek.h"
#include "version.h"
#include "asn1.h"

extern void scan_all();

extern char __StackLimit;
int heapLeft() {
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
    return left;
}

int cmd_initialize() {
    if (apdu.nc > 0) {
        initialize_flash(true);
        scan_all();
        has_session_pin = has_session_sopin = false;
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL, *kds = NULL, *dkeks = NULL;
        size_t tag_len = 0;    
        while (walk_tlv(apdu.data, apdu.nc, &p, &tag, &tag_len, &tag_data)) {
            if (tag == 0x80) { //options
                file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
                flash_write_data_to_file(tf, tag_data, tag_len);
            }
            else if (tag == 0x81) { //user pin
                if (file_pin1 && file_pin1->data) {
                    uint8_t dhash[33];
                    dhash[0] = tag_len;
                    double_hash_pin(tag_data, tag_len, dhash+1);
                    flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_pin);
                    has_session_pin = true;
                }
            }
            else if (tag == 0x82) { //sopin pin
                if (file_sopin && file_sopin->data) {
                    uint8_t dhash[33];
                    dhash[0] = tag_len;
                    double_hash_pin(tag_data, tag_len, dhash+1);
                    flash_write_data_to_file(file_sopin, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_sopin);
                    has_session_sopin = true;
                }
            }
            else if (tag == 0x91) { //retries user pin
                file_t *tf = search_by_fid(0x1082, NULL, SPECIFY_EF);
                if (tf && tf->data) {
                    flash_write_data_to_file(tf, tag_data, tag_len);
                }
                if (file_retries_pin1 && file_retries_pin1->data) {
                    flash_write_data_to_file(file_retries_pin1, tag_data, tag_len);
                }
            }
            else if (tag == 0x92) {
                dkeks = tag_data;
                file_t *tf = file_new(EF_DKEK);
                if (!tf)
                    return SW_MEMORY_FAILURE();
                flash_write_data_to_file(tf, NULL, 0);
            }
            else if (tag == 0x93) {
                file_t *ef_puk = search_by_fid(EF_PUKAUT, NULL, SPECIFY_EF);
                if (!ef_puk)
                    return SW_MEMORY_FAILURE();
                uint8_t pk_status[4], puks = MIN(tag_data[0],MAX_PUK);
                memset(pk_status, 0, sizeof(pk_status));
                pk_status[0] = puks;
                pk_status[1] = puks;
                pk_status[2] = tag_data[1];
                flash_write_data_to_file(ef_puk, pk_status, sizeof(pk_status));
                for (int i = 0; i < puks; i++) {
                    file_t *tf = file_new(EF_PUK+i);
                    if (!tf)
                        return SW_MEMORY_FAILURE();
                    flash_write_data_to_file(tf, NULL, 0);
                }
            }
            else if (tag == 0x97) {
                kds = tag_data;
                /*
                for (int i = 0; i < MIN(*kds,MAX_KEY_DOMAINS); i++) {
                    file_t *tf = file_new(EF_DKEK+i);
                    if (!tf)
                        return SW_MEMORY_FAILURE();
                    flash_write_data_to_file(tf, NULL, 0);
                }
                */
            }
        }
        file_t *tf_kd = search_by_fid(EF_KEY_DOMAIN, NULL, SPECIFY_EF);
        if (!tf_kd)
            return SW_EXEC_ERROR();
        if (store_mkek(NULL) != CCID_OK)
            return SW_EXEC_ERROR();
        if (dkeks) {
            if (*dkeks > 0) {
                uint16_t d = *dkeks;
                if (flash_write_data_to_file(tf_kd, (const uint8_t *)&d, sizeof(d)) != CCID_OK)
                    return SW_EXEC_ERROR();
            }
            else {
                int r = save_dkek_key(0, random_bytes_get(32));
                if (r != CCID_OK)
                    return SW_EXEC_ERROR();
                uint16_t d = 0x0101;
                if (flash_write_data_to_file(tf_kd, (const uint8_t *)&d, sizeof(d)) != CCID_OK)
                    return SW_EXEC_ERROR();
            }
        }
        else {
            uint16_t d = 0x0000;
            if (flash_write_data_to_file(tf_kd, (const uint8_t *)&d, sizeof(d)) != CCID_OK)
                return SW_EXEC_ERROR();
        }
        if (kds) {
            uint8_t t[MAX_KEY_DOMAINS*2], k = MIN(*kds,MAX_KEY_DOMAINS);
            memset(t, 0xff, 2*k);
            if (flash_write_data_to_file(tf_kd, t, 2*k) != CCID_OK)
                return SW_EXEC_ERROR();
        }
        /* When initialized, it has all credentials */
        isUserAuthenticated = true;
        low_flash_available();
    }
    else { //free memory bytes request
        int heap_left = heapLeft();
        res_APDU[0] = ((heap_left >> 24) & 0xff);
        res_APDU[1] = ((heap_left >> 16) & 0xff);
        res_APDU[2] = ((heap_left >> 8) & 0xff);
        res_APDU[3] = ((heap_left >> 0) & 0xff);
        res_APDU[4] = 0;
        res_APDU[5] = HSM_VERSION_MAJOR;
        res_APDU[6] = HSM_VERSION_MINOR;
        res_APDU_size = 7;
    }
    return SW_OK();
}