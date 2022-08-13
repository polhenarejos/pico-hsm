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

int cmd_list_keys()
{
    //first CC
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (PRKD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = PRKD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
            res_APDU[res_APDU_size++] = KEY_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    //second CD
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (CD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = CD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (DCOD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = DCOD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    return SW_OK();
}
