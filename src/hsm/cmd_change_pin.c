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
#include "kek.h"

int cmd_change_pin() {
    if (P1(apdu) == 0x0) {
        if (P2(apdu) == 0x81) {
            if (!file_sopin || !file_pin1) {
                return SW_FILE_NOT_FOUND();
            }
            if (!file_pin1->data) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_read_uint8(file_get_data(file_pin1));
            int r = check_pin(file_pin1, apdu.data, pin_len);
            if (r != 0x9000)
                return r;
            uint8_t mkek[MKEK_SIZE];
            r = load_mkek(mkek); //loads the MKEK with old pin
            if (r != CCID_OK)
                return SW_EXEC_ERROR();
            //encrypt MKEK with new pin
            hash_multi(apdu.data+pin_len, apdu.nc-pin_len, session_pin);
            has_session_pin = true;
            r = store_mkek(mkek);
            release_mkek(mkek);
            if (r != CCID_OK)
                return SW_EXEC_ERROR();
            uint8_t dhash[33];
            dhash[0] = apdu.nc-pin_len;
            double_hash_pin(apdu.data+pin_len, apdu.nc-pin_len, dhash+1);
            flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
            low_flash_available();
            return SW_OK();
        }
    }
    return SW_WRONG_P1P2();
}