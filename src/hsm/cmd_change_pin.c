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
        if (P2(apdu) == 0x81 || P2(apdu) == 0x88) {
            file_t *file_pin = NULL;
            if (P2(apdu) == 0x81) {
                file_pin = file_pin1;
            }
            else if (P2(apdu) == 0x88) {
                file_pin = file_sopin;
            }
            if (!file_pin) {
                return SW_FILE_NOT_FOUND();
            }
            if (!file_has_data(file_pin)) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_read_uint8(file_pin);
            int r = check_pin(file_pin, apdu.data, pin_len);
            if (r != 0x9000) {
                return r;
            }
            uint8_t mkek[MKEK_SIZE];
            r = load_mkek(mkek); //loads the MKEK with old pin
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            //encrypt MKEK with new pin

            if (P2(apdu) == 0x81) {
                hash_multi(apdu.data + pin_len, (uint16_t)(apdu.nc - pin_len), session_pin);
                has_session_pin = true;
            }
            else if (P2(apdu) == 0x88) {
                hash_multi(apdu.data + pin_len, (uint16_t)(apdu.nc - pin_len), session_sopin);
                has_session_sopin = true;
            }
            r = store_mkek(mkek);
            release_mkek(mkek);
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            uint8_t dhash[33];
            dhash[0] = (uint8_t)apdu.nc - pin_len;
            double_hash_pin(apdu.data + pin_len, (uint16_t)(apdu.nc - pin_len), dhash + 1);
            file_put_data(file_pin, dhash, sizeof(dhash));
            low_flash_available();
            return SW_OK();
        }
    }
    return SW_WRONG_P1P2();
}
