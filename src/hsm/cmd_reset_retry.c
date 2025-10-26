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

#include "crypto_utils.h"
#include "sc_hsm.h"
#include "kek.h"

int cmd_reset_retry() {
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_sopin || !file_pin1) {
        return SW_FILE_NOT_FOUND();
    }
    if (!file_has_data(file_sopin)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint16_t opts = get_device_options();
    if (!(opts & HSM_OPT_RRC)) {
        return SW_COMMAND_NOT_ALLOWED();
    }
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        uint8_t newpin_len = 0;
        if (P1(apdu) == 0x0) {
            uint8_t so_pin_len = file_read_uint8(file_sopin);
            if ((uint16_t)apdu.nc <= so_pin_len + 1) {
                return SW_WRONG_LENGTH();
            }
            uint16_t r = check_pin(file_sopin, apdu.data, so_pin_len);
            if (r != 0x9000) {
                return r;
            }
            newpin_len = (uint8_t)apdu.nc - so_pin_len;
        }
        else if (P1(apdu) == 0x2) {
            if (!has_session_sopin) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (apdu.nc > 16) {
                return SW_WRONG_LENGTH();
            }
            newpin_len = (uint8_t)apdu.nc;
        }
        uint8_t dhash[33];
        dhash[0] = newpin_len;
        double_hash_pin(apdu.data + (apdu.nc - newpin_len), newpin_len, dhash + 1);
        file_put_data(file_pin1, dhash, sizeof(dhash));
        if (pin_reset_retries(file_pin1, true) != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        uint8_t mkek[MKEK_SIZE];
        int r = load_mkek(mkek); //loads the MKEK with SO pin
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        hash_multi(apdu.data + (apdu.nc - newpin_len), newpin_len, session_pin);
        has_session_pin = true;
        r = store_mkek(mkek);
        release_mkek(mkek);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        low_flash_available();
        return SW_OK();
    }
    else if (P1(apdu) == 0x1 || P1(apdu) == 0x3) {
        if (!(opts & HSM_OPT_RRC_RESET_ONLY)) {
            return SW_COMMAND_NOT_ALLOWED();
        }
        if (P1(apdu) == 0x1) {
            uint8_t so_pin_len = file_read_uint8(file_sopin);
            if (apdu.nc != so_pin_len) {
                return SW_WRONG_LENGTH();
            }
            uint16_t r = check_pin(file_sopin, apdu.data, so_pin_len);
            if (r != 0x9000) {
                return r;
            }
        }
        else if (P1(apdu) == 0x3) {
            if (!has_session_sopin) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (apdu.nc != 0) {
                return SW_WRONG_LENGTH();
            }
        }
        if (pin_reset_retries(file_pin1, true) != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
