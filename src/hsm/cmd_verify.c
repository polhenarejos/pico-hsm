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

int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    
    if (p1 != 0x0 || (p2 & 0x60) != 0x0)
        return SW_WRONG_P1P2();

    if (p2 == 0x81) { //UserPin
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_TRANSPORT_PIN)
            return SW_DATA_INVALID();
        if (has_session_pin && apdu.nc == 0)
            return SW_OK();
        if (*file_get_data(file_pin1) == 0 && pka_enabled() == false) //not initialized
            return SW_REFERENCE_NOT_FOUND();
        if (apdu.nc > 0) {
            return check_pin(file_pin1, apdu.data, apdu.nc);
        }
        if (file_read_uint8(file_get_data(file_retries_pin1)) == 0)
            return SW_PIN_BLOCKED();
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_get_data(file_retries_pin1)));
    }
    else if (p2 == 0x88) { //SOPin
        if (file_read_uint8(file_get_data(file_sopin)) == 0) //not initialized
            return SW_REFERENCE_NOT_FOUND();
        if (apdu.nc > 0) {
            return check_pin(file_sopin, apdu.data, apdu.nc);
        }
        if (file_read_uint8(file_get_data(file_retries_sopin)) == 0)
            return SW_PIN_BLOCKED();
        if (has_session_sopin)
            return SW_OK();
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_get_data(file_retries_sopin)));
    }
    else if (p2 == 0x85) {
        return SW_OK();
    }
    return SW_REFERENCE_NOT_FOUND();
}
