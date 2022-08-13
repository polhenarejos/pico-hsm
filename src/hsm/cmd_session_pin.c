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
#include "random.h"
#include "eac.h"

int cmd_session_pin() {
    if (P1(apdu) == 0x01 && P2(apdu) == 0x81) {
        memcpy(sm_session_pin, random_bytes_get(8), 8);
        sm_session_pin_len = 8;
        
        memcpy(res_APDU, sm_session_pin, sm_session_pin_len);
        res_APDU_size = sm_session_pin_len;
        apdu.ne = sm_session_pin_len;
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}
