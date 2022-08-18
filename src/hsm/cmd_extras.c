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
#include "hardware/rtc.h"
#include "files.h"

int cmd_extras() {
    if (P2(apdu) != 0x0)
        return SW_INCORRECT_P1P2();
    if (P1(apdu) == 0xA) { //datetime operations
        if (apdu.nc == 0) {
            datetime_t dt;
            if (!rtc_get_datetime(&dt))
                return SW_EXEC_ERROR();
            res_APDU[res_APDU_size++] = dt.year >> 8;
            res_APDU[res_APDU_size++] = dt.year & 0xff;
            res_APDU[res_APDU_size++] = dt.month;
            res_APDU[res_APDU_size++] = dt.day;
            res_APDU[res_APDU_size++] = dt.dotw;
            res_APDU[res_APDU_size++] = dt.hour;
            res_APDU[res_APDU_size++] = dt.min;
            res_APDU[res_APDU_size++] = dt.sec;
        }
        else {
            if (apdu.nc != 8)
                return SW_WRONG_LENGTH();
            datetime_t dt;
            dt.year = (apdu.data[0] << 8) | (apdu.data[1]);
            dt.month = apdu.data[2];
            dt.day = apdu.data[3];
            dt.dotw = apdu.data[4];
            dt.hour = apdu.data[5];
            dt.min = apdu.data[6];
            dt.sec = apdu.data[7];
            if (!rtc_set_datetime(&dt))
                return SW_WRONG_DATA();
        }
    }
    else if (P1(apdu) == 0x6) { //dynamic options
        if (apdu.nc > sizeof(uint8_t))
            return SW_WRONG_LENGTH();
        uint16_t opts = get_device_options();
        if (apdu.nc == 0) {
            res_APDU[res_APDU_size++] = opts >> 8;
            res_APDU[res_APDU_size++] = opts & 0xff;
        }
        else {
            uint8_t newopts[] = { apdu.data[0], (opts & 0xff) };
            file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
            flash_write_data_to_file(tf, newopts, sizeof(newopts));
            low_flash_available();
        }
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}
