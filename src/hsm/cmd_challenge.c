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

#include "random.h"
#include "sc_hsm.h"

uint8_t challenge[256];
uint8_t challenge_len = 0;

int cmd_challenge()
{
    uint8_t *rb = (uint8_t *) random_bytes_get(apdu.ne);
    if (!rb) {
        return SW_WRONG_LENGTH();
    }
    memcpy(res_APDU, rb, apdu.ne);
    challenge_len = MIN(apdu.ne, sizeof(challenge));
    memcpy(challenge, rb, challenge_len);
    res_APDU_size = apdu.ne;
    return SW_OK();
}
