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

#include "random.h"
#include "sc_hsm.h"

uint8_t challenge[256];
uint16_t challenge_len = 0;
static bool challenge_pending = false;

bool pka_challenge_pending(void) {
    return challenge_pending;
}

void clear_pka_challenge(void) {
    memset(challenge, 0, sizeof(challenge));
    challenge_len = 0;
    challenge_pending = false;
}

int cmd_challenge(void) {
    if (apdu.ne == 0 || apdu.ne > sizeof(challenge)) {
        return SW_WRONG_LENGTH();
    }
    uint8_t *rb = (uint8_t *) random_bytes_get(apdu.ne);
    if (!rb) {
        return SW_WRONG_LENGTH();
    }
    memcpy(res_APDU, rb, apdu.ne);
    clear_pka_challenge();
    memset(puk_status, 0, sizeof(puk_status));
    challenge_len = (uint16_t)apdu.ne;
    memcpy(challenge, rb, challenge_len);
    challenge_pending = true;
    res_APDU_size = (uint16_t)apdu.ne;
    return SW_OK();
}
