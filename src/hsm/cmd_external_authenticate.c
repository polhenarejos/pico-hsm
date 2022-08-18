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
#include "cvc.h"
#include "files.h"

extern file_t *ef_puk_aut;
extern uint8_t challenge[256];
extern uint8_t challenge_len;

int cmd_external_authenticate() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0)
        return SW_INCORRECT_P1P2();
    if (ef_puk_aut == NULL)
        return SW_REFERENCE_NOT_FOUND();
    if (apdu.nc == 0)
        return SW_WRONG_LENGTH();
    file_t *ef_puk = search_by_fid(EF_PUKAUT, NULL, SPECIFY_EF);
    if (!ef_puk || !ef_puk->data || file_get_size(ef_puk) == 0)
        return SW_FILE_NOT_FOUND();
    uint8_t *puk_data = file_get_data(ef_puk);
    uint8_t *input = (uint8_t *)calloc(dev_name_len+challenge_len, sizeof(uint8_t)), hash[32];
    memcpy(input, dev_name, dev_name_len);
    memcpy(input+dev_name_len, challenge, challenge_len);
    hash256(input, dev_name_len+challenge_len, hash);
    int r = puk_verify(apdu.data, apdu.nc, hash, 32, file_get_data(ef_puk_aut), file_get_size(ef_puk_aut));
    free(input);
    if (r != 0)
        return SW_CONDITIONS_NOT_SATISFIED();
    puk_status[ef_puk_aut->fid & (MAX_PUK-1)] = 1;
    uint8_t auts = 0;
    for (int i = 0; i < puk_data[0]; i++)
        auts += puk_status[i];
    if (auts >= puk_data[2]) {
        isUserAuthenticated = true;
    }
    return SW_OK();
}
