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

#include "sc_hsm.h"
#include "tlv.h"
#include "oid.h"
#include "eac.h"
#include "files.h"
#include "cvc.h"

file_t *ef_puk_aut = NULL;

int cmd_mse(void) {
    int p1 = P1(apdu);
    int p2 = P2(apdu);
    if (p2 != 0xA4 && p2 != 0xA6 && p2 != 0xAA && p2 != 0xB4 && p2 != 0xB6 && p2 != 0xB8) {
        return SW_INCORRECT_P1P2();
    }
    if (p1 & 0x1) { //SET
        uint8_t *p = NULL;
        tlv_item_t item;
        tlv_ctx_t ctxi;
        tlv_ctx_init(BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc), &ctxi);
        while (tlv_walk(&ctxi, &p, &item)) {
            if (item.tag == 0x80) {
                if (p2 == 0xA4) {
                    if (item.value.len == 10 &&
                        memcmp(item.value.data, OID_ID_CA_ECDH_AES_CBC_CMAC_128, item.value.len) == 0) {
                        sm_set_protocol(MSE_AES);
                    }
                }
            }
            else if (item.tag == 0x83) {
                if (item.value.len == 1) {

                }
                else {
                    if (p2 == 0xB6) {
                        if (puk_store_select_chr(item.value.data) == PICOKEYS_OK) {
                            return SW_OK();
                        }
                    }
                    else if (p2 == 0xA4) {   /* Aut */
                        for (uint8_t i = 0; i < MAX_PUK; i++) {
                            file_t *ef = file_search(EF_PUK + i);
                            if (!ef) {
                                break;
                            }
                            if (!file_has_data(ef)) {
                                break;
                            }
                            uint16_t chr_len = 0;
                            const uint8_t *chr = cvc_get_chr(file_get_data(ef),
                                                             file_get_size(ef),
                                                             &chr_len);
                            if (memcmp(chr, item.value.data, chr_len) == 0) {
                                ef_puk_aut = ef;
                                if (puk_status[i] == 1) {
                                    return SW_CONDITIONS_NOT_SATISFIED(); // It is correct
                                }
                                return SW_OK();
                            }
                        }
                    }
                    return SW_REFERENCE_NOT_FOUND();
                }
            }
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}
