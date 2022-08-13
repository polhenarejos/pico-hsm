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
#include "random.h"

int cmd_key_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    uint8_t key_size = 32;
    int r;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (p2 == 0xB2)
        key_size = 32;
    else if (p2 == 0xB1)
        key_size = 24;
    else if (p2 == 0xB0)
        key_size = 16;
    //at this moment, we do not use the template, as only CBC is supported by the driver (encrypt, decrypt and CMAC)
    uint8_t aes_key[32]; //maximum AES key size
    memcpy(aes_key, random_bytes_get(key_size), key_size);
    int aes_type = 0x0;
    if (key_size == 16)
        aes_type = HSM_KEY_AES_128;
    else if (key_size == 24)
        aes_type = HSM_KEY_AES_192;
    else if (key_size == 32)
        aes_type = HSM_KEY_AES_256;
    r = store_keys(aes_key, aes_type, key_id);
    if (r != CCID_OK)
        return SW_MEMORY_FAILURE();
    if (find_and_store_meta_key(key_id) != CCID_OK)
        return SW_EXEC_ERROR();
    low_flash_available();
    return SW_OK();
}
