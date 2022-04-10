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

#ifndef _EAC_H_
#define _EAC_H_

#include <stdlib.h>
#include "pico/stdlib.h"
#include "hsm2040.h"

typedef enum MSE_protocol {
    MSE_AES = 0,
    MSE_3DES,
    MSE_NONE
}MSE_protocol;

extern void sm_derive_all_keys(const uint8_t *input, size_t input_len);
extern void sm_set_protocol(MSE_protocol proto);
extern MSE_protocol sm_get_protocol();
extern uint8_t *sm_get_nonce();
extern int sm_sign(uint8_t *in, size_t in_len, uint8_t *out);

#endif
