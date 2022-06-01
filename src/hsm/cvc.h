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

#ifndef _CVC_H_
#define _CVC_H_

#include <stdlib.h>
#include "pico/stdlib.h"

extern size_t asn1_cvc_cert(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len);
extern size_t asn1_cvc_aut(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len);

#endif
