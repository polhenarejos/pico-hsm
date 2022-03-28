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

#ifndef _HASH_UTILS_H_
#define _HASH_UTILS_H_

extern void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]);
extern void hash256(const uint8_t *input, size_t len, uint8_t output[32]);
extern void generic_hash(mbedtls_md_type_t md, const uint8_t *input, size_t len, uint8_t *output);

#endif
