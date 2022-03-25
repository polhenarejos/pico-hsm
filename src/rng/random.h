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


#ifndef _RANDOM_H_
#define _RANDOM_H_

void random_init (void);
void random_fini (void);

/* 32-byte random bytes */
const uint8_t *random_bytes_get (size_t);
void random_bytes_free (const uint8_t *p);

/* 8-byte salt */
void random_get_salt (uint8_t *p);

/* iterator returning a byta at a time */
int random_gen (void *arg, unsigned char *output, size_t output_len);

#endif 