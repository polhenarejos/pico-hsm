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

#ifndef _DKEK_H_
#define _DKEK_H_

extern int load_dkek(uint8_t, uint8_t *);
extern int save_dkek_key(uint8_t, const uint8_t *key);
extern int store_dkek_key(uint8_t, uint8_t *);
extern void init_dkek();
extern void release_dkek(uint8_t *);
extern int import_dkek_share(uint8_t, const uint8_t *share);
extern int dkek_kcv(uint8_t, uint8_t *kcv);
extern int dkek_encrypt(uint8_t, uint8_t *data, size_t len);
extern int dkek_decrypt(uint8_t, uint8_t *data, size_t len);
extern int dkek_encode_key(uint8_t, void *key_ctx, int key_type, uint8_t *out, size_t *out_len);
extern int dkek_type_key(const uint8_t *in);
extern int dkek_decode_key(uint8_t, void *key_ctx, const uint8_t *in, size_t in_len, int *key_size_out);

#define MAX_DKEK_ENCODE_KEY_BUFFER (8+1+12+6+(8+2*4+2*4096/8+3+13)+16)

#define MAX_KEY_DOMAINS 16

#define DKEK_IV_SIZE     (IV_SIZE)
#define DKEK_KEY_SIZE    (32)
#define DKEK_KEY_CS_SIZE (4)
#define DKEK_SIZE        (DKEK_IV_SIZE+DKEK_KEY_SIZE+DKEK_KEY_CS_SIZE)
#define DKEK_KEY(p)      (p+DKEK_IV_SIZE)
#define DKEK_IV(p)       (p)
#define DKEK_CHECKSUM(p) (p+DKEK_IV_SIZE+DKEK_KEY_SIZE)

#endif
