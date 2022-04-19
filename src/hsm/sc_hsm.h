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

#ifndef _SC_HSM_H_
#define _SC_HSM_H_

#include <stdlib.h>
#include "pico/stdlib.h"
#include "ccid2040.h"

extern const uint8_t sc_hsm_aid[];


#define ALGO_RSA_RAW			0x20		/* RSA signature with external padding */
#define ALGO_RSA_DECRYPT		0x21		/* RSA decrypt */
#define ALGO_RSA_PKCS1			0x30		/* RSA signature with DigestInfo input and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA1		0x31		/* RSA signature with SHA-1 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA256	0x33		/* RSA signature with SHA-256 hash and PKCS#1 V1.5 padding */

#define ALGO_RSA_PSS			0x40		/* RSA signature with external hash and PKCS#1 PSS padding*/
#define ALGO_RSA_PSS_SHA1		0x41		/* RSA signature with SHA-1 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA256		0x43		/* RSA signature with SHA-256 hash and PKCS#1 PSS padding */

#define ALGO_EC_RAW				0x70		/* ECDSA signature with hash input */
#define ALGO_EC_SHA1			0x71		/* ECDSA signature with SHA-1 hash */
#define ALGO_EC_SHA224			0x72		/* ECDSA signature with SHA-224 hash */
#define ALGO_EC_SHA256			0x73		/* ECDSA signature with SHA-256 hash */
#define ALGO_EC_DH				0x80        /* ECDH key derivation */

#define ALGO_EC_DERIVE		    0x98		/* Derive EC key from EC key */

#define ALGO_AES_CBC_ENCRYPT	0x10
#define ALGO_AES_CBC_DECRYPT	0x11
#define ALGO_AES_CMAC		    0x18
#define ALGO_AES_DERIVE		    0x99

#define HSM_OPT_RRC                 0x0001
#define HSM_OPT_TRANSPORT_PIN       0x0002
#define HSM_OPT_SESSION_PIN         0x0004
#define HSM_OPT_SESSION_PIN_EXPL    0x000C
#define HSM_OPT_REPLACE_PKA         0x0008
#define HSM_OPT_COMBINED_AUTH       0x0010
#define HSM_OPT_RRC_RESET_ONLY      0x0020
#define HSM_OPT_BOOTSEL_BUTTON      0x0100

#define P15_KEYTYPE_RSA     0x30
#define P15_KEYTYPE_ECC     0xA0
#define P15_KEYTYPE_AES     0xA8

extern int pin_reset_retries(const file_t *pin, bool);
extern int pin_wrong_retry(const file_t *pin);

extern void hash(const uint8_t *input, size_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]);
extern void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]);

extern uint8_t session_pin[32], session_sopin[32];

#endif