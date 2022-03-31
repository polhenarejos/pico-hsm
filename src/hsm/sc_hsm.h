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
#include "hsm2040.h"

extern const uint8_t sc_hsm_aid[];

#define SW_BYTES_REMAINING_00()             set_res_sw (0x61, 0x00)
#define SW_WARNING_STATE_UNCHANGED()        set_res_sw (0x62, 0x00)
#define SW_EXEC_ERROR()                     set_res_sw (0x64, 0x00)
#define SW_MEMORY_FAILURE()                 set_res_sw (0x65, 0x81)
#define SW_WRONG_LENGTH()                   set_res_sw (0x67, 0x00)
#define SW_WRONG_DATA()                     set_res_sw (0x67, 0x00)
#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED()  set_res_sw (0x68, 0x81)
#define SW_SECURE_MESSAGING_NOT_SUPPORTED() set_res_sw (0x68, 0x82)
#define SW_SECURITY_STATUS_NOT_SATISFIED()  set_res_sw (0x69, 0x82)
#define SW_PIN_BLOCKED()                    set_res_sw (0x69, 0x83)
#define SW_DATA_INVALID()                   set_res_sw (0x69, 0x84)
#define SW_CONDITIONS_NOT_SATISFIED()       set_res_sw (0x69, 0x85)
#define SW_COMMAND_NOT_ALLOWED()            set_res_sw (0x69, 0x86)
#define SW_APPLET_SELECT_FAILED()           set_res_sw (0x69, 0x99)
#define SW_FUNC_NOT_SUPPORTED()             set_res_sw (0x6A, 0x81)
#define SW_FILE_NOT_FOUND()                 set_res_sw (0x6A, 0x82)
#define SW_RECORD_NOT_FOUND()               set_res_sw (0x6A, 0x83)
#define SW_FILE_FULL()                      set_res_sw (0x6A, 0x84)
#define SW_INCORRECT_P1P2()                 set_res_sw (0x6A, 0x86)
#define SW_REFERENCE_NOT_FOUND()            set_res_sw (0x6A, 0x88)
#define SW_WRONG_P1P2()                     set_res_sw (0x6B, 0x00)
#define SW_CORRECT_LENGTH_00()              set_res_sw (0x6C, 0x00)
#define SW_INS_NOT_SUPPORTED()              set_res_sw (0x6D, 0x00)
#define SW_CLA_NOT_SUPPORTED()              set_res_sw (0x6E, 0x00)
#define SW_UNKNOWN()                        set_res_sw (0x6F, 0x00)
#define SW_OK()                             set_res_sw (0x90, 0x00)

#define HSM_OK                              0
#define HSM_ERR_NO_MEMORY                   -1000
#define HSM_ERR_MEMORY_FATAL                -1001
#define HSM_ERR_NULL_PARAM                  -1002
#define HSM_ERR_FILE_NOT_FOUND              -1003
#define HSM_ERR_BLOCKED                     -1004
#define HSM_NO_LOGIN                        -1005
#define HSM_EXEC_ERROR                      -1006
#define HSM_WRONG_LENGTH                    -1007
#define HSM_WRONG_DATA                      -1008
#define HSM_WRONG_DKEK                      -1009
#define HSM_WRONG_SIGNATURE                 -1010
#define HSM_WRONG_PADDING                   -1011

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

#define HSM_OPT_RRC                 0x1
#define HSM_OPT_TRANSPORT_PIN       0x2
#define HSM_OPT_SESSION_PIN         0x4
#define HSM_OPT_SESSION_PIN_EXPL    0xC
#define HSM_OPT_REPLACE_PKA         0x8
#define HSM_OPT_COMBINED_AUTH       0x10
#define HSM_OPT_RRC_RESET_ONLY      0x20

#define P15_KEYTYPE_RSA     0x30
#define P15_KEYTYPE_ECC     0xA0
#define P15_KEYTYPE_AES     0xA8

extern int pin_reset_retries(const file_t *pin, bool);
extern int pin_wrong_retry(const file_t *pin);

extern void hash(const uint8_t *input, size_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]);
extern void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]);

extern uint8_t session_pin[32], session_sopin[32];

#define IV_SIZE 16

#endif