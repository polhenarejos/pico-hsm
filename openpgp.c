/*
 * openpgp.c -- OpenPGP card protocol support
 *
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018
 *               2019, 2021
 *               Free Software Initiative of Japan
 * Author: NIIBE Yutaka <gniibe@fsij.org>
 *
 * This file is a part of Gnuk, a GnuPG USB Token implementation.
 *
 * Gnuk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gnuk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>

#include "config.h"

#include "gnuk.h"
//#include "sys.h"
#include "status-code.h"
#include "mbedtls/sha256.h"
#include "random.h"
#include "pico/util/queue.h"
#include "pico/multicore.h"
#include "hsm2040.h"
#include "tusb.h"

static queue_t *openpgp_comm;

#define USER_PASSWD_MINLEN 6
#define ADMIN_PASSWD_MINLEN 8

#define INS_VERIFY        			0x20
#define INS_CHANGE_REFERENCE_DATA		0x24
#define INS_PSO		  			0x2a
#define INS_RESET_RETRY_COUNTER			0x2c
#define INS_ACTIVATE_FILE			0x44
#define INS_PGP_GENERATE_ASYMMETRIC_KEY_PAIR	0x47
#define INS_EXTERNAL_AUTHENTICATE		0x82
#define INS_GET_CHALLENGE			0x84
#define INS_INTERNAL_AUTHENTICATE		0x88
#define INS_SELECT_FILE				0xa4
#define INS_READ_BINARY				0xb0
#define INS_READ_BINARY_ODD         0xb1
#define INS_GET_DATA				0xca
#define INS_WRITE_BINARY			0xd0
#define INS_UPDATE_BINARY			0xd6
#define INS_PUT_DATA				0xda
#define INS_PUT_DATA_ODD			0xdb	/* For key import */
#define INS_TERMINATE_DF			0xe6

static const uint8_t *challenge; /* Random bytes */

static const uint8_t
select_file_TOP_result[] __attribute__ ((aligned (1))) = {
  0x00, 0x00,	     /* unused */
  0x00, 0x00,	     /* number of bytes in this directory: to be filled */
  0x3f, 0x00,	     /* field of selected file: MF, 3f00 */
  0x38,			/* it's DF */
  0xff,			/* unused */
  0xff,	0x44, 0x44,	/* access conditions */
  0x01,			/* status of the selected file (OK, unblocked) */
  0x05,			/* number of bytes of data follow */
    0x03,			/* Features: unused */
    0x01,			/* number of subdirectories (OpenPGP) */
    0x01,			/* number of elementary files (SerialNo) */
    0x00,			/* number of secret codes */
    0x00,			/* Unused */
  0x00, 0x00		/* PIN status: OK, PIN blocked?: No */
};

uint16_t set_res_sw (uint8_t sw1, uint8_t sw2)
{
    apdu.sw = (sw1 << 8) | sw2;
    return make_uint16_t(sw1, sw2);
}

#define FILE_NONE	0
#define FILE_DF_OPENPGP	1
#define FILE_MF		2
#define FILE_EF_DIR	3
#define FILE_EF_SERIAL_NO	4
#define FILE_EF_UPDATE_KEY_0	5
#define FILE_EF_UPDATE_KEY_1	6
#define FILE_EF_UPDATE_KEY_2	7
#define FILE_EF_UPDATE_KEY_3	8
#define FILE_EF_CH_CERTIFICATE	9
#define FILE_DF_SC_HSM          10
#define FILE_CARD_TERMINATED	255

#define FILE_TYPE_UNKNOWN       0x00
#define FILE_TYPE_DF            0x04
#define FILE_TYPE_INTERNAL_EF	0x03
#define FILE_TYPE_WORKING_EF    0x01
#define FILE_TYPE_BSO           0x10

/* EF structures */
#define FILE_EF_UNKNOWN             0x00
#define FILE_EF_TRANSPARENT         0x01
#define FILE_EF_LINEAR_FIXED        0x02
#define FILE_EF_LINEAR_FIXED_TLV    0x03
#define FILE_EF_LINEAR_VARIABLE     0x04
#define FILE_EF_LINEAR_VARIABLE_TLV 0x05
#define FILE_EF_CYCLIC              0x06
#define FILE_EF_CYCLIC_TLV          0x07

#define ACL_OP_DELETE_SELF      0x00
#define ACL_OP_CREATE_DF        0x01
#define ACL_OP_CREATE_EF        0x02
#define ACL_OP_DELETE_CHILD     0x03
#define ACL_OP_WRITE            0x04
#define ACL_OP_UPDATE_ERASE     0x05
#define ACL_OP_READ_SEARCH      0x06

typedef struct pkcs15_entry
{
    const uint16_t fid;
    const uint8_t parent; //entry number in the whole table!!
    const uint8_t *name;
    const uint8_t type;
    const uint8_t *data; //should include 2 bytes len at begining
    const uint8_t ef_structure;
    const uint8_t acl[7];
} pkcs15_entry_t;

//puts FCI in the RAPDU
void process_fci(const pkcs15_entry_t *pe) {
    uint8_t *p = res_APDU;
    uint8_t buf[64];
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0x6f;
    res_APDU[res_APDU_size++] = 0x00; //computed later
    
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 2;
    if (pe->data)
        memcpy(res_APDU+res_APDU_size, pe->data, 2);
    else
        memset(res_APDU+res_APDU_size, 0, 2);
    res_APDU_size += 2;
    
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size] = 0;
    if (pe->type == FILE_TYPE_INTERNAL_EF)
        res_APDU[res_APDU_size++] |= 0x08;
    else if (pe->type == FILE_TYPE_WORKING_EF)
        res_APDU[res_APDU_size++] |= pe->ef_structure & 0x7;
    else if (pe->type == FILE_TYPE_DF)
        res_APDU[res_APDU_size++] |= 0x38;
    
    res_APDU[res_APDU_size++] = 0x83;
    res_APDU[res_APDU_size++] = 2;
    put_uint16_t(pe->fid, res_APDU+res_APDU_size);
    res_APDU_size += 2;
    res_APDU[1] = res_APDU_size-2;
}

const uint8_t t[] = {
               0x01,0xbb,
                0x7F,0x21,0x82,0x01,0xB6,0x7F,0x4E,0x82,0x01,0x6E,0x5F,0x29,0x01,0x00,0x42,0x0E,0x44,0x45,0x43,0x56,0x43,0x41,0x65,0x49,0x44,0x30,0x30,0x31,0x30,0x32,0x7F,0x49,0x82,0x01,0x1D,0x06,0x0A,0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x02,0x02,0x03,0x81,0x20,0xA9,0xFB,0x57,0xDB,0xA1,0xEE,0xA9,0xBC,0x3E,0x66,0x0A,0x90,0x9D,0x83,0x8D,0x72,0x6E,0x3B,0xF6,0x23,0xD5,0x26,0x20,0x28,0x20,0x13,0x48,0x1D,0x1F,0x6E,0x53,0x77,0x82,0x20,0x7D,0x5A,0x09,0x75,0xFC,0x2C,0x30,0x57,0xEE,0xF6,0x75,0x30,0x41,0x7A,0xFF,0xE7,0xFB,0x80,0x55,0xC1,0x26,0xDC,0x5C,0x6C,0xE9,0x4A,0x4B,0x44,0xF3,0x30,0xB5,0xD9,0x83,0x20,0x26,0xDC,0x5C,0x6C,0xE9,0x4A,0x4B,0x44,0xF3,0x30,0xB5,0xD9,0xBB,0xD7,0x7C,0xBF,0x95,0x84,0x16,0x29,0x5C,0xF7,0xE1,0xCE,0x6B,0xCC,0xDC,0x18,0xFF,0x8C,0x07,0xB6,0x84,0x41,0x04,0x8B,0xD2,0xAE,0xB9,0xCB,0x7E,0x57,0xCB,0x2C,0x4B,0x48,0x2F,0xFC,0x81,0xB7,0xAF,0xB9,0xDE,0x27,0xE1,0xE3,0xBD,0x23,0xC2,0x3A,0x44,0x53,0xBD,0x9A,0xCE,0x32,0x62,0x54,0x7E,0xF8,0x35,0xC3,0xDA,0xC4,0xFD,0x97,0xF8,0x46,0x1A,0x14,0x61,0x1D,0xC9,0xC2,0x77,0x45,0x13,0x2D,0xED,0x8E,0x54,0x5C,0x1D,0x54,0xC7,0x2F,0x04,0x69,0x97,0x85,0x20,0xA9,0xFB,0x57,0xDB,0xA1,0xEE,0xA9,0xBC,0x3E,0x66,0x0A,0x90,0x9D,0x83,0x8D,0x71,0x8C,0x39,0x7A,0xA3,0xB5,0x61,0xA6,0xF7,0x90,0x1E,0x0E,0x82,0x97,0x48,0x56,0xA7,0x86,0x41,0x04,0x33,0x47,0xEC,0xF9,0x6F,0xFB,0x4B,0xD9,0xB8,0x55,0x4E,0xFB,0xCC,0xFC,0x7D,0x0B,0x24,0x2F,0x10,0x71,0xE2,0x9B,0x4C,0x9C,0x62,0x2C,0x79,0xE3,0x39,0xD8,0x40,0xAF,0x67,0xBE,0xB9,0xB9,0x12,0x69,0x22,0x65,0xD9,0xC1,0x6C,0x62,0x57,0x3F,0x45,0x79,0xFF,0xD4,0xDE,0x2D,0xE9,0x2B,0xAB,0x40,0x9D,0xD5,0xC5,0xD4,0x82,0x44,0xA9,0xF7,0x87,0x01,0x01,0x5F,0x20,0x0E,0x44,0x45,0x43,0x56,0x43,0x41,0x65,0x49,0x44,0x30,0x30,0x31,0x30,0x32,0x7F,0x4C,0x12,0x06,0x09,0x04,0x00,0x7F,0x00,0x07,0x03,0x01,0x02,0x02,0x53,0x05,0xFE,0x0F,0x01,0xFF,0xFF,0x5F,0x25,0x06,0x01,0x00,0x01,0x00,0x01,0x08,0x5F,0x24,0x06,0x01,0x03,0x01,0x00,0x01,0x08,0x5F,0x37,0x40,0x50,0x67,0x14,0x5C,0x68,0xCA,0xE9,0x52,0x0F,0x5B,0xB3,0x48,0x17,0xF1,0xCA,0x9C,0x43,0x59,0x3D,0xB5,0x64,0x06,0xC6,0xA3,0xB0,0x06,0xCB,0xF3,0xF3,0x14,0xE7,0x34,0x9A,0xCF,0x0C,0xC6,0xBF,0xEB,0xCB,0xDE,0xFD,0x10,0xB4,0xDC,0xF0,0xF2,0x31,0xDA,0x56,0x97,0x7D,0x88,0xF9,0xF9,0x01,0x82,0xD1,0x99,0x07,0x6A,0x56,0x50,0x64,0x51
            };
const uint8_t token_info[] = {
    0x0, 0x1f, 
    0x30, 0x1d, 0x2, 0x1, 0x2, 0x4, 0x4, 0x6, 0x0, 0x0, 0x0, 0xc, 0x6, 0x4d, 0x61, 0x6e, 0x75, 0x49, 0x44, 0x80, 0x6, 0x50, 0x61, 0x74, 0x61, 0x74, 0x61, 0x3, 0x2, 0x7, 0x80
};

const pkcs15_entry_t pkcs15_entries[] = {
    { .fid = 0x3f00, .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, // MF
    { .fid = 0x2f00, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DIR
    { .fid = 0x2f01, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ATR
    { .fid = 0x2f02, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = t, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.GDO
    { .fid = 0x2f03, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = token_info, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    { .fid = 0x5015, .parent = 0, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, //DF.PKCS15
    { .fid = 0x5031, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ODF
    { .fid = 0x5032, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    { .fid = 0x5033, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.UnusedSpace
    { .fid = 0x0000, .parent = 0, .name = openpgpcard_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    { .fid = 0x0000, .parent = 0, .name = sc_hsm_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL, .ef_structure = 0, .acl = {0} } //end
};

const pkcs15_entry_t *MF = &pkcs15_entries[0];
const pkcs15_entry_t *pkcs15_last = &pkcs15_entries[sizeof(pkcs15_entries)/sizeof(pkcs15_entry_t)-1];
const pkcs15_entry_t *pkcs15_openpgp = &pkcs15_entries[sizeof(pkcs15_entries)/sizeof(pkcs15_entry_t)-3];
const pkcs15_entry_t *pkcs15_sc_hsm = &pkcs15_entries[sizeof(pkcs15_entries)/sizeof(pkcs15_entry_t)-2];

extern const pkcs15_entry_t *search_by_fid(const uint16_t, const pkcs15_entry_t *, const uint8_t);

bool card_terminated = false;

#define SPECIFY_EF 0x1
#define SPECIFY_DF 0x2
#define SPECIFY_ANY 0x3

#define MAX_DEPTH 4

bool is_parent(const pkcs15_entry_t *child, const pkcs15_entry_t *parent) {
    if (child == parent)
        return true;
    if (child == MF)
        return false;
    return is_parent(&pkcs15_entries[child->parent], parent);
}

const pkcs15_entry_t *search_by_name(uint8_t *name, uint16_t namelen) {
    for (const pkcs15_entry_t *p = pkcs15_entries; p != pkcs15_last; p++) {
        if (p->name && *p->name == apdu.cmd_apdu_data_len && memcmp(p->name+1, name, namelen) == 0) {
            return p;
        }
    }
    return NULL;
}

const pkcs15_entry_t *search_by_fid(const uint16_t fid, const pkcs15_entry_t *parent, const uint8_t sp) {
    
    for (const pkcs15_entry_t *p = pkcs15_entries; p != pkcs15_last; p++) {
        if (p->fid != 0x0000 && p->fid == fid) {
            if (!parent || (parent && is_parent(p, parent))) {
                if (!sp || sp == SPECIFY_ANY || (((sp & SPECIFY_EF) && (p->type & FILE_TYPE_INTERNAL_EF)) || ((sp & SPECIFY_DF) && p->type == FILE_TYPE_DF)))
                    return p;
            }
        }
    }
    return NULL;
}

uint8_t make_path_buf(const pkcs15_entry_t *pe, uint8_t *buf, uint8_t buflen, const pkcs15_entry_t *top) {
    if (!buflen)
        return 0;
    if (pe == top) //MF or relative DF
        return 0;
    put_uint16_t(pe->fid, buf);
    return make_path_buf(&pkcs15_entries[pe->parent], buf+2, buflen-2, top)+2;
}

uint8_t make_path(const pkcs15_entry_t *pe, const pkcs15_entry_t *top, uint8_t *path) {
    uint8_t buf[MAX_DEPTH*2], *p = path;
    put_uint16_t(pe->fid, buf);
    uint8_t depth = make_path_buf(&pkcs15_entries[pe->parent], buf+2, sizeof(buf)-2, top)+2;
    for (int d = depth-2; d >= 0; d -= 2) {
        memcpy(p, buf+d, 2);
        p += 2;
    }
    return depth;
}

const pkcs15_entry_t *search_by_path(const uint8_t *pe_path, uint8_t pathlen, const pkcs15_entry_t *parent) {
    uint8_t path[MAX_DEPTH*2];
    if (pathlen > sizeof(path)) {
        return NULL;
    }
    for (const pkcs15_entry_t *p = pkcs15_entries; p != pkcs15_last; p++) {
        uint8_t depth = make_path(p, parent, path);
        if (pathlen == depth && memcmp(path, pe_path, depth))
            return p;
    }
    return NULL;
}

uint8_t file_selection;
const pkcs15_entry_t *currentEF = NULL;
const pkcs15_entry_t *currentDF = NULL;
const pkcs15_entry_t *selected_applet = NULL;
bool isUserAuthenticated = false;

bool authenticate_action(const pkcs15_entry_t *ef, uint8_t op) {
    uint8_t acl = ef->acl[op];
    if (acl == 0x0)
        return true;
    else if (acl == 0xff)
        return false;
    else if (acl == 0x90 || acl & 0x9F == 0x10) {
            // PIN required.
        if(isUserAuthenticated) {
            return true;
        } 
        else {
            return false;
        }
    }
    return false;
}

static void gpg_init (void)
{
    const uint8_t *flash_do_start;
    const uint8_t *flash_do_end;
    
    flash_do_storage_init (&flash_do_start, &flash_do_end);
    
    if (flash_do_start == NULL)
        card_terminated = true;
    
    gpg_data_scan (flash_do_start, flash_do_end);
    flash_key_storage_init ();
    multicore_lockout_victim_init();
}

static void gpg_fini (void)
{
    ac_fini ();
}

#if defined(PINPAD_SUPPORT)
/*
 * Let user input PIN string.
 * Return length of the string.
 * The string itself is in PIN_INPUT_BUFFER.
 */
static int
get_pinpad_input (int msg_code)
{
  int r;

  led_blink (LED_START_COMMAND);
  r = pinpad_getline (msg_code, 8000000);
  led_blink (LED_FINISH_COMMAND);
  return r;
}
#endif

static int cmd_verify (queue_t *ccid_comm)
{
    int len;
    uint8_t p1 = P1 (apdu);
    uint8_t p2 = P2 (apdu);
    int r;
    const uint8_t *pw;
    
    (void)ccid_comm;
    DEBUG_INFO (" - VERIFY\r\n");
    DEBUG_BYTE (p2);
    
    len = apdu.cmd_apdu_data_len;
    pw = apdu.cmd_apdu_data;
    printf("%X %X %X\r\n",selected_applet,pkcs15_openpgp,pkcs15_sc_hsm);
    
    if (selected_applet == pkcs15_openpgp) {
        if (len == 0)
        {
            if (p1 == 0)
            {			/* This is to examine status.  */
                if (p2 == 0x81)
                    r = ac_check_status (AC_PSO_CDS_AUTHORIZED);
                else if (p2 == 0x82)
                    r = ac_check_status (AC_OTHER_AUTHORIZED);
                else
                    r = ac_check_status (AC_ADMIN_AUTHORIZED);
        
                if (r)
                    /* If authentication done already, return success.  */
                    return GPG_SUCCESS ();
                else
                {		 /* If not, return retry counter, encoded.  */
                    r = gpg_pw_get_retry_counter (p2);
                    set_res_sw (0x63, 0xc0 | (r&0x0f));
                }
            }
            else if (p1 == 0xff)
            {			/* Reset the status.  */
                if (p2 == 0x81)
                    ac_reset_pso_cds ();
                else if (p2 == 0x82)
                    ac_reset_other ();
                else
                    ac_reset_admin ();
                return GPG_SUCCESS ();
            }
            else
                return GPG_BAD_P1_P2 ();
        }
        
        if (gpg_do_kdf_check (len, 1) == 0)
        {
            return GPG_CONDITION_NOT_SATISFIED ();
        }
        
        /* This is real authentication.  */
        if (p2 == 0x81)
            r = verify_pso_cds (pw, len);
        else if (p2 == 0x82)
            r = verify_other (pw, len);
        else
            r = verify_admin (pw, len);
        
        if (r < 0)
        {
            DEBUG_INFO ("failed\r\n");
            return GPG_SECURITY_FAILURE ();
        }
        else if (r == 0)
        {
            DEBUG_INFO ("blocked\r\n");
            return GPG_SECURITY_AUTH_BLOCKED ();
        }
        else
        {
            DEBUG_INFO ("good\r\n");
            return GPG_SUCCESS ();
        }
    }
    else if (selected_applet == pkcs15_sc_hsm) {
        return GPG_BAD_P1_P2();
    }
    return 0;
}

int
gpg_change_keystring (int who_old, const uint8_t *old_ks,
		      int who_new, const uint8_t *new_ks)
{
  int r;
  int prv_keys_exist = 0;

  r = gpg_do_load_prvkey (GPG_KEY_FOR_SIGNING, who_old, old_ks);
  if (r < 0)
    return r;

  if (r > 0)
    prv_keys_exist++;

  r = gpg_do_chks_prvkey (GPG_KEY_FOR_SIGNING, who_old, old_ks,
			  who_new, new_ks);
  if (r < 0)
    return -2;

  r = gpg_do_load_prvkey (GPG_KEY_FOR_DECRYPTION, who_old, old_ks);
  if (r < 0)
    return r;

  if (r > 0)
    prv_keys_exist++;

  r = gpg_do_chks_prvkey (GPG_KEY_FOR_DECRYPTION, who_old, old_ks,
			  who_new, new_ks);
  if (r < 0)
    return -2;

  r = gpg_do_load_prvkey (GPG_KEY_FOR_AUTHENTICATION, who_old, old_ks);
  if (r < 0)
    return r;

  if (r > 0)
    prv_keys_exist++;

  r = gpg_do_chks_prvkey (GPG_KEY_FOR_AUTHENTICATION, who_old, old_ks,
			  who_new, new_ks);
  if (r < 0)
    return -2;

  if (prv_keys_exist)
    return 1;
  else
    return 0;
}

static void
cmd_change_password (queue_t *ccid_comm)
{
  uint8_t old_ks[KEYSTRING_MD_SIZE];
  uint8_t new_ks0[KEYSTRING_SIZE];
  uint8_t *new_salt = KS_GET_SALT (new_ks0);
  int newsalt_len = SALT_SIZE;
  uint8_t *new_ks = KS_GET_KEYSTRING (new_ks0);
  uint8_t p1 = P1 (apdu);	/* 0: change (old+new), 1: exchange (new) */
  uint8_t p2 = P2 (apdu);
  int len;
  uint8_t *pw, *newpw;
  int pw_len, newpw_len;
  int who = p2 - 0x80;
  int who_old;
  int r;
  int pw3_null = 0;
  const uint8_t *salt;
  int salt_len;
  const uint8_t *ks_pw3;

  (void)ccid_comm;
  DEBUG_INFO ("Change PW\r\n");
  DEBUG_BYTE (who);

  len = apdu.cmd_apdu_data_len;
  pw = apdu.cmd_apdu_data;

  if (p1 != 0)
    {
      GPG_FUNCTION_NOT_SUPPORTED ();
      return;
    }

  if (gpg_do_kdf_check (len, 2) == 0)
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  if (who == BY_USER)			/* PW1 */
    {
      const uint8_t *ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);

      who_old = who;
      pw_len = verify_user_0 (AC_PSO_CDS_AUTHORIZED, pw, len, -1, ks_pw1, 0);

      if (ks_pw1 == NULL)
	{
	  salt = NULL;
	  salt_len = 0;
	}
      else
	{
	  salt = KS_GET_SALT (ks_pw1);
	  salt_len = SALT_SIZE;
	}

      if (pw_len < 0)
	{
	  DEBUG_INFO ("permission denied.\r\n");
	  GPG_SECURITY_FAILURE ();
	  return;
	}
      else if (pw_len == 0)
	{
	  DEBUG_INFO ("blocked.\r\n");
	  GPG_SECURITY_AUTH_BLOCKED ();
	  return;
	}
      else
	{
	  newpw = pw + pw_len;
	  newpw_len = len - pw_len;
	  ks_pw3 = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);

	  /* Check length of password */
	  if ((ks_pw3 == NULL && newpw_len < ADMIN_PASSWD_MINLEN)
	      || newpw_len < USER_PASSWD_MINLEN)
	    {
	      DEBUG_INFO ("new password length is too short.");
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }
	}
    }
  else				/* PW3 (0x83) */
    {
      ks_pw3 = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);
      pw_len = verify_admin_0 (pw, len, -1, ks_pw3, 0);

      if (ks_pw3 == NULL)
	{
	  if (admin_authorized == BY_USER)
	    {
	      const uint8_t *ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);

	      if (ks_pw1 == NULL)
		{
		  GPG_SECURITY_FAILURE ();
		  return;
		}

	      salt = KS_GET_SALT (ks_pw1);
	      salt_len = SALT_SIZE;
	    }
	  else
	    {
	      salt = NULL;
	      salt_len = 0;
	    }
	}
      else
	{
	  salt = KS_GET_SALT (ks_pw3);
	  salt_len = SALT_SIZE;
	}

      if (pw_len < 0)
	{
	  DEBUG_INFO ("permission denied.\r\n");
	  GPG_SECURITY_FAILURE ();
	  return;
	}
      else if (pw_len == 0)
	{
	  DEBUG_INFO ("blocked.\r\n");
	  GPG_SECURITY_AUTH_BLOCKED ();
	  return;
	}
      else
	{
	  newpw = pw + pw_len;
	  newpw_len = len - pw_len;

	  if (newpw_len == 0 && admin_authorized == BY_ADMIN)
	    {
	      const uint8_t *initial_pw;

	      gpg_do_get_initial_pw_setting (1, &newpw_len, &initial_pw);
	      memcpy (newpw, initial_pw, newpw_len);
	      newsalt_len = 0;
	      pw3_null = 1;
	    }
	  else if (newpw_len < ADMIN_PASSWD_MINLEN)
	    {
	      DEBUG_INFO ("new password length is too short.");
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  who_old = admin_authorized;
	}
    }

  if (newsalt_len != 0)
    random_get_salt (new_salt);
  s2k (salt, salt_len, pw, pw_len, old_ks);
  s2k (new_salt, newsalt_len, newpw, newpw_len, new_ks);
  new_ks0[0] = newpw_len;

  r = gpg_change_keystring (who_old, old_ks, who, new_ks);
  if (r <= -2)
    {
      DEBUG_INFO ("memory error.\r\n");
      GPG_MEMORY_FAILURE ();
    }
  else if (r < 0)
    {
      DEBUG_INFO ("security error.\r\n");
      GPG_SECURITY_FAILURE ();
    }
  else if (r == 0 && who == BY_USER)	/* no prvkey */
    {
      DEBUG_INFO ("user pass change not supported with no keys.\r\n");
      GPG_CONDITION_NOT_SATISFIED ();
    }
  else if (r > 0 && who == BY_USER)
    {
      /* When it was already admin-less mode, admin_authorized is
       * BY_USER.  If no PW3 keystring, it's becoming admin-less mode,
       * now.  For these two cases, we need to reset admin
       * authorization status.  */
      if (admin_authorized == BY_USER)
	ac_reset_admin ();
      else if (ks_pw3 == NULL)
	{
	  enum kind_of_key kk0;

	  /* Remove keystrings for BY_ADMIN.  */
	  for (kk0 = 0; kk0 <= GPG_KEY_FOR_AUTHENTICATION; kk0++)
	    gpg_do_chks_prvkey (kk0, BY_ADMIN, NULL, 0, NULL);

	  ac_reset_admin ();
	}

      gpg_do_write_simple (NR_DO_KEYSTRING_PW1, new_ks0, KS_META_SIZE);
      ac_reset_pso_cds ();
      ac_reset_other ();
      DEBUG_INFO ("Changed length of DO_KEYSTRING_PW1.\r\n");
      GPG_SUCCESS ();
    }
  else if (r > 0 && who == BY_ADMIN)
    {
      if (pw3_null)
	gpg_do_write_simple (NR_DO_KEYSTRING_PW3, NULL, 0);
      else
	gpg_do_write_simple (NR_DO_KEYSTRING_PW3, new_ks0, KS_META_SIZE);

      ac_reset_admin ();
      DEBUG_INFO ("Changed length of DO_KEYSTRING_PW3.\r\n");
      GPG_SUCCESS ();
    }
  else /* r == 0 && who == BY_ADMIN */	/* no prvkey */
    {
      if (pw3_null)
	gpg_do_write_simple (NR_DO_KEYSTRING_PW3, NULL, 0);
      else
	{
	  new_ks0[0] |= PW_LEN_KEYSTRING_BIT;
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW3, new_ks0, KEYSTRING_SIZE);
	}
      DEBUG_INFO ("Changed DO_KEYSTRING_PW3.\r\n");
      ac_reset_admin ();
      GPG_SUCCESS ();
    }
}


#ifndef S2KCOUNT
/*
 * OpenPGP uses the value 65535 for the key on disk.
 * Given the condition that the access to flash ROM is harder than disk,
 * that is, the threat model is different, we chose the default value 192.
 */
#define S2KCOUNT 192
#endif
void
s2k (const unsigned char *salt, size_t slen,
     const unsigned char *input, size_t ilen, unsigned char output[32])
{
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  size_t count = S2KCOUNT;
  const uint8_t *unique = unique_device_id ();

  mbedtls_sha256_starts (&ctx, 0);

  mbedtls_sha256_update (&ctx, unique, 12);

  while (count > slen + ilen)
    {
      if (slen)
	mbedtls_sha256_update (&ctx, salt, slen);
      mbedtls_sha256_update (&ctx, input, ilen);
      count -= slen + ilen;
    }

  if (count <= slen)
    mbedtls_sha256_update (&ctx, salt, count);
  else
    {
      if (slen)
	{
	  mbedtls_sha256_update (&ctx, salt, slen);
	  count -= slen;
	}
      mbedtls_sha256_update (&ctx, input, count);
    }

  mbedtls_sha256_finish (&ctx, output);
  mbedtls_sha256_free (&ctx);
}


static void
cmd_reset_user_password (queue_t *ccid_comm)
{
  uint8_t p1 = P1 (apdu);
  int len;
  const uint8_t *pw;
  const uint8_t *newpw;
  int pw_len, newpw_len;
  int r;
  uint8_t new_ks0[KEYSTRING_SIZE];
  uint8_t *new_ks = KS_GET_KEYSTRING (new_ks0);
  uint8_t *new_salt = KS_GET_SALT (new_ks0);
  const uint8_t *ks_pw3 = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);
  const uint8_t *salt;
  int salt_len;

  (void)ccid_comm;
  DEBUG_INFO ("Reset PW1\r\n");
  DEBUG_BYTE (p1);

  len = apdu.cmd_apdu_data_len;
  pw = apdu.cmd_apdu_data;

  if (p1 == 0x00)		/* by User with Reseting Code */
    {
      const uint8_t *ks_rc = gpg_do_read_simple (NR_DO_KEYSTRING_RC);
      uint8_t old_ks[KEYSTRING_MD_SIZE];

      if (gpg_do_kdf_check (len, 2) == 0)
	{
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      if (gpg_pw_locked (PW_ERR_RC))
	{
	  DEBUG_INFO ("blocked.\r\n");
	  GPG_SECURITY_AUTH_BLOCKED ();
	  return;
	}

      if (ks_rc == NULL)
	{
	  DEBUG_INFO ("security error.\r\n");
	  GPG_SECURITY_FAILURE ();
	  return;
	}

      pw_len = ks_rc[0] & PW_LEN_MASK;
      salt = KS_GET_SALT (ks_rc);
      salt_len = SALT_SIZE;
      newpw = pw + pw_len;
      newpw_len = len - pw_len;

      /* Check length of new password */
      if ((ks_pw3 == NULL && newpw_len < ADMIN_PASSWD_MINLEN)
	  || newpw_len < USER_PASSWD_MINLEN)
	{
	  DEBUG_INFO ("new password length is too short.");
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      random_get_salt (new_salt);
      s2k (salt, salt_len, pw, pw_len, old_ks);
      s2k (new_salt, SALT_SIZE, newpw, newpw_len, new_ks);
      new_ks0[0] = newpw_len;
      r = gpg_change_keystring (BY_RESETCODE, old_ks, BY_USER, new_ks);
      if (r <= -2)
	{
	  DEBUG_INFO ("memory error.\r\n");
	  GPG_MEMORY_FAILURE ();
	}
      else if (r < 0)
	{
	  DEBUG_INFO ("failed.\r\n");
	  gpg_pw_increment_err_counter (PW_ERR_RC);
	  GPG_SECURITY_FAILURE ();
	}
      else if (r == 0)
	{
	  DEBUG_INFO ("user pass change not supported with no keys.\r\n");
	  GPG_CONDITION_NOT_SATISFIED ();
	}
      else
	{
	  DEBUG_INFO ("done.\r\n");
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW1, new_ks0, KS_META_SIZE);
	  ac_reset_pso_cds ();
	  ac_reset_other ();
	  if (admin_authorized == BY_USER)
	    ac_reset_admin ();
	  gpg_pw_reset_err_counter (PW_ERR_RC);
	  gpg_pw_reset_err_counter (PW_ERR_PW1);
	  GPG_SUCCESS ();
	}
    }
  else				/* by Admin (p1 == 0x02) */
    {
      const uint8_t *old_ks = keystring_md_pw3;

      if (!ac_check_status (AC_ADMIN_AUTHORIZED))
	{
	  DEBUG_INFO ("permission denied.\r\n");
	  GPG_SECURITY_FAILURE ();
	  return;
	}

      if (gpg_do_kdf_check (len, 1) == 0)
	{
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      newpw_len = len;
      newpw = pw;

      /* Check length of new password */
      if ((ks_pw3 == NULL && newpw_len < ADMIN_PASSWD_MINLEN)
	  || newpw_len < USER_PASSWD_MINLEN)
	{
	  DEBUG_INFO ("new password length is too short.");
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      random_get_salt (new_salt);
      s2k (new_salt, SALT_SIZE, newpw, newpw_len, new_ks);
      new_ks0[0] = newpw_len;
      r = gpg_change_keystring (admin_authorized, old_ks, BY_USER, new_ks);
      if (r <= -2)
	{
	  DEBUG_INFO ("memory error.\r\n");
	  GPG_MEMORY_FAILURE ();
	}
      else if (r < 0)
	{
	  DEBUG_INFO ("security error.\r\n");
	  GPG_SECURITY_FAILURE ();
	}
      else if (r == 0)
	{
	  DEBUG_INFO ("user pass change not supported with no keys.\r\n");
	  GPG_CONDITION_NOT_SATISFIED ();
	}
      else
	{
	  DEBUG_INFO ("done.\r\n");
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW1, new_ks0, KS_META_SIZE);
	  ac_reset_pso_cds ();
	  ac_reset_other ();
	  if (admin_authorized == BY_USER)
	    ac_reset_admin ();
	  gpg_pw_reset_err_counter (PW_ERR_PW1);
	  GPG_SUCCESS ();
	}
    }
}

static void
cmd_put_data (queue_t *ccid_comm)
{
  uint8_t *data;
  uint16_t tag;
  int len;

  (void)ccid_comm;
  DEBUG_INFO (" - PUT DATA\r\n");

  tag = ((P1 (apdu)<<8) | P2 (apdu));
  len = apdu.cmd_apdu_data_len;
  data = apdu.cmd_apdu_data;
  gpg_do_put_data (tag, data, len);
}

static void
cmd_pgp_gakp (queue_t *ccid_comm)
{
  (void)ccid_comm;
  DEBUG_INFO (" - Generate Asymmetric Key Pair\r\n");
  DEBUG_BYTE (P1 (apdu));

  if (P1 (apdu) == 0x81)
    /* Get public key */
    gpg_do_public_key (apdu.cmd_apdu_data[0]);
  else
    {
      if (!ac_check_status (AC_ADMIN_AUTHORIZED))
	GPG_SECURITY_FAILURE ();
#ifdef KDF_DO_REQUIRED
      else if (!gpg_do_kdf_check (0, 0))
	GPG_CONDITION_NOT_SATISFIED ();
#endif
      else
	gpg_do_keygen (&apdu.cmd_apdu_data[0]);
    }
}

#ifdef FLASH_UPGRADE_SUPPORT
const uint8_t *
gpg_get_firmware_update_key (uint8_t keyno)
{
  extern uint8_t _updatekey_store[1024];
  const uint8_t *p;

  p = _updatekey_store + keyno * FIRMWARE_UPDATE_KEY_CONTENT_LEN;
  return p;
}
#endif

#ifdef CERTDO_SUPPORT
#define FILEID_CH_CERTIFICATE_IS_VALID 1
#else
#define FILEID_CH_CERTIFICATE_IS_VALID 0
#endif

static int cmd_read_binary (queue_t *ccid_comm)
{
    uint16_t fid;
    uint32_t offset;
    uint8_t ins = INS(apdu), p1 = P1(apdu), p2 = P2(apdu);
    const pkcs15_entry_t *ef = NULL;
    
    (void)ccid_comm;
    DEBUG_INFO (" - Read binary\r\n");
    
    if ((ins & 0x1) == 0)
    {
        if ((p1 & 0x80) != 0) {
            if (!(ef = search_by_fid(p1&0x1f, NULL, SPECIFY_EF)))
                return SW_FILE_NOT_FOUND ();
            offset = p2;
        }
        else {
            offset = make_uint16_t(p1, p2) & 0x7fff;
            ef = currentEF;
        }
    }
    else {
        if (p1 == 0 && (p2 & 0xE0) == 0 && (p2 & 0x1f) != 0 && (p2 & 0x1f) != 0x1f) {
            if (!(ef = search_by_fid(p2&0x1f, NULL, SPECIFY_EF)))
                return SW_FILE_NOT_FOUND ();
        } 
        else {
            uint16_t file_id = make_uint16_t(p1, p2) & 0x7fff;
            if (file_id == 0x0)
                ef = currentEF;
            else if (!(ef = search_by_fid(file_id, NULL, SPECIFY_EF)))
                return SW_FILE_NOT_FOUND ();
            
            if (apdu.cmd_apdu_data[0] != 0x54)
                return SW_WRONG_DATA();
                
            offset = 0;
            for (int d = 0; d < apdu.cmd_apdu_data[1]; d++)
                offset |= apdu.cmd_apdu_data[2+d]<<(apdu.cmd_apdu_data[1]-1-d)*8;
        }
        
    }
    
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        uint16_t data_len = get_uint16_t(ef->data, 0);
        if (offset > data_len)
            return SW_WRONG_P1P2();
        
        uint16_t maxle = data_len-offset;
        if (apdu.expected_res_size > maxle)
            apdu.expected_res_size = maxle;
        res_APDU = ef->data+2+offset;
        res_APDU_size = data_len-offset;
    }

    return GPG_SUCCESS ();
}
void select_file(const pkcs15_entry_t *pe) {
    if (!pe)
    {
        currentDF = MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &pkcs15_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == pkcs15_openpgp || currentEF == pkcs15_sc_hsm)
        selected_applet = currentEF;
}
static uint16_t cmd_select_file (queue_t *ccid_comm)
{
    (void)ccid_comm;
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    const pkcs15_entry_t *pe = NULL;
    uint16_t fid = 0x0;
    
    // Only "first or only occurence" supported 
    //if ((p2 & 0xF3) != 0x00) {
    //    return SW_INCORRECT_P1P2();
    //}
    
    if (apdu.cmd_apdu_data_len >= 2)
        fid = get_uint16_t(apdu.cmd_apdu_data, 0);
    
    if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
        if (apdu.cmd_apdu_data_len == 0) {
        	pe = MF;
        	ac_fini();
        }
        else if (apdu.cmd_apdu_data_len == 2) {
            if (!(pe = search_by_fid(fid, NULL, SPECIFY_ANY))) {
                return GPG_NO_FILE ();
            }
        }
    }
    else if (p1 == 0x01) { //Select child DF - DF identifier
        if (!(pe = search_by_fid(fid, currentDF, SPECIFY_DF))) {
            return GPG_NO_FILE ();
        }
    }
    else if (p1 == 0x02) { //Select EF under the current DF - EF identifier
        if (!(pe = search_by_fid(fid, currentDF, SPECIFY_EF))) {
            return GPG_NO_FILE ();
        }
    }
    else if (p1 == 0x03) { //Select parent DF of the current DF - Absent
        if (apdu.cmd_apdu_data_len != 0)
            return GPG_NO_FILE ();
    }
    else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
        if (!(pe = search_by_name(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len))) {
            return GPG_NO_FILE ();
        }
        if (card_terminated) {
            return GPG_APPLICATION_TERMINATED ();
        }        
    }
    else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
        if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, MF))) {
            return GPG_NO_FILE ();
        }
    }
    else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
        if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, currentDF))) {
            return GPG_NO_FILE ();
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        process_fci(pe);
    }
    else
        return SW_INCORRECT_P1P2();
    select_file(pe);
    return GPG_SUCCESS ();
}

static void
cmd_get_data (queue_t *ccid_comm)
{
  uint16_t tag = ((P1 (apdu)<<8) | P2 (apdu));

  (void)ccid_comm;
  DEBUG_INFO (" - Get Data\r\n");

  gpg_do_get_data (tag, 0);
}

#define ECDSA_HASH_LEN 32
#define ECDSA_SIGNATURE_LENGTH 64

#define EDDSA_HASH_LEN_MAX 256
#define ED25519_SIGNATURE_LENGTH 64
#define ED448_SIGNATURE_LENGTH 114

#define ECC_CIPHER_DO_HEADER_SIZE 7

static void
cmd_pso (queue_t *ccid_comm)
{
  int len = apdu.cmd_apdu_data_len;
  int r = -1;
  int attr;
  int pubkey_len;
  unsigned int result_len = 0;
  int cs;

  DEBUG_INFO (" - PSO: ");
  DEBUG_WORD ((uint32_t)&r);
  DEBUG_BINARY (apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
  DEBUG_SHORT (len);

  if (P1 (apdu) == 0x9e && P2 (apdu) == 0x9a)
    {
      attr = gpg_get_algo_attr (GPG_KEY_FOR_SIGNING);
      pubkey_len = gpg_get_algo_attr_key_size (GPG_KEY_FOR_SIGNING,
					       GPG_KEY_PUBLIC);

      if (!ac_check_status (AC_PSO_CDS_AUTHORIZED))
	{
	  DEBUG_INFO ("security error.");
	  GPG_SECURITY_FAILURE ();
	  return;
	}

#ifdef ACKBTN_SUPPORT
      if (gpg_do_get_uif (GPG_KEY_FOR_SIGNING))
	eventflag_signal (ccid_comm, EV_EXEC_ACK_REQUIRED);
#endif

      if (attr == ALGO_RSA2K || attr == ALGO_RSA4K)
	{
	  /* Check size of digestInfo */
	  if (len != 34		/* MD5 */
	      && len != 35		/* SHA1 / RIPEMD-160 */
	      && len != 47		/* SHA224 */
	      && len != 51		/* SHA256 */
	      && len != 67		/* SHA384 */
	      && len != 83)		/* SHA512 */
	    {
	      DEBUG_INFO (" wrong length");
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  DEBUG_BINARY (kd[GPG_KEY_FOR_SIGNING].data, pubkey_len);

	  result_len = pubkey_len;
	  r = rsa_sign (apdu.cmd_apdu_data, res_APDU, len,
			&kd[GPG_KEY_FOR_SIGNING], pubkey_len);
	}
      else if (attr == ALGO_SECP256K1)
	{
	  /* ECDSA with p256r1/p256k1 for signature */
	  if (len != ECDSA_HASH_LEN)
	    {
	      DEBUG_INFO (" wrong length");
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  //cs = chopstx_setcancelstate (0);
	  result_len = ECDSA_SIGNATURE_LENGTH;
	  r = ecdsa_sign_p256k1 (apdu.cmd_apdu_data, res_APDU,
				 kd[GPG_KEY_FOR_SIGNING].data);
	  //chopstx_setcancelstate (cs);
	}
      else if (attr == ALGO_ED25519)
	{
	  uint32_t output[ED25519_SIGNATURE_LENGTH/4]; /* Require 4-byte alignment. */

	  //cs = chopstx_setcancelstate (0);
	  result_len = ED25519_SIGNATURE_LENGTH;
	  r = eddsa_sign_25519 (apdu.cmd_apdu_data, len, output,
				kd[GPG_KEY_FOR_SIGNING].data,
				kd[GPG_KEY_FOR_SIGNING].data+32,
				kd[GPG_KEY_FOR_SIGNING].pubkey);
	  //chopstx_setcancelstate (cs);
	  memcpy (res_APDU, output, ED25519_SIGNATURE_LENGTH);
	}
      else if (attr == ALGO_ED448)
	{
	  //cs = chopstx_setcancelstate (0);
	  result_len = ED448_SIGNATURE_LENGTH;
	  r = ed448_sign (res_APDU, apdu.cmd_apdu_data, len,
			  kd[GPG_KEY_FOR_SIGNING].data,
			  kd[GPG_KEY_FOR_SIGNING].data+57,
			  kd[GPG_KEY_FOR_SIGNING].pubkey);
	  //chopstx_setcancelstate (cs);
	}
      else
	{
	  DEBUG_INFO ("unknown algo.");
	  GPG_FUNCTION_NOT_SUPPORTED ();
	  return;
	}

      if (r == 0)
	{
	  res_APDU_size = result_len;
	  gpg_increment_digital_signature_counter ();
	}
      else   /* Failure */
	ac_reset_pso_cds ();
    }
  else if (P1 (apdu) == 0x80 && P2 (apdu) == 0x86)
    {
      attr = gpg_get_algo_attr (GPG_KEY_FOR_DECRYPTION);
      pubkey_len = gpg_get_algo_attr_key_size (GPG_KEY_FOR_DECRYPTION,
					       GPG_KEY_PUBLIC);

      DEBUG_BINARY (kd[GPG_KEY_FOR_DECRYPTION].data, pubkey_len);

      if (!ac_check_status (AC_OTHER_AUTHORIZED))
	{
	  DEBUG_INFO ("security error.");
	  GPG_SECURITY_FAILURE ();
	  return;
	}

#ifdef ACKBTN_SUPPORT
      if (gpg_do_get_uif (GPG_KEY_FOR_DECRYPTION))
	eventflag_signal (ccid_comm, EV_EXEC_ACK_REQUIRED);
#else
      (void)ccid_comm;
#endif

      if (attr == ALGO_RSA2K || attr == ALGO_RSA4K)
	{
	  /* Skip padding 0x00 */
	  len--;
	  if (len != pubkey_len)
	    {
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }
	  r = rsa_decrypt (apdu.cmd_apdu_data+1, res_APDU, len,
			   &kd[GPG_KEY_FOR_DECRYPTION], &result_len);
	}
      else if (attr == ALGO_SECP256K1)
	{
	  int header = ECC_CIPHER_DO_HEADER_SIZE;

	  /* Format is in big endian MPI: 04 || x || y */
	  if (len != 65 + ECC_CIPHER_DO_HEADER_SIZE
	      || apdu.cmd_apdu_data[header] != 0x04)
	    {
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  //cs = chopstx_setcancelstate (0);
	  result_len = 65;
	  r = ecdh_decrypt_p256k1 (apdu.cmd_apdu_data + header, res_APDU,
				   kd[GPG_KEY_FOR_DECRYPTION].data);
	  //chopstx_setcancelstate (cs);
	}
      else if (attr == ALGO_CURVE25519)
	{
	  int header = ECC_CIPHER_DO_HEADER_SIZE;

	  if (len != 32 + ECC_CIPHER_DO_HEADER_SIZE)
	    {
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  //cs = chopstx_setcancelstate (0);
	  result_len = 32;
	  r = ecdh_decrypt_curve25519 (apdu.cmd_apdu_data + header, res_APDU,
				       kd[GPG_KEY_FOR_DECRYPTION].data);
	  //chopstx_setcancelstate (cs);
	}
      else if (attr == ALGO_X448)
	{
	  int header = ECC_CIPHER_DO_HEADER_SIZE;

	  if (len != 56 + ECC_CIPHER_DO_HEADER_SIZE)
	    {
	      GPG_CONDITION_NOT_SATISFIED ();
	      return;
	    }

	  //cs = chopstx_setcancelstate (0);
	  result_len = 56;
	  r = ecdh_decrypt_x448 (res_APDU, apdu.cmd_apdu_data + header,
				 kd[GPG_KEY_FOR_DECRYPTION].data);
	  //chopstx_setcancelstate (cs);
	}
      else
	{
	  DEBUG_INFO ("unknown algo.");
	  GPG_FUNCTION_NOT_SUPPORTED ();
	  return;
	}

      if (r == 0)
	res_APDU_size = result_len;
    }

  if (r < 0)
    {
      DEBUG_INFO (" - ??");
      DEBUG_BYTE (P1 (apdu));
      DEBUG_INFO (" - ??");
      DEBUG_BYTE (P2 (apdu));
      GPG_ERROR ();
    }

  DEBUG_INFO ("PSO done.\r\n");
}


#define MAX_RSA_DIGEST_INFO_LEN 102 /* 40% */
static void
cmd_internal_authenticate (queue_t *ccid_comm)
{
  int attr = gpg_get_algo_attr (GPG_KEY_FOR_AUTHENTICATION);
  int pubkey_len = gpg_get_algo_attr_key_size (GPG_KEY_FOR_AUTHENTICATION,
					       GPG_KEY_PUBLIC);
  int len = apdu.cmd_apdu_data_len;
  int r = -1;
  unsigned int result_len = 0;
  int cs;

  DEBUG_INFO (" - INTERNAL AUTHENTICATE\r\n");

  if (P1 (apdu) != 0x00 || P2 (apdu) != 0x00)
    {
      DEBUG_INFO (" - ??");
      DEBUG_BYTE (P1 (apdu));
      DEBUG_INFO (" - ??");
      DEBUG_BYTE (P2 (apdu));
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  DEBUG_SHORT (len);
  if (!ac_check_status (AC_OTHER_AUTHORIZED))
    {
      DEBUG_INFO ("security error.");
      GPG_SECURITY_FAILURE ();
      return;
    }

#ifdef ACKBTN_SUPPORT
  if (gpg_do_get_uif (GPG_KEY_FOR_AUTHENTICATION))
    eventflag_signal (ccid_comm, EV_EXEC_ACK_REQUIRED);
#else
  (void)ccid_comm;
#endif

  if (attr == ALGO_RSA2K || attr == ALGO_RSA4K)
    {
      if (len > MAX_RSA_DIGEST_INFO_LEN)
	{
	  DEBUG_INFO ("input is too long.");
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      result_len = pubkey_len;
      r = rsa_sign (apdu.cmd_apdu_data, res_APDU, len,
		    &kd[GPG_KEY_FOR_AUTHENTICATION], pubkey_len);
    }
  else if (attr == ALGO_SECP256K1)
    {
      if (len != ECDSA_HASH_LEN)
	{
	  DEBUG_INFO ("wrong hash length.");
	  GPG_CONDITION_NOT_SATISFIED ();
	  return;
	}

      //cs = chopstx_setcancelstate (0);
      result_len = ECDSA_SIGNATURE_LENGTH;
      r = ecdsa_sign_p256k1 (apdu.cmd_apdu_data, res_APDU,
			     kd[GPG_KEY_FOR_AUTHENTICATION].data);
      //chopstx_setcancelstate (cs);
    }
  else if (attr == ALGO_ED25519)
    {
      uint32_t output[ED25519_SIGNATURE_LENGTH/4]; /* Require 4-byte alignment. */

      //cs = chopstx_setcancelstate (0);
      result_len = ED25519_SIGNATURE_LENGTH;
      r = eddsa_sign_25519 (apdu.cmd_apdu_data, len, output,
			    kd[GPG_KEY_FOR_AUTHENTICATION].data,
			    kd[GPG_KEY_FOR_AUTHENTICATION].data+32,
			    kd[GPG_KEY_FOR_AUTHENTICATION].pubkey);
      //chopstx_setcancelstate (cs);
      memcpy (res_APDU, output, ED25519_SIGNATURE_LENGTH);
    }
  else if (attr == ALGO_ED448)
    {
      //cs = chopstx_setcancelstate (0);
      result_len = ED448_SIGNATURE_LENGTH;
      r = ed448_sign (res_APDU, apdu.cmd_apdu_data, len,
		      kd[GPG_KEY_FOR_AUTHENTICATION].data,
		      kd[GPG_KEY_FOR_AUTHENTICATION].data+57,
		      kd[GPG_KEY_FOR_AUTHENTICATION].pubkey);
      //chopstx_setcancelstate (cs);
    }

  if (r == 0)
    res_APDU_size = result_len;
  else
    GPG_ERROR ();

  DEBUG_INFO ("INTERNAL AUTHENTICATE done.\r\n");
}


#define MBD_OPRATION_WRITE  0
#define MBD_OPRATION_UPDATE 1

static void
modify_binary (uint8_t op, uint8_t p1, uint8_t p2, int len)
{
  uint8_t file_id;
  uint16_t offset;
  int is_short_EF = (p1 & 0x80) != 0;
  int r;

  if (!ac_check_status (AC_ADMIN_AUTHORIZED))
    {
      DEBUG_INFO ("security error.");
      GPG_SECURITY_FAILURE ();
      return;
    }

  if (is_short_EF)
    file_id = (p1 & 0x1f);
  else
    file_id = file_selection - FILE_EF_SERIAL_NO + FILEID_SERIAL_NO;

  if (!FILEID_CH_CERTIFICATE_IS_VALID && file_id == FILEID_CH_CERTIFICATE)
    {
      GPG_NO_FILE ();
      return;
    }

  if (op == MBD_OPRATION_UPDATE && file_id != FILEID_CH_CERTIFICATE)
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  if (file_id > FILEID_CH_CERTIFICATE)
    {
      GPG_NO_FILE ();
      return;
    }

  if (is_short_EF)
    {
      file_selection = file_id - FILEID_SERIAL_NO + FILE_EF_SERIAL_NO;
      offset = p2;

      if (op == MBD_OPRATION_UPDATE)
	{
	  r = flash_erase_binary (file_id);
	  if (r < 0)
	    {
	      DEBUG_INFO ("memory error.\r\n");
	      GPG_MEMORY_FAILURE ();
	      return;
	    }
	}
    }
  else
    offset = (p1 << 8) | p2;

  DEBUG_SHORT (len);
  DEBUG_SHORT (offset);

  if (file_id == FILEID_CH_CERTIFICATE && (len&1))
    /* It's OK the size of last write is odd.  */
    apdu.cmd_apdu_data[len++] = 0xff;

  r = flash_write_binary (file_id, apdu.cmd_apdu_data, len, offset);
  if (r < 0)
    {
      DEBUG_INFO ("memory error.\r\n");
      GPG_MEMORY_FAILURE ();
      return;
    }

#ifdef FLASH_UPGRADE_SUPPORT
  if (file_id >= FILEID_UPDATE_KEY_0 && file_id <= FILEID_UPDATE_KEY_3
      && len == 0 && offset == 0)
    {
      int i;
      const uint8_t *p;

      for (i = 0; i < 4; i++)
	{
	  p = gpg_get_firmware_update_key (i);
	  if (p[0] != 0x00 || p[1] != 0x00) /* still valid */
	    break;
	}

      if (i == 4)			/* all update keys are removed */
	{
	  p = gpg_get_firmware_update_key (0);
	  flash_erase_page ((uintptr_t)p);
	}
    }
#endif

  GPG_SUCCESS ();
}


#if defined(CERTDO_SUPPORT)
static void
cmd_update_binary (queue_t *ccid_comm)
{
  int len = apdu.cmd_apdu_data_len;

  (void)ccid_comm;
  DEBUG_INFO (" - UPDATE BINARY\r\n");
  modify_binary (MBD_OPRATION_UPDATE, P1 (apdu), P2 (apdu), len);
  DEBUG_INFO ("UPDATE BINARY done.\r\n");
}
#endif


static void
cmd_write_binary (queue_t *ccid_comm)
{
  int len = apdu.cmd_apdu_data_len;

  (void)ccid_comm;
  DEBUG_INFO (" - WRITE BINARY\r\n");
  modify_binary (MBD_OPRATION_WRITE, P1 (apdu), P2 (apdu), len);
  DEBUG_INFO ("WRITE BINARY done.\r\n");
}


#ifdef FLASH_UPGRADE_SUPPORT
static void
cmd_external_authenticate (queue_t *ccid_comm)
{
  const uint8_t *pubkey;
  const uint8_t *signature = apdu.cmd_apdu_data;
  int len = apdu.cmd_apdu_data_len;
  uint8_t keyno = P2 (apdu);
  int r;

  (void)ccid_comm;
  DEBUG_INFO (" - EXTERNAL AUTHENTICATE\r\n");

  if (keyno >= 4)
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  pubkey = gpg_get_firmware_update_key (keyno);
  if (len != 256
      || (pubkey[0] == 0xff && pubkey[1] == 0xff) /* not registered */
      || (pubkey[0] == 0x00 && pubkey[1] == 0x00) /* removed */)
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  r = rsa_verify (pubkey, FIRMWARE_UPDATE_KEY_CONTENT_LEN,
		  challenge, signature);
  random_bytes_free (challenge);
  challenge = NULL;

  if (r < 0)
    {
      GPG_SECURITY_FAILURE ();
      return;
    }

  eventflag_signal (openpgp_comm, EV_EXIT); /* signal to self.  */
  set_res_sw (0xff, 0xff);
  DEBUG_INFO ("EXTERNAL AUTHENTICATE done.\r\n");
}
#endif

static void
cmd_get_challenge (queue_t *ccid_comm)
{
  int len = apdu.expected_res_size;

  (void)ccid_comm;
  DEBUG_INFO (" - GET CHALLENGE\r\n");

  if (len > CHALLENGE_LEN)
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }
  else if (len == 0)
    /* Le is not specified.  Return full-sized challenge by GET_RESPONSE.  */
    len = CHALLENGE_LEN;

  if (challenge)
    random_bytes_free (challenge);

#ifdef ACKBTN_SUPPORT
  if (gpg_do_get_uif (GPG_KEY_FOR_SIGNING)
      || gpg_do_get_uif (GPG_KEY_FOR_DECRYPTION)
      || gpg_do_get_uif (GPG_KEY_FOR_AUTHENTICATION))
    eventflag_signal (ccid_comm, EV_EXEC_ACK_REQUIRED);
#endif

  challenge = random_bytes_get ();
  memcpy (res_APDU, challenge, len);
  res_APDU_size = len;
  GPG_SUCCESS ();
  DEBUG_INFO ("GET CHALLENGE done.\r\n");
}


#ifdef LIFE_CYCLE_MANAGEMENT_SUPPORT
static void
cmd_activate_file (queue_t *ccid_comm)
{
  (void)ccid_comm;
  if (file_selection != FILE_CARD_TERMINATED)
    {
      GPG_NO_RECORD ();
      return;
    }

  flash_activate ();
  //file_selection = FILE_DF_OPENPGP;
  file_selection = FILE_DF_SC_HSM;
  GPG_SUCCESS ();
}

static void
cmd_terminate_df (queue_t *ccid_comm)
{
  const uint8_t *ks_pw3;
  uint8_t p1 = P1 (apdu);
  uint8_t p2 = P2 (apdu);

  (void)ccid_comm;
  //if (file_selection != FILE_DF_OPENPGP)
  if (file_selection != FILE_DF_SC_HSM)
    {
      GPG_NO_RECORD ();
      return;
    }

  if (p1 != 0 || p2 != 0)
    {
      GPG_BAD_P1_P2();
      return;
    }

  if (apdu.cmd_apdu_data_len != 0)
    {
      GPG_WRONG_LENGTH();
      return;
    }

  ks_pw3 = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);

  if (!ac_check_status (AC_ADMIN_AUTHORIZED)
      && !((ks_pw3 && gpg_pw_locked (PW_ERR_PW3))
	   || (ks_pw3 == NULL && gpg_pw_locked (PW_ERR_PW1))))
    {
      /* Only allow the case admin authorized, or, admin pass is locked.  */
      GPG_SECURITY_FAILURE();
      return;
    }

  ac_reset_admin ();
  ac_reset_pso_cds ();
  ac_reset_other ();
  gpg_do_terminate ();
  flash_terminate ();
  file_selection = FILE_CARD_TERMINATED;
  GPG_SUCCESS ();
}
#endif


struct command
{
  uint8_t command;
  void (*cmd_handler) (queue_t *ccid_comm);
};

const struct command cmds[] = {
  { INS_VERIFY, cmd_verify },
  { INS_CHANGE_REFERENCE_DATA, cmd_change_password },
  { INS_PSO, cmd_pso },
  { INS_RESET_RETRY_COUNTER, cmd_reset_user_password },
#ifdef LIFE_CYCLE_MANAGEMENT_SUPPORT
  { INS_ACTIVATE_FILE, cmd_activate_file },
#endif
  { INS_PGP_GENERATE_ASYMMETRIC_KEY_PAIR, cmd_pgp_gakp },
#ifdef FLASH_UPGRADE_SUPPORT
  { INS_EXTERNAL_AUTHENTICATE,	            /* Not in OpenPGP card protocol */
    cmd_external_authenticate },
#endif
  { INS_GET_CHALLENGE, cmd_get_challenge }, /* Not in OpenPGP card protocol */
  { INS_INTERNAL_AUTHENTICATE, cmd_internal_authenticate },
  { INS_SELECT_FILE, cmd_select_file },
  { INS_READ_BINARY, cmd_read_binary },     /* Not in OpenPGP card protocol */
  { INS_READ_BINARY_ODD, cmd_read_binary },     /* Not in OpenPGP card protocol */
  { INS_GET_DATA, cmd_get_data },
  { INS_WRITE_BINARY, cmd_write_binary},    /* Not in OpenPGP card protocol */
#if defined(CERTDO_SUPPORT)
  { INS_UPDATE_BINARY, cmd_update_binary }, /* Not in OpenPGP card protocol */
#endif
  { INS_PUT_DATA, cmd_put_data },
  { INS_PUT_DATA_ODD, cmd_put_data },
#ifdef LIFE_CYCLE_MANAGEMENT_SUPPORT
  { INS_TERMINATE_DF, cmd_terminate_df},
#endif
};
#define NUM_CMDS ((int)(sizeof (cmds) / sizeof (struct command)))

static void
process_command_apdu (queue_t *ccid_comm)
{
    int i;
    uint8_t cmd = INS (apdu);

    for (i = 0; i < NUM_CMDS; i++)
        if (cmds[i].command == cmd)
            break;

    if (i < NUM_CMDS)
    {
        if (file_selection == FILE_CARD_TERMINATED
    	    && cmd != INS_SELECT_FILE && cmd != INS_ACTIVATE_FILE
    	    && cmd != INS_GET_CHALLENGE && cmd != INS_EXTERNAL_AUTHENTICATE)
	        GPG_APPLICATION_TERMINATED ();
        else if (selected_applet == NULL
           && cmd != INS_SELECT_FILE && cmd != INS_ACTIVATE_FILE
           && cmd != INS_GET_CHALLENGE && cmd != INS_EXTERNAL_AUTHENTICATE
           && cmd != INS_WRITE_BINARY && cmd != INS_UPDATE_BINARY
           && cmd != INS_READ_BINARY && cmd != INS_READ_BINARY_ODD)
	        GPG_NO_RECORD ();
        else
	    {
	        cmds[i].cmd_handler (ccid_comm);
	    }
    }
    else
    {
        DEBUG_INFO (" - ??");
        DEBUG_BYTE (cmd);
        GPG_NO_INS ();
    }
}

void openpgp_card_thread ()
{
    queue_t *ccid_comm = (queue_t *)multicore_fifo_pop_blocking();
    openpgp_comm = (queue_t *)multicore_fifo_pop_blocking();

    gpg_init ();

    while (1)
    {
#if defined(PINPAD_SUPPORT)
        int len, pw_len, newpw_len;
#endif
      
        uint32_t m;
        queue_remove_blocking(openpgp_comm, &m);

        DEBUG_INFO ("GPG!: ");

        if (m == EV_VERIFY_CMD_AVAILABLE)
	    {
#if defined(PINPAD_SUPPORT)
	        if (INS (apdu) != INS_VERIFY)
	        {
	            GPG_CONDITION_NOT_SATISFIED ();
	            goto done;
	        }

	        pw_len = get_pinpad_input (PIN_INPUT_CURRENT);
	        if (pw_len < 0)
	        {
	            GPG_ERROR ();
	            goto done;
	        }
	        memcpy (apdu.cmd_apdu_data, pin_input_buffer, pw_len);
	        apdu.cmd_apdu_data_len = pw_len;
#else
	        GPG_ERROR ();
	        goto done;
#endif
	    }
        else if (m == EV_MODIFY_CMD_AVAILABLE)
	    {
#if defined(PINPAD_SUPPORT)
	        uint8_t bConfirmPIN = apdu.cmd_apdu_data[0];
	        uint8_t *p = apdu.cmd_apdu_data;

	        if (INS (apdu) != INS_CHANGE_REFERENCE_DATA
	            && INS (apdu) != INS_RESET_RETRY_COUNTER
	            && INS (apdu) != INS_PUT_DATA)
	        {
	            GPG_CONDITION_NOT_SATISFIED ();
	            goto done;
	        }

	        if ((bConfirmPIN & 2))	/* Require old PIN */
	        {
	            pw_len = get_pinpad_input (PIN_INPUT_CURRENT);
	            if (pw_len < 0)
		        {
		            GPG_ERROR ();
		            goto done;
		        }
	            memcpy (p, pin_input_buffer, pw_len);
	            p += pw_len;
	        }
	        else
	            pw_len = 0;

	        newpw_len = get_pinpad_input (PIN_INPUT_NEW);
	        if (newpw_len < 0)
	        {
	            GPG_ERROR ();
	            goto done;
	        }
	        memcpy (p, pin_input_buffer, newpw_len);

	        if ((bConfirmPIN & 1))	/* New PIN twice */
	        {
	            len = get_pinpad_input (PIN_INPUT_CONFIRM);
	            if (len < 0)
		        {
		            GPG_ERROR ();
		            goto done;
		        }

	            if (len != newpw_len || memcmp (p, pin_input_buffer, len) != 0)
		        {
		            GPG_SECURITY_FAILURE ();
		            goto done;
		        }
	        }

	        apdu.cmd_apdu_data_len = pw_len + newpw_len;
#else
	        GPG_ERROR ();
	        goto done;
#endif
	    }
        else if (m == EV_EXIT)
	        break;

        process_command_apdu (ccid_comm);
        done:;
        uint32_t flag = EV_EXEC_FINISHED;
        queue_add_blocking(ccid_comm, &flag);
    }

    gpg_fini ();
}
