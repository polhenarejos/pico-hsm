/*
 * openpgp-do.c -- OpenPGP card Data Objects (DO) handling
 *
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018,
 *               2020, 2021
 *               Free Software Initiative of Japan1161
 
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

#include "sys.h"
#include "gnuk.h"
#include "status-code.h"
#include "random.h"
#include "common.h"
#include "mbedtls/aes.h"
#include "mbedtls/sha512.h"
#include "shake256.h"

/* Forward declaration */
#define CLEAN_PAGE_FULL 1
#define CLEAN_SINGLE    0
static void gpg_do_delete_prvkey (enum kind_of_key kk, int clean_page_full);
static void gpg_reset_digital_signature_counter (void);

#define PASSWORD_ERRORS_MAX 3	/* >= errors, it will be locked */
static const uint8_t *pw_err_counter_p[3];

static int
gpg_pw_get_err_counter (uint8_t which)
{
  return flash_cnt123_get_value (pw_err_counter_p[which]);
}

int
gpg_pw_get_retry_counter (int who)
{
  if (who == 0x81 || who == 0x82)
    return PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_PW1);
  else if (who == 0x83)
    return PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_PW3);
  else
    return PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_RC);
}

int
gpg_pw_locked (uint8_t which)
{
  if (gpg_pw_get_err_counter (which) >= PASSWORD_ERRORS_MAX)
    return 1;
  else
    return 0;
}

void
gpg_pw_reset_err_counter (uint8_t which)
{
  flash_cnt123_clear (&pw_err_counter_p[which]);
  if (pw_err_counter_p[which] != NULL)
    GPG_MEMORY_FAILURE ();
}

void
gpg_pw_increment_err_counter (uint8_t which)
{
  flash_cnt123_increment (which, &pw_err_counter_p[which]);
}


uint16_t data_objects_number_of_bytes;

/*
 * Compile time vars:
 *   Historical Bytes, Extended Capabilities.
 */

/* Historical Bytes */
const uint8_t historical_bytes[] __attribute__ ((aligned (1))) = {
  10,
  0x00,
  0x31, 0x84,			/* Full DF name, GET DATA, MF */
  0x73,
  0x80, 0x01, 0x80,		/* Full DF name */
				/* 1-byte */
				/* Command chaining, No extended Lc and Le */
#ifdef LIFE_CYCLE_MANAGEMENT_SUPPORT
  0x05,
#else
  0x00,
#endif
  0x90, 0x00			/* Status info */
};

/* Extended Capabilities */
static const uint8_t extended_capabilities[] __attribute__ ((aligned (1))) = {
  10,
  0x75,				/*
				 * No Secure Messaging supported
				 * GET CHALLENGE supported
				 * Key import supported
				 * PW status byte can be put
				 * No private_use_DO
				 * Algorithm attrs are changable
				 * No DEC with AES
				 * KDF-DO available
				 */
  0,		  /* Secure Messaging Algorithm: N/A (TDES=0, AES=1) */
  0x00, CHALLENGE_LEN, 		/* Max size of GET CHALLENGE */
#ifdef CERTDO_SUPPORT
  0x08, 0x00,	  /* max. length of cardholder certificate (2KiB) */
#else
  0x00, 0x00,
#endif
  /* Max. length of command APDU data */
  0x00, 0xff,
  /* Max. length of response APDU data */
  0x01, 0x00,
};

#ifdef ACKBTN_SUPPORT
/* General Feature Management */
static const uint8_t feature_mngmnt[] __attribute__ ((aligned (1))) = {
  3,
  0x81, 0x01, 0x20,
};
#endif

/* Algorithm Attributes */
#define OPENPGP_ALGO_RSA   0x01
#define OPENPGP_ALGO_ECDH  0x12
#define OPENPGP_ALGO_ECDSA 0x13
#define OPENPGP_ALGO_EDDSA 0x16 /* It catches 22, finally.  */

static const uint8_t algorithm_attr_ed448[] __attribute__ ((aligned (1))) = {
  4,
  OPENPGP_ALGO_EDDSA,
  /* OID of Ed448 */
  0x2b, 0x65, 0x71
};

static const uint8_t algorithm_attr_x448[] __attribute__ ((aligned (1))) = {
  4,
  OPENPGP_ALGO_ECDH,
  /* OID of X448 */
  0x2b, 0x65, 0x6f
};

static const uint8_t algorithm_attr_rsa2k[] __attribute__ ((aligned (1))) = {
  6,
  OPENPGP_ALGO_RSA,
  0x08, 0x00,	      /* Length modulus (in bit): 2048 */
  0x00, 0x20,	      /* Length exponent (in bit): 32  */
  0x00		      /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_rsa4k[] __attribute__ ((aligned (1))) = {
  6,
  OPENPGP_ALGO_RSA,
  0x10, 0x00,	      /* Length modulus (in bit): 4096 */
  0x00, 0x20,	      /* Length exponent (in bit): 32  */
  0x00		      /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_p256k1[] __attribute__ ((aligned (1))) = {
  6,
  OPENPGP_ALGO_ECDSA,
  0x2b, 0x81, 0x04, 0x00, 0x0a /* OID of curve secp256k1 */
};

static const uint8_t algorithm_attr_ed25519[] __attribute__ ((aligned (1))) = {
  10,
  OPENPGP_ALGO_EDDSA,
  /* OID of the curve Ed25519 */
  0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
};

static const uint8_t algorithm_attr_cv25519[] __attribute__ ((aligned (1))) = {
  11,
  OPENPGP_ALGO_ECDH,
  /* OID of the curve Curve25519 */
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};


/*
 * Representation of PW1_LIFETIME:
 *    0: PW1_LIEFTIME_P == NULL : PW1 is valid for single PSO:CDS command
 *    1: PW1_LIEFTIME_P != NULL : PW1 is valid for several PSO:CDS commands
 *
 * The address in the variable PW1_LIEFTIME_P is used when filling zero
 * in flash memory
 */
static const uint8_t *pw1_lifetime_p;

static int
gpg_get_pw1_lifetime (void)
{
  if (pw1_lifetime_p == NULL)
    return 0;
  else
    return 1;
}


/*
 * Representation of algorithm attributes:
 *    0: ALGO_ATTR_<>_P == NULL : RSA-2048
 *    N: ALGO_ATTR_<>_P != NULL :
 *
 */
static const uint8_t *algo_attr_sig_p;
static const uint8_t *algo_attr_dec_p;
static const uint8_t *algo_attr_aut_p;

static const uint8_t **
get_algo_attr_pointer (enum kind_of_key kk)
{
  if (kk == GPG_KEY_FOR_SIGNING)
    return &algo_attr_sig_p;
  else if (kk == GPG_KEY_FOR_DECRYPTION)
    return &algo_attr_dec_p;
  else
    return &algo_attr_aut_p;
}

static int
kk_to_nr (enum kind_of_key kk)
{
  int nr;

  if (kk == GPG_KEY_FOR_SIGNING)
    nr = NR_KEY_ALGO_ATTR_SIG;
  else if (kk == GPG_KEY_FOR_DECRYPTION)
    nr = NR_KEY_ALGO_ATTR_DEC;
  else
    nr = NR_KEY_ALGO_ATTR_AUT;

  return nr;
}

int
gpg_get_algo_attr (enum kind_of_key kk)
{
  const uint8_t *algo_attr_p = *get_algo_attr_pointer (kk);

  if (algo_attr_p == NULL)
    return ALGO_RSA2K;

  return algo_attr_p[1];
}

static void
gpg_reset_algo_attr (enum kind_of_key kk)
{
  gpg_do_delete_prvkey (kk, CLEAN_PAGE_FULL);
  if (kk == GPG_KEY_FOR_SIGNING)
    {
      gpg_reset_digital_signature_counter ();
      gpg_do_write_simple (NR_DO_FP_SIG, NULL, 0);
      gpg_do_write_simple (NR_DO_KGTIME_SIG, NULL, 0);
    }
  else if (kk == GPG_KEY_FOR_DECRYPTION)
    {
      gpg_do_write_simple (NR_DO_FP_DEC, NULL, 0);
      gpg_do_write_simple (NR_DO_KGTIME_DEC, NULL, 0);
    }
  else
    {
      gpg_do_write_simple (NR_DO_FP_AUT, NULL, 0);
      gpg_do_write_simple (NR_DO_KGTIME_AUT, NULL, 0);
    }
}

static const uint8_t *
get_algo_attr_data_object (enum kind_of_key kk)
{
  const uint8_t *algo_attr_p = *get_algo_attr_pointer (kk);

  if (algo_attr_p == NULL)
    return algorithm_attr_rsa2k;

  switch (algo_attr_p[1])
    {
    case ALGO_RSA4K:
      return algorithm_attr_rsa4k;
    case ALGO_SECP256K1:
      return algorithm_attr_p256k1;
    case ALGO_CURVE25519:
      return algorithm_attr_cv25519;
    case ALGO_ED25519:
      return algorithm_attr_ed25519;
    case ALGO_ED448:
      return algorithm_attr_ed448;
    case ALGO_X448:
      return algorithm_attr_x448;
    default:
      return algorithm_attr_rsa2k;
    }
}

int
gpg_get_algo_attr_key_size (enum kind_of_key kk, enum size_of_key s)
{
  const uint8_t *algo_attr_p = *get_algo_attr_pointer (kk);

  if (algo_attr_p == NULL)	/* RSA-2048 */
    goto rsa2k;

  switch (algo_attr_p[1])
    {
    case ALGO_RSA4K:
      if (s == GPG_KEY_STORAGE)
	return 1024;
      else
	return 512;
    case ALGO_SECP256K1:
      if (s == GPG_KEY_STORAGE)
	return 128;
      else if (s == GPG_KEY_PUBLIC)
	return 64;
      else
	return 32;
    case ALGO_CURVE25519:
      if (s == GPG_KEY_STORAGE)
	return 64;
      else
	return 32;
    case ALGO_ED25519:
      if (s == GPG_KEY_STORAGE)
	return 128;
      else if (s == GPG_KEY_PUBLIC)
	return 32;
      else
	return 64;
    case ALGO_ED448:
      if (s == GPG_KEY_STORAGE)
	return 256;
      else if (s == GPG_KEY_PUBLIC)
	return 57;
      else
	return 128;
    case ALGO_X448:
      if (s == GPG_KEY_STORAGE)
	return 112;
      else
	return 56;
    default:
    rsa2k:
      if (s == GPG_KEY_STORAGE)
	return 512;
      else
	return 256;
    }
}


static uint32_t digital_signature_counter;

static const uint8_t *
gpg_write_digital_signature_counter (const uint8_t *p, uint32_t dsc)
{
  uint16_t hw0, hw1;

  if ((dsc >> 10) == 0)
    { /* no upper bits */
      hw1 = NR_COUNTER_DS_LSB | ((dsc & 0x0300) >> 8) | ((dsc & 0x00ff) << 8);
      flash_put_data_internal (p, hw1);
      return p+2;
    }
  else
    {
      hw0 = NR_COUNTER_DS | ((dsc & 0xfc0000) >> 18) | ((dsc & 0x03fc00) >> 2);
      hw1 = NR_COUNTER_DS_LSB | ((dsc & 0x0300) >> 8) | ((dsc & 0x00ff) << 8);
      flash_put_data_internal (p, hw0);
      flash_put_data_internal (p+2, hw1);
      return p+4;
    }
}

static void
gpg_reset_digital_signature_counter (void)
{
  if (digital_signature_counter != 0)
    {
      flash_put_data (NR_COUNTER_DS);
      flash_put_data (NR_COUNTER_DS_LSB);
      digital_signature_counter = 0;
    }
}

void
gpg_increment_digital_signature_counter (void)
{
  uint16_t hw0, hw1;
  uint32_t dsc = (digital_signature_counter + 1) & 0x00ffffff;

  if ((dsc & 0x03ff) == 0)
    { /* carry occurs from l10 to h14 */
      hw0 = NR_COUNTER_DS | ((dsc & 0xfc0000) >> 18) | ((dsc & 0x03fc00) >> 2);
      hw1 = NR_COUNTER_DS_LSB;	/* zero */
      flash_put_data (hw0);
      flash_put_data (hw1);
    }
  else
    {
      hw1 = NR_COUNTER_DS_LSB | ((dsc & 0x0300) >> 8) | ((dsc & 0x00ff) << 8);
      flash_put_data (hw1);
    }

  digital_signature_counter = dsc;

  if (gpg_get_pw1_lifetime () == 0)
    ac_reset_pso_cds ();
}


#define SIZE_FINGER_PRINT 20
#define SIZE_KEYGEN_TIME 4	/* RFC4880 */

enum do_type {
  DO_FIXED,
  DO_VAR,
  DO_CMP_READ,
  DO_PROC_READ,
  DO_PROC_WRITE,
  DO_PROC_READWRITE,
};

struct do_table_entry {
  uint16_t tag;
  enum do_type do_type;
  uint8_t ac_read;
  uint8_t ac_write;
  const void *obj;
};

static uint8_t *res_p;

static void copy_do_1 (uint16_t tag, const uint8_t *do_data, int with_tag);
static const struct do_table_entry *get_do_entry (uint16_t tag);

#define GPG_DO_AID		0x004f
#define GPG_DO_NAME		0x005b
#define GPG_DO_LOGIN_DATA	0x005e
#define GPG_DO_CH_DATA		0x0065
#define GPG_DO_APP_DATA		0x006e
#define GPG_DO_DISCRETIONARY    0x0073
#define GPG_DO_SS_TEMP		0x007a
#define GPG_DO_DS_COUNT		0x0093
#define GPG_DO_EXTCAP		0x00c0
#define GPG_DO_ALG_SIG		0x00c1
#define GPG_DO_ALG_DEC		0x00c2
#define GPG_DO_ALG_AUT		0x00c3
#define GPG_DO_PW_STATUS	0x00c4
#define GPG_DO_FP_ALL		0x00c5
#define GPG_DO_CAFP_ALL		0x00c6
#define GPG_DO_FP_SIG		0x00c7
#define GPG_DO_FP_DEC		0x00c8
#define GPG_DO_FP_AUT		0x00c9
#define GPG_DO_CAFP_1		0x00ca
#define GPG_DO_CAFP_2		0x00cb
#define GPG_DO_CAFP_3		0x00cc
#define GPG_DO_KGTIME_ALL	0x00cd
#define GPG_DO_KGTIME_SIG	0x00ce
#define GPG_DO_KGTIME_DEC	0x00cf
#define GPG_DO_KGTIME_AUT	0x00d0
#define GPG_DO_RESETTING_CODE	0x00d3
#define GPG_DO_UIF_SIG		0x00d6
#define GPG_DO_UIF_DEC		0x00d7
#define GPG_DO_UIF_AUT		0x00d8
#define GPG_DO_KDF		0x00f9
#define GPG_DO_ALG_INFO		0x00fa
#define GPG_DO_KEY_IMPORT	0x3fff
#define GPG_DO_LANGUAGE		0x5f2d
#define GPG_DO_SEX		0x5f35
#define GPG_DO_URL		0x5f50
#define GPG_DO_HIST_BYTES	0x5f52
#define GPG_DO_CH_CERTIFICATE	0x7f21
#define GPG_DO_FEATURE_MNGMNT	0x7f74

static const uint8_t *do_ptr[NR_DO__LAST__];

static int
do_tag_to_nr (uint16_t tag)
{
  switch (tag)
    {
    case GPG_DO_SEX:
      return NR_DO_SEX;
    case GPG_DO_FP_SIG:
      return NR_DO_FP_SIG;
    case GPG_DO_FP_DEC:
      return NR_DO_FP_DEC;
    case GPG_DO_FP_AUT:
      return NR_DO_FP_AUT;
    case GPG_DO_CAFP_1:
      return NR_DO_CAFP_1;
    case GPG_DO_CAFP_2:
      return NR_DO_CAFP_2;
    case GPG_DO_CAFP_3:
      return NR_DO_CAFP_3;
    case GPG_DO_KGTIME_SIG:
      return NR_DO_KGTIME_SIG;
    case GPG_DO_KGTIME_DEC:
      return NR_DO_KGTIME_DEC;
    case GPG_DO_KGTIME_AUT:
      return NR_DO_KGTIME_AUT;
    case GPG_DO_LOGIN_DATA:
      return NR_DO_LOGIN_DATA;
    case GPG_DO_URL:
      return NR_DO_URL;
    case GPG_DO_NAME:
      return NR_DO_NAME;
    case GPG_DO_LANGUAGE:
      return NR_DO_LANGUAGE;
    case GPG_DO_KDF:
      return NR_DO_KDF;
    default:
      return -1;
    }
}

static void
copy_tag (uint16_t tag)
{
  if (tag < 0x0100)
    *res_p++ = (tag & 0xff);
  else
    {
      *res_p++ = (tag >> 8);
      *res_p++ = (tag & 0xff);
    }
}


#define SIZE_FP 20
#define SIZE_KGTIME 4

static void
do_fp_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_FP*3;
    }

  data = gpg_do_read_simple (NR_DO_FP_SIG);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_FP_DEC);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_FP_AUT);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;
}

static void
do_cafp_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_FP*3;
    }

  data = gpg_do_read_simple (NR_DO_CAFP_1);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_CAFP_2);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_CAFP_2);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;
}

static void
do_kgtime_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_KGTIME*3;
    }

  data = gpg_do_read_simple (NR_DO_KGTIME_SIG);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;

  data = gpg_do_read_simple (NR_DO_KGTIME_DEC);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;

  data = gpg_do_read_simple (NR_DO_KGTIME_AUT);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;
}

const uint8_t openpgpcard_aid[] = {
  0xd2, 0x76,		    /* D: National, 276: DEU ISO 3166-1 */
  0x00, 0x01, 0x24,	    /* Registered Application Provider Identifier */
  0x01,			    /* Application: OpenPGPcard */
  0x02, 0x00,		    /* Version 2.0 */
  /* v. id */ /*   serial number   */
  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, /* To be overwritten */
};

static void
do_openpgpcard_aid (uint16_t tag, int with_tag)
{
  const volatile uint8_t *p = openpgpcard_aid;
  uint16_t vid = (p[8] << 8) | p[9];

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = 16;
    }

  if (vid == 0xffff || vid == 0x0000)
    {
      const uint8_t *u = unique_device_id () + (MHZ < 96 ? 8: 0);

      memcpy (res_p, openpgpcard_aid, 8);
      res_p += 8;

      /* vid == 0xfffe: serial number is four random bytes */
      *res_p++ = 0xff;
      *res_p++ = 0xfe;

      *res_p++ = u[3];
      *res_p++ = u[2];
      *res_p++ = u[1];
      *res_p++ = u[0];
    }
  else
    {
      memcpy (res_p, openpgpcard_aid, 14);
      res_p += 14;
    }

  *res_p++ = 0;
  *res_p++ = 0;
}

static void
do_ds_count (uint16_t tag, int with_tag)
{
  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = 3;
    }

  *res_p++ = (digital_signature_counter >> 16) & 0xff;
  *res_p++ = (digital_signature_counter >> 8) & 0xff;
  *res_p++ = digital_signature_counter & 0xff;
}

static void
do_alg_info (uint16_t tag, int with_tag)
{
  uint8_t *len_p = NULL;
  int i;

  if (with_tag)
    {
      copy_tag (tag);
      len_p = res_p;
      *res_p++ = 0;	 /* Filled later, assuming length is <= 127 */
    }

  for (i = 0; i < 3; i++)
    {
      uint16_t tag_algo = GPG_DO_ALG_SIG + i;

      copy_do_1 (tag_algo, algorithm_attr_rsa2k, 1);
      copy_do_1 (tag_algo, algorithm_attr_rsa4k, 1);
      copy_do_1 (tag_algo, algorithm_attr_p256k1, 1);
      if (i == 0 || i == 2)
	{
	  copy_do_1 (tag_algo, algorithm_attr_ed25519, 1);
	  copy_do_1 (tag_algo, algorithm_attr_ed448, 1);
	}
      if (i == 1)
	{
	  copy_do_1 (tag_algo, algorithm_attr_cv25519, 1);
	  copy_do_1 (tag_algo, algorithm_attr_x448, 1);
	}
    };

  if (len_p)
    *len_p = res_p - len_p - 1; /* Actually, it's 127-byte long.  */
}

static int
rw_pw_status (uint16_t tag, int with_tag,
	      const uint8_t *data, int len, int is_write)
{
  if (is_write)
    {
      if (len != 1)
	return 0;		/* Failure */

      /* The first byte of DATA specifies the lifetime.  */
      if (data[0] == 0 && pw1_lifetime_p != NULL)
	{
	  flash_bool_clear (&pw1_lifetime_p);
	  if (pw1_lifetime_p != NULL) /* No change after update */
	    return 0;
	}
      else if (pw1_lifetime_p == NULL)
	{
	  pw1_lifetime_p = flash_bool_write (NR_BOOL_PW1_LIFETIME);
	  if (pw1_lifetime_p == NULL) /* No change after update */
	    return 0;
	}

      return 1;			/* Success */
    }
  else
    {
      if (with_tag)
	{
	  copy_tag (tag);
	  *res_p++ = SIZE_PW_STATUS_BYTES;
	}

      *res_p++ = gpg_get_pw1_lifetime ();
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_PW1);
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_RC);
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_pw_get_err_counter (PW_ERR_PW3);
      return 1;
    }
}

static int
rw_algorithm_attr (uint16_t tag, int with_tag,
		   const uint8_t *data, int len, int is_write)
{
  enum kind_of_key kk;

  if (tag == GPG_DO_ALG_SIG)
    kk = GPG_KEY_FOR_SIGNING;
  else if (tag == GPG_DO_ALG_DEC)
    kk = GPG_KEY_FOR_DECRYPTION;
  else
    kk = GPG_KEY_FOR_AUTHENTICATION;

  if (is_write)
    {
      int algo = -1;
      const uint8_t **algo_attr_pp = get_algo_attr_pointer (kk);

      if (len == 4)
	{
	  if (memcmp (data, algorithm_attr_ed448+1, 4) == 0)
	    algo = ALGO_ED448;
	  else if (memcmp (data, algorithm_attr_x448+1, 4) == 0)
	    algo = ALGO_X448;
	}
      if (len == 6)
	{
	  if (memcmp (data, algorithm_attr_rsa2k+1, 6) == 0)
	    algo = ALGO_RSA2K;
	  else if (memcmp (data, algorithm_attr_rsa4k+1, 6) == 0)
	    algo = ALGO_RSA4K;
	  else if ((tag != GPG_DO_ALG_DEC
		    && memcmp (data, algorithm_attr_p256k1+1, 6) == 0)
		   || (tag == GPG_DO_ALG_DEC && data[0]==OPENPGP_ALGO_ECDH
		       && memcmp (data+1, algorithm_attr_p256k1+2, 5) == 0))
	    algo = ALGO_SECP256K1;
	}
      else if (len == 10 && memcmp (data, algorithm_attr_ed25519+1, 10) == 0)
	algo = ALGO_ED25519;
      else if (len == 11 && memcmp (data, algorithm_attr_cv25519+1, 11) == 0)
	algo = ALGO_CURVE25519;

      if (algo < 0)
	return 0;		/* Error.  */
      else if (algo == ALGO_RSA2K && *algo_attr_pp != NULL)
	{
	  gpg_reset_algo_attr (kk);
          /* Read it again, since GC may occur.  */
          algo_attr_pp = get_algo_attr_pointer (kk);
	  flash_enum_clear (algo_attr_pp);
	  if (*algo_attr_pp != NULL)
	    return 0;
	}
      else if ((algo != ALGO_RSA2K && *algo_attr_pp == NULL) ||
	       (*algo_attr_pp != NULL && (*algo_attr_pp)[1] != algo))
	{
	  gpg_reset_algo_attr (kk);
          /* Read it again, since GC may occur.  */
          algo_attr_pp = get_algo_attr_pointer (kk);
          if (*algo_attr_pp)
            flash_enum_clear (algo_attr_pp);
	  *algo_attr_pp = flash_enum_write (kk_to_nr (kk), algo);
	  if (*algo_attr_pp == NULL)
	    return 0;
	}

      return 1;
    }
  else
    {
      const uint8_t *algo_attr_do = get_algo_attr_data_object (kk);

      copy_do_1 (tag, algo_attr_do, with_tag);
      /* Override the byte when GPG_DO_ALG_DEC.  */
      if (tag == GPG_DO_ALG_DEC && algo_attr_do[1] == OPENPGP_ALGO_ECDSA)
	*(res_p - algo_attr_do[0]) = OPENPGP_ALGO_ECDH;
      return 1;
    }
}


static uint8_t uif_flags;	/* Six bits of flags */

#ifdef ACKBTN_SUPPORT
int
gpg_do_get_uif (enum kind_of_key kk)
{
  return ((uif_flags >> (kk * 2)) & 3) != 0;
}

static int
rw_uif (uint16_t tag, int with_tag, const uint8_t *data, int len, int is_write)
{
  uint8_t nr;
  int v;

  if (tag != GPG_DO_UIF_SIG && tag != GPG_DO_UIF_DEC && tag != GPG_DO_UIF_AUT)
    return 0;		/* Failure */

  nr = (tag - GPG_DO_UIF_SIG) + NR_DO_UIF_SIG;
  v = (uif_flags >> ((tag - GPG_DO_UIF_SIG) * 2)) & 3;
  if (is_write)
    {
      const uint8_t *p;

      if (len != 2 || data[1] != 0x20)
	return 0;

      if (v == 2)
	return 0;

      if (data[0] != 0x00 && data[0] != 0x01 && data[0] != 0x02)
	return 0;

      p = flash_enum_write (nr, data[0]);
      if (p == NULL)
	return 0;

      uif_flags &= ~(3 << ((nr - NR_DO_UIF_SIG) * 2));
      uif_flags |= (data[0] & 3) << ((nr - NR_DO_UIF_SIG) * 2);
      return 1;
    }
  else
    {
      if (with_tag)
	{
	  copy_tag (tag);
	  *res_p++ = 2;
	}

      *res_p++ = v;
      *res_p++ = 0x20;
      return 1;
    }
}
#endif


#define SIZE_OF_KDF_DO_MIN              90
#define SIZE_OF_KDF_DO_MAX             110
#define OPENPGP_KDF_ITERSALTED_S2K 3
#define OPENPGP_SHA256             8

static int
rw_kdf (uint16_t tag, int with_tag, const uint8_t *data, int len, int is_write)
{
  if (tag != GPG_DO_KDF)
    return 0;		/* Failure */

  if (is_write)
    {
      const uint8_t **do_data_p = (const uint8_t **)&do_ptr[NR_DO_KDF];

      /* KDF DO can be changed only when no keys are registered.  */
      if (do_ptr[NR_DO_PRVKEY_SIG] || do_ptr[NR_DO_PRVKEY_DEC]
	  || do_ptr[NR_DO_PRVKEY_AUT])
	return 0;

      /* The valid data format is:
	 Deleting:
	   nothing
	 Minimum (for admin-less):
	   81 01 03 = KDF_ITERSALTED_S2K
	   82 01 08 = SHA256
	   83 04 4-byte... = count
	   84 08 8-byte... = salt
	   87 20 32-byte user hash
	   88 20 32-byte admin hash
	 Full:
	   81 01 03 = KDF_ITERSALTED_S2K
	   82 01 08 = SHA256
	   83 04 4-byte... = count
	   84 08 8-byte... = salt user
	   85 08 8-byte... = salt reset-code
	   86 08 8-byte... = salt admin
	   87 20 32-byte user hash
	   88 20 32-byte admin hash
      */
      if (!(len == 0
	    || (len == SIZE_OF_KDF_DO_MIN &&
		(data[0] == 0x81 && data[3] == 0x82 && data[6] == 0x83
		 && data[12] == 0x84 && data[22] == 0x87 && data[56] == 0x88))
	    || (len == SIZE_OF_KDF_DO_MAX &&
		(data[0] == 0x81 && data[3] == 0x82 && data[6] == 0x83
		 && data[12] == 0x84 && data[22] == 0x85 && data[32] == 0x86
		 && data[42] == 0x87 && data[76] == 0x88))))
	return 0;

      if (*do_data_p)
	flash_do_release (*do_data_p);

      /* Clear all keystrings and auth states */
      gpg_do_write_simple (NR_DO_KEYSTRING_PW1, NULL, 0);
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);
      gpg_do_write_simple (NR_DO_KEYSTRING_PW3, NULL, 0);
      ac_reset_admin ();
      ac_reset_pso_cds ();
      ac_reset_other ();

      if (len == 0)
	{
	  *do_data_p = NULL;
	  return 1;
	}
      else
	{
	  *do_data_p = flash_do_write (NR_DO_KDF, data, len);
	  if (*do_data_p)
	    return 1;
	  else
	    return 0;
	}
    }
  else
    {
      if (do_ptr[NR_DO_KDF])
	copy_do_1 (tag, do_ptr[NR_DO_KDF], with_tag);
      else
	return 0;

      return 1;
    }
}


/*
 * Check LEN is valid for HOW_MANY of passphrase string.
 *
 * HOW_MANY = 1: LEN is valid for a single passphrase string.
 * HOW_MANY = 2: LEN is valid for two single passphrase strings.
 *               This is used to change passphrase.
 *               The second passphrase may be nothing.
 *
 * LEN = 0: Check if KDF-DO is available.
 */
int
gpg_do_kdf_check (int len, int how_many)
{
  const uint8_t *kdf_do = do_ptr[NR_DO_KDF];

  if (len == 0)
    return kdf_do != NULL;

  if (kdf_do)
    {
      const uint8_t *kdf_spec = kdf_do+1;
      int kdf_do_len = kdf_do[0];
      int hash_len;

      if (kdf_do_len == SIZE_OF_KDF_DO_MIN)
	hash_len = kdf_spec[23];
      else
	hash_len = kdf_spec[43];

      if ((hash_len * how_many) != len && hash_len != len)
	return 0;
    }

  return 1;
}

void
gpg_do_get_initial_pw_setting (int is_pw3, int *r_len, const uint8_t **r_p)
{
  const uint8_t *kdf_do = do_ptr[NR_DO_KDF];

  if (kdf_do)
    {
      int len = kdf_do[0];
      const uint8_t *kdf_spec = kdf_do+1;

      *r_len = 32;

      if (len == SIZE_OF_KDF_DO_MIN)
	{
	  if (is_pw3)
	    *r_p = kdf_spec + 58;
	  else
	    *r_p = kdf_spec + 24;
	}
      else
	{
	  if (is_pw3)
	    *r_p = kdf_spec + 78;
	  else
	    *r_p = kdf_spec + 44;
	}
    }
  else
    {
      if (is_pw3)
	{
	  *r_len = strlen (OPENPGP_CARD_INITIAL_PW3);
	  *r_p = (const uint8_t *)OPENPGP_CARD_INITIAL_PW3;
	}
      else
	{
	  *r_len = strlen (OPENPGP_CARD_INITIAL_PW1);
	  *r_p = (const uint8_t *)OPENPGP_CARD_INITIAL_PW1;
	}
    }
}

static int
proc_resetting_code (const uint8_t *data, int len)
{
  const uint8_t *old_ks = keystring_md_pw3;
  uint8_t new_ks0[KEYSTRING_SIZE];
  uint8_t *new_ks = KS_GET_KEYSTRING (new_ks0);
  const uint8_t *newpw;
  int newpw_len;
  int r;
  uint8_t *salt = KS_GET_SALT (new_ks0);

  DEBUG_INFO ("Resetting Code!\r\n");

  if (len == 0)
    {				/* Removal of resetting code.  */
      enum kind_of_key kk0;

      for (kk0 = 0; kk0 <= GPG_KEY_FOR_AUTHENTICATION; kk0++)
	gpg_do_chks_prvkey (kk0, BY_RESETCODE, NULL, 0, NULL);
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);
    }
  else
    {
      if (gpg_do_kdf_check (len, 1) == 0)
	return 0;

      newpw_len = len;
      newpw = data;
      new_ks0[0] = newpw_len;
      random_get_salt (salt);
      s2k (salt, SALT_SIZE, newpw, newpw_len, new_ks);
      r = gpg_change_keystring (admin_authorized, old_ks, BY_RESETCODE, new_ks);
      if (r <= -2)
	{
	  DEBUG_INFO ("memory error.\r\n");
	  return 0;
	}
      else if (r < 0)
	{
	  DEBUG_INFO ("security error.\r\n");
	  return 0;
	}
      else if (r == 0)
	{
	  DEBUG_INFO ("error (no prvkey).\r\n");
	  return 0;
	}
      else
	{
	  DEBUG_INFO ("done.\r\n");
	  gpg_do_write_simple (NR_DO_KEYSTRING_RC, new_ks0, KS_META_SIZE);
	}
    }

  gpg_pw_reset_err_counter (PW_ERR_RC);
  return 1;
}

static void
encrypt (const uint8_t *key, const uint8_t *iv, uint8_t *data, int len)
{
  mbedtls_aes_context aes;
  uint8_t iv0[INITIAL_VECTOR_SIZE];
  size_t iv_offset;

  DEBUG_INFO ("ENC\r\n");
  DEBUG_BINARY (data, len);

  mbedtls_aes_setkey_enc (&aes, key, 128);
  memcpy (iv0, iv, INITIAL_VECTOR_SIZE);
  iv_offset = 0;
  mbedtls_aes_crypt_cfb128 (&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, iv0, data, data);
}

/* For three keys: Signing, Decryption, and Authentication */
struct key_data kd[3];

static void
decrypt (const uint8_t *key, const uint8_t *iv, uint8_t *data, int len)
{
  mbedtls_aes_context aes;
  uint8_t iv0[INITIAL_VECTOR_SIZE];
  size_t iv_offset;

  mbedtls_aes_setkey_enc (&aes, key, 128); /* This is setkey_enc, because of CFB.  */
  memcpy (iv0, iv, INITIAL_VECTOR_SIZE);
  iv_offset = 0;
  mbedtls_aes_crypt_cfb128 (&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, iv0, data, data);

  DEBUG_INFO ("DEC\r\n");
  DEBUG_BINARY (data, len);
}

static void
encrypt_dek (const uint8_t *key_string, uint8_t *dek)
{
  mbedtls_aes_context aes;

  mbedtls_aes_setkey_enc (&aes, key_string, 128);
  mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_ENCRYPT, dek, dek);
}

static void
decrypt_dek (const uint8_t *key_string, uint8_t *dek)
{
  mbedtls_aes_context aes;

  mbedtls_aes_setkey_dec (&aes, key_string, 128);
  mbedtls_aes_crypt_ecb (&aes, MBEDTLS_AES_DECRYPT, dek, dek);
}

static uint8_t
get_do_ptr_nr_for_kk (enum kind_of_key kk)
{
  switch (kk)
    {
    case GPG_KEY_FOR_SIGNING:
      return NR_DO_PRVKEY_SIG;
    case GPG_KEY_FOR_DECRYPTION:
      return NR_DO_PRVKEY_DEC;
    case GPG_KEY_FOR_AUTHENTICATION:
      return NR_DO_PRVKEY_AUT;
    }
  return NR_DO_PRVKEY_SIG;
}

void
gpg_do_clear_prvkey (enum kind_of_key kk)
{
  memset (kd[kk].data, 0, MAX_PRVKEY_LEN);
}


#define CHECKSUM_ADDR(kdi,prvkey_len) \
	(&(kdi).data[prvkey_len / sizeof (uint32_t)])
#define kdi_len(prvkey_len) (prvkey_len+DATA_ENCRYPTION_KEY_SIZE)
struct key_data_internal {
  uint32_t data[(MAX_PRVKEY_LEN+DATA_ENCRYPTION_KEY_SIZE) / sizeof (uint32_t)];
  /*
   * Secret key data.
   * RSA: p and q, ECDSA/ECDH: d, EdDSA: a+seed
   */
  /* Checksum */
};

#define CKDC_CALC  0
#define CKDC_CHECK 1
static int
compute_key_data_checksum (struct key_data_internal *kdi, int prvkey_len,
			   int check_or_calc)
{
  unsigned int i;
  uint32_t d[4] = { 0, 0, 0, 0 };
  uint32_t *checksum = CHECKSUM_ADDR (*kdi, prvkey_len);

  for (i = 0; i < prvkey_len / sizeof (uint32_t); i++)
    d[i&3] ^= kdi->data[i];

  if (check_or_calc == CKDC_CALC)	/* store */
    {
      memcpy (checksum, d, DATA_ENCRYPTION_KEY_SIZE);
      return 0;
    }
  else				/* check */
    return memcmp (checksum, d, DATA_ENCRYPTION_KEY_SIZE) == 0;
}

/*
 * Return  1 on success,
 *         0 if none,
 *        -1 on error,
 */
int
gpg_do_load_prvkey (enum kind_of_key kk, int who, const uint8_t *keystring)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  int prvkey_len = gpg_get_algo_attr_key_size (kk, GPG_KEY_PRIVATE);
  const uint8_t *do_data = do_ptr[nr];
  const uint8_t *key_addr;
  uint8_t dek[DATA_ENCRYPTION_KEY_SIZE];
  const uint8_t *iv;
  struct key_data_internal kdi;

  DEBUG_INFO ("Loading private key: ");
  DEBUG_BYTE (kk);

  if (do_data == NULL)
    return 0;

  key_addr = kd[kk].pubkey - prvkey_len;
  memcpy (kdi.data, key_addr, prvkey_len);
  iv = &do_data[1];
  memcpy (CHECKSUM_ADDR (kdi, prvkey_len),
	  iv + INITIAL_VECTOR_SIZE, DATA_ENCRYPTION_KEY_SIZE);

  memcpy (dek, iv + DATA_ENCRYPTION_KEY_SIZE*(who+1), DATA_ENCRYPTION_KEY_SIZE);
  decrypt_dek (keystring, dek);

  decrypt (dek, iv, (uint8_t *)&kdi, kdi_len (prvkey_len));
  memset (dek, 0, DATA_ENCRYPTION_KEY_SIZE);
  if (!compute_key_data_checksum (&kdi, prvkey_len, CKDC_CHECK))
    {
      DEBUG_INFO ("gpg_do_load_prvkey failed.\r\n");
      return -1;
    }

  memcpy (kd[kk].data, kdi.data, prvkey_len);
  DEBUG_BINARY (kd[kk].data, prvkey_len);
  return 1;
}


static int8_t num_prv_keys;

static void
gpg_do_delete_prvkey (enum kind_of_key kk, int clean_page_full)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  const uint8_t *do_data = do_ptr[nr];
  uint8_t *key_addr;
  int prvkey_len = gpg_get_algo_attr_key_size (kk, GPG_KEY_PRIVATE);
  int key_size = gpg_get_algo_attr_key_size (kk, GPG_KEY_STORAGE);

  if (do_data == NULL)
    {
      if (clean_page_full)
	flash_key_release_page (kk);
      return;
    }

  do_ptr[nr] = NULL;
  flash_do_release (do_data);
  key_addr = (uint8_t *)kd[kk].pubkey - prvkey_len;
  kd[kk].pubkey = NULL;
  if (clean_page_full)
    flash_key_release_page (kk);
  else
    flash_key_release (key_addr, key_size);

  if (admin_authorized == BY_ADMIN && kk == GPG_KEY_FOR_SIGNING)
    {			/* Recover admin keystring DO.  */
      const uint8_t *ks_pw3 = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);

      if (ks_pw3 != NULL)
	{
	  uint8_t ks0[KEYSTRING_SIZE];

	  ks0[0] = ks_pw3[0] | PW_LEN_KEYSTRING_BIT;
	  memcpy (KS_GET_SALT (ks0), KS_GET_SALT (ks_pw3), SALT_SIZE);
	  memcpy (KS_GET_KEYSTRING (ks0), keystring_md_pw3, KEYSTRING_MD_SIZE);
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW3, ks0, KEYSTRING_SIZE);
	}
    }

  if (--num_prv_keys == 0)
    {
      /* Delete PW1 and RC if any.  */
      gpg_do_write_simple (NR_DO_KEYSTRING_PW1, NULL, 0);
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);

      ac_reset_pso_cds ();
      ac_reset_other ();
      if (admin_authorized == BY_USER)
	ac_reset_admin ();
    }
}

void
gpg_do_terminate (void)
{
  int i;

  for (i = 0; i < 3; i++)
    kd[i].pubkey = NULL;

  for (i = 0; i < NR_DO__LAST__; i++)
    do_ptr[i] = NULL;

  num_prv_keys = 0;
  data_objects_number_of_bytes = 0;
  digital_signature_counter = 0;

  pw1_lifetime_p = NULL;
  pw_err_counter_p[PW_ERR_PW1] = NULL;
  pw_err_counter_p[PW_ERR_RC] = NULL;
  pw_err_counter_p[PW_ERR_PW3] = NULL;
  algo_attr_sig_p = algo_attr_dec_p = algo_attr_aut_p = NULL;
}

static int
gpg_do_write_prvkey (enum kind_of_key kk, const uint8_t *key_data,
		     int prvkey_len, const uint8_t *keystring_admin,
		     const uint8_t *pubkey)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  int attr = gpg_get_algo_attr (kk);;
  const uint8_t *p;
  int r;
  struct prvkey_data prv;
  struct prvkey_data *pd = &prv;
  uint8_t *key_addr;
  const uint8_t *dek, *iv;
  struct key_data_internal kdi;
  int pubkey_len;
  uint8_t ks[KEYSTRING_MD_SIZE];
  enum kind_of_key kk0;
  int pw_len;
  const uint8_t *initial_pw;

  DEBUG_INFO ("Key import\r\n");
  DEBUG_SHORT (prvkey_len);

  /* Delete it first, if any.  */
  gpg_do_delete_prvkey (kk, CLEAN_SINGLE);

  if (attr == ALGO_SECP256K1)
    {
      pubkey_len = prvkey_len * 2;
      if (prvkey_len != 32)
	return -1;
    }
  else if (attr == ALGO_CURVE25519)
    {
      pubkey_len = prvkey_len;
      if (prvkey_len != 32)
	return -1;
    }
  else if (attr == ALGO_ED25519)
    {
      pubkey_len = prvkey_len / 2;
      if (prvkey_len != 64)
	return -1;
    }
  else if (attr == ALGO_ED448)
    {
      pubkey_len = 57 + 1; /* +1 to be even.  */
      if (prvkey_len != 128)
	return -1;
    }
  else if (attr == ALGO_X448)
    {
      pubkey_len = prvkey_len;
      if (prvkey_len != 56)
	return -1;
    }
  else				/* RSA */
    {
      int key_size = gpg_get_algo_attr_key_size (kk, GPG_KEY_STORAGE);

      pubkey_len = prvkey_len;
      if (prvkey_len + pubkey_len != key_size)
	return -1;
    }

  DEBUG_INFO ("Getting keystore address...\r\n");
  key_addr = flash_key_alloc (kk);
  if (key_addr == NULL)
    return -1;

  kd[kk].pubkey = key_addr + prvkey_len;

  num_prv_keys++;

  DEBUG_INFO ("key_addr: ");
  DEBUG_WORD ((uint32_t)key_addr);

  memcpy (kdi.data, key_data, prvkey_len);
  memset ((uint8_t *)kdi.data + prvkey_len, 0, MAX_PRVKEY_LEN - prvkey_len);

  compute_key_data_checksum (&kdi, prvkey_len, CKDC_CALC);

  dek = random_bytes_get (); /* 32-byte random bytes */
  iv = dek + DATA_ENCRYPTION_KEY_SIZE;
  memcpy (pd->dek_encrypted_1, dek, DATA_ENCRYPTION_KEY_SIZE);
  memcpy (pd->dek_encrypted_2, dek, DATA_ENCRYPTION_KEY_SIZE);
  memcpy (pd->dek_encrypted_3, dek, DATA_ENCRYPTION_KEY_SIZE);

  gpg_do_get_initial_pw_setting (0, &pw_len, &initial_pw);
  s2k (NULL, 0, initial_pw, pw_len, ks);

  /* Handle existing keys and keystring DOs.  */
  gpg_do_write_simple (NR_DO_KEYSTRING_PW1, NULL, 0);
  gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);
  for (kk0 = 0; kk0 <= GPG_KEY_FOR_AUTHENTICATION; kk0++)
    if (kk0 != kk)
      {
	gpg_do_chks_prvkey (kk0, admin_authorized, keystring_md_pw3,
			    BY_USER, ks);
	gpg_do_chks_prvkey (kk0, BY_RESETCODE, NULL, 0, NULL);
      }

  encrypt (dek, iv, (uint8_t *)&kdi, kdi_len (prvkey_len));

  r = flash_key_write (key_addr, (const uint8_t *)kdi.data, prvkey_len,
		       pubkey, pubkey_len);
  if (r < 0)
    {
      random_bytes_free (dek);
      memset (pd, 0, sizeof (struct prvkey_data));
      return r;
    }

  memcpy (pd->iv, iv, INITIAL_VECTOR_SIZE);
  memcpy (pd->checksum_encrypted, CHECKSUM_ADDR (kdi, prvkey_len),
	  DATA_ENCRYPTION_KEY_SIZE);

  encrypt_dek (ks, pd->dek_encrypted_1);

  memset (pd->dek_encrypted_2, 0, DATA_ENCRYPTION_KEY_SIZE);

  if (keystring_admin)
    encrypt_dek (keystring_admin, pd->dek_encrypted_3);
  else
    memset (pd->dek_encrypted_3, 0, DATA_ENCRYPTION_KEY_SIZE);

  p = flash_do_write (nr, (const uint8_t *)pd, sizeof (struct prvkey_data));
  do_ptr[nr] = p;

  random_bytes_free (dek);
  memset (pd, 0, sizeof (struct prvkey_data));
  if (p == NULL)
    return -1;

  if (keystring_admin && kk == GPG_KEY_FOR_SIGNING)
    {
      const uint8_t *ks_admin = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);
      uint8_t ks_info[KS_META_SIZE];

      if (ks_admin != NULL && (ks_admin[0] & PW_LEN_KEYSTRING_BIT))
	{
	  ks_info[0] = ks_admin[0] & PW_LEN_MASK;
	  memcpy (KS_GET_SALT (ks_info), KS_GET_SALT (ks_admin), SALT_SIZE);
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW3, ks_info, KS_META_SIZE);
	}
      else
	{
	  DEBUG_INFO ("No admin keystring!\r\n");
	}
    }

  return 0;
}

int
gpg_do_chks_prvkey (enum kind_of_key kk,
		    int who_old, const uint8_t *old_ks,
		    int who_new, const uint8_t *new_ks)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  const uint8_t *do_data = do_ptr[nr];
  uint8_t dek[DATA_ENCRYPTION_KEY_SIZE];
  struct prvkey_data prv;
  struct prvkey_data *pd = &prv;
  uint8_t *dek_p;
  int update_needed = 0;
  int r = 1;			/* Success */

  if (do_data == NULL)
    return 0;			/* No private key */

  memcpy (pd, &do_data[1], sizeof (struct prvkey_data));

  dek_p = ((uint8_t *)pd) + INITIAL_VECTOR_SIZE
    + DATA_ENCRYPTION_KEY_SIZE * who_old;
  memcpy (dek, dek_p, DATA_ENCRYPTION_KEY_SIZE);
  if (who_new == 0)		/* Remove */
    {
      int i;

      for (i = 0; i < DATA_ENCRYPTION_KEY_SIZE; i++)
	if (dek_p[i] != 0)
	  {
	    update_needed = 1;
	    dek_p[i] = 0;
	  }
    }
  else
    {
      decrypt_dek (old_ks, dek);
      encrypt_dek (new_ks, dek);
      dek_p += DATA_ENCRYPTION_KEY_SIZE * (who_new - who_old);
      if (memcmp (dek_p, dek, DATA_ENCRYPTION_KEY_SIZE) != 0)
	{
	  memcpy (dek_p, dek, DATA_ENCRYPTION_KEY_SIZE);
	  update_needed = 1;
	}
    }

  if (update_needed)
    {
      const uint8_t *p;

      flash_do_release (do_data);
      do_ptr[nr] = NULL;
      p = flash_do_write (nr, (const uint8_t *)pd, sizeof (struct prvkey_data));
      do_ptr[nr] = p;
      if (p == NULL)
	r = -1;
    }

  memset (pd, 0, sizeof (struct prvkey_data));

  return r;
}


static enum kind_of_key
kkb_to_kk (uint8_t kk_byte)
{
  enum kind_of_key kk;

  if (kk_byte == 0xb6)
    kk = GPG_KEY_FOR_SIGNING;
  else if (kk_byte == 0xb8)
    kk = GPG_KEY_FOR_DECRYPTION;
  else				/* 0xa4 */
    kk = GPG_KEY_FOR_AUTHENTICATION;
  return kk;
}

/*
 * RSA-2048:
 * 4d, xx, xx, xx:    Extended Header List
 *   b6 00 (SIG) / b8 00 (DEC) / a4 00 (AUT)
 *   7f48, xx: cardholder private key template
 *       91 L<E>:        91=tag of E, L<E>: length of E
 *       92 Lh<P> Ll<P>: 92=tag of P, L<P>: length of P
 *       93 Lh<Q> Ll<Q>: 93=tag of Q, L<Q>: length of Q
 *   5f48, xx xx xx: cardholder private key
 *       <E: 4-byte>, <P: 128-byte>, <Q: 128-byte>
 *
 * RSA-4096:
 * 4d, 82, 02, 18:    Extended Header List
 *   b6 00 (SIG) / b8 00 (DEC) / a4 00 (AUT)
 *   7f48, 0a: cardholder private key template
 *       91 L<E>:        91=tag of E, L<E>: length of E
 *       92 82 Lh<P> Ll<P>: 92=tag of P, L<P>: length of P
 *       93 82 Lh<Q> Ll<Q>: 93=tag of Q, L<Q>: length of Q
 *   5f48, 82 02 04: cardholder private key
 *       <E: 4-byte>, <P: 256-byte>, <Q: 256-byte>
 *
 * ECDSA / ECDH / EdDSA:
 * 4d, 2a:    Extended Header List
 *   b6 00 (SIG) / b8 00 (DEC) / a4 00 (AUT)
 *   7f48, 02: cardholder private key template
 *       9x LEN: 9x=tag of private key d,  LEN=length of d
 *   5f48, 20: cardholder private key
 * <d: 32-byte>
 */
static int
proc_key_import (const uint8_t *data, int len)
{
  int r = -1;
  enum kind_of_key kk;
  const uint8_t *keystring_admin;
  int attr;
  const uint8_t *p = data;
  uint8_t pubkey[512];

#ifdef KDF_DO_REQUIRED
  const uint8_t *kdf_do = do_ptr[NR_DO_KDF];

  if (kdf_do == NULL)
    return 0;		/* Error.  */
#endif

  if (admin_authorized == BY_ADMIN)
    keystring_admin = keystring_md_pw3;
  else
    keystring_admin = NULL;

  DEBUG_BINARY (data, len);

  if (*p++ != 0x4d)
    return 0;

  /* length field */
  if (*p == 0x82)
    p += 3;
  else if (*p == 0x81)
    p += 2;
  else
    p += 1;

  kk = kkb_to_kk (*p);
  if (kk == GPG_KEY_FOR_SIGNING)
    {
      ac_reset_pso_cds ();
      gpg_reset_digital_signature_counter ();
    }
  else
    ac_reset_other ();

  attr = gpg_get_algo_attr (kk);

  if ((len <= 12 && (attr == ALGO_SECP256K1 || attr == ALGO_CURVE25519
		     || attr == ALGO_ED25519 || attr == ALGO_ED448
		     || attr == ALGO_X448))
      || (len <= 22 && attr == ALGO_RSA2K) || (len <= 24 && attr == ALGO_RSA4K))
    {					    /* Deletion of the key */
      gpg_do_delete_prvkey (kk, CLEAN_SINGLE);
      return 1;
    }

  if (attr == ALGO_RSA2K)
    {
      /* It should starts with 00 01 00 01 (E), skiping E (4-byte) */
      r = modulus_calc (&data[26], len - 26, pubkey);
      if (r >= 0)
	r = gpg_do_write_prvkey (kk, &data[26], len - 26, keystring_admin,
				 pubkey);
    }
  else if (attr == ALGO_RSA4K)
    {
      /* It should starts with 00 01 00 01 (E), skiping E (4-byte) */
      r = modulus_calc (&data[28], len - 28, pubkey);
      if (r >= 0)
	r = gpg_do_write_prvkey (kk, &data[28], len - 28, keystring_admin,
				 pubkey);
    }
  else if (attr == ALGO_SECP256K1)
    {
      r = ecc_compute_public_p256k1 (&data[12], pubkey);
      if (r >= 0)
	r = gpg_do_write_prvkey (kk, &data[12], len - 12, keystring_admin,
				 pubkey);
    }
  else if (attr == ALGO_CURVE25519)
    {
      uint8_t priv[32];
      int i;

      if (len - 12 != 32)
	return 0;		/* Error.  */

      for (i = 0; i < 32; i++)
	priv[31-i] = data[12+i];
      ecdh_compute_public_25519 (priv, pubkey);
      r = gpg_do_write_prvkey (kk, priv, 32, keystring_admin, pubkey);
    }
  else if (attr == ALGO_ED25519)
    {
      uint8_t hash[64];

      if (len - 12 != 32)
	return 0;		/* Error.  */
      mbedtls_sha512_context ctx;
      mbedtls_sha512_init(&ctx);

      mbedtls_sha512_starts (&ctx, 0);
      mbedtls_sha512_update (&ctx, &data[12], 32);
      mbedtls_sha512_finish (&ctx, hash);
      mbedtls_sha512_free (&ctx);

      hash[0] &= 248;
      hash[31] &= 127;
      hash[31] |= 64;
      eddsa_compute_public_25519 (hash, pubkey);
      r = gpg_do_write_prvkey (kk, hash, 64, keystring_admin, pubkey);
    }
  else if (attr == ALGO_ED448)
    {
      shake_context ctx;
      uint8_t hash[128];

      if (len - 12 != 57)
	return 0;		/* Error.  */

      shake256_start (&ctx);
      shake256_update (&ctx, &data[12], 57);
      shake256_finish (&ctx, hash, 2*57);
      memset (hash+114, 0, 128-114);
      ed448_compute_public (pubkey, hash);
      pubkey[57] = 0;
      r = gpg_do_write_prvkey (kk, hash, 128, keystring_admin, pubkey);
    }
  else if (attr == ALGO_X448)
    {
      uint8_t priv[56];

      if (len - 12 != 56)
	return 0;		/* Error.  */

      memcpy (priv, data+12, 56);
      ecdh_compute_public_x448 (pubkey, priv);
      r = gpg_do_write_prvkey (kk, priv, 56, keystring_admin, pubkey);
    }

  if (r < 0)
    return 0;
  else
    return 1;
}

static const uint16_t cmp_ch_data[] = {
  3,
  GPG_DO_NAME,
  GPG_DO_LANGUAGE,
  GPG_DO_SEX,
};

static const uint16_t cmp_app_data[] = {
#ifdef ACKBTN_SUPPORT
  4,
#else
  3,
#endif
  GPG_DO_AID,
  GPG_DO_HIST_BYTES,
  GPG_DO_DISCRETIONARY,
#ifdef ACKBTN_SUPPORT
  GPG_DO_FEATURE_MNGMNT,
#endif
};

static const uint16_t cmp_discretionary[] = {
#ifdef ACKBTN_SUPPORT
  11,
#else
  8,
#endif
  GPG_DO_EXTCAP,
  GPG_DO_ALG_SIG, GPG_DO_ALG_DEC, GPG_DO_ALG_AUT,
  GPG_DO_PW_STATUS,
  GPG_DO_FP_ALL, GPG_DO_CAFP_ALL, GPG_DO_KGTIME_ALL,
#ifdef ACKBTN_SUPPORT
  GPG_DO_UIF_SIG, GPG_DO_UIF_DEC, GPG_DO_UIF_AUT
#endif
};

static const uint16_t cmp_ss_temp[] = { 1, GPG_DO_DS_COUNT };

static const struct do_table_entry
gpg_do_table[] = {
  /* Variables: Fixed size */
  { GPG_DO_SEX, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[0] },
  { GPG_DO_FP_SIG, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[1] },
  { GPG_DO_FP_DEC, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[2] },
  { GPG_DO_FP_AUT, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[3] },
  { GPG_DO_CAFP_1, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[4] },
  { GPG_DO_CAFP_2, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[5] },
  { GPG_DO_CAFP_3, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[6] },
  { GPG_DO_KGTIME_SIG, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[7] },
  { GPG_DO_KGTIME_DEC, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[8] },
  { GPG_DO_KGTIME_AUT, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[9] },
  /* Variables: Variable size */
  { GPG_DO_LOGIN_DATA, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[10] },
  { GPG_DO_URL, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[11] },
  { GPG_DO_NAME, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[12] },
  { GPG_DO_LANGUAGE, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[13] },
  /* Pseudo DO READ: calculated */
  { GPG_DO_FP_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_fp_all },
  { GPG_DO_CAFP_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_cafp_all },
  { GPG_DO_KGTIME_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_kgtime_all },
  /* Pseudo DO READ: calculated, not changeable by user */
  { GPG_DO_DS_COUNT, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_ds_count },
  { GPG_DO_AID, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_openpgpcard_aid },
  { GPG_DO_ALG_INFO, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_alg_info },
  /* Pseudo DO READ/WRITE: calculated */
  { GPG_DO_PW_STATUS, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_pw_status },
  { GPG_DO_ALG_SIG, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_algorithm_attr },
  { GPG_DO_ALG_DEC, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_algorithm_attr },
  { GPG_DO_ALG_AUT, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_algorithm_attr },
#ifdef ACKBTN_SUPPORT
  { GPG_DO_UIF_SIG, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED, rw_uif },
  { GPG_DO_UIF_DEC, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED, rw_uif },
  { GPG_DO_UIF_AUT, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED, rw_uif },
#endif
  { GPG_DO_KDF, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_kdf },
  /* Fixed data */
  { GPG_DO_HIST_BYTES, DO_FIXED, AC_ALWAYS, AC_NEVER, historical_bytes },
  { GPG_DO_EXTCAP, DO_FIXED, AC_ALWAYS, AC_NEVER, extended_capabilities },
#ifdef ACKBTN_SUPPORT
  { GPG_DO_FEATURE_MNGMNT, DO_FIXED, AC_ALWAYS, AC_NEVER, feature_mngmnt },
#endif
  /* Compound data: Read access only */
  { GPG_DO_CH_DATA, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_ch_data },
  { GPG_DO_APP_DATA, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_app_data },
  { GPG_DO_DISCRETIONARY, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_discretionary },
  { GPG_DO_SS_TEMP, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_ss_temp },
  /* Simple data: write access only */
  { GPG_DO_RESETTING_CODE, DO_PROC_WRITE, AC_NEVER, AC_ADMIN_AUTHORIZED,
    proc_resetting_code },
  /* Compound data: Write access only */
  { GPG_DO_KEY_IMPORT, DO_PROC_WRITE, AC_NEVER, AC_ADMIN_AUTHORIZED,
    proc_key_import },
#if 0
  /* Card holder certificate is handled in special way, as its size is big */
  { GPG_DO_CH_CERTIFICATE, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, NULL },
#endif
};

#define NUM_DO_ENTRIES (int)(sizeof (gpg_do_table) \
			     / sizeof (struct do_table_entry))

/*
 * Reading data from Flash ROM, initialize DO_PTR, PW_ERR_COUNTERS, etc.
 */
void
gpg_data_scan (const uint8_t *do_start, const uint8_t *do_end)
{
  const uint8_t *p;
  int i;
  const uint8_t *dsc_h14_p, *dsc_l10_p;
  int dsc_h14, dsc_l10;

  dsc_h14_p = dsc_l10_p = NULL;
  pw1_lifetime_p = NULL;
  pw_err_counter_p[PW_ERR_PW1] = NULL;
  pw_err_counter_p[PW_ERR_RC] = NULL;
  pw_err_counter_p[PW_ERR_PW3] = NULL;
  algo_attr_sig_p = algo_attr_dec_p = algo_attr_aut_p = NULL;
  digital_signature_counter = 0;
  uif_flags = 0;

  /* Clear all data objects.  */
  for (i = 0; i < NR_DO__LAST__; i++)
    do_ptr[i] = NULL;

  /* When the card is terminated no data objects are valid.  */
  if (do_start == NULL)
    return;

  /* Traverse DO, counters, etc. in DATA pool */
  p = do_start;
  while (p < do_end && *p != NR_EMPTY)
    {
      uint8_t nr = *p++;
      uint8_t second_byte = *p;

      if (nr == 0x00 && second_byte == 0x00)
	p++;			/* Skip released word */
      else
	{
	  if (nr < 0x80)
	    {
	      /* It's Data Object */
	      if (nr < NR_DO__LAST__)
		do_ptr[nr] = p;

	      p += second_byte + 1; /* second_byte has length */

	      if (((uintptr_t)p & 1))
		p++;
	    }
	  else if (nr >= 0x80 && nr <= 0xbf)
	    /* Encoded data of Digital Signature Counter: upper 14-bit */
	    {
	      dsc_h14_p = p - 1;
	      p++;
	    }
	  else if (nr >= 0xc0 && nr <= 0xc3)
	    /* Encoded data of Digital Signature Counter: lower 10-bit */
	    {
	      dsc_l10_p = p - 1;
	      p++;
	    }
	  else
	    switch (nr)
	      {
	      case NR_BOOL_PW1_LIFETIME:
		pw1_lifetime_p = p - 1;
		p++;
		break;
	      case NR_KEY_ALGO_ATTR_SIG:
		algo_attr_sig_p = p - 1;
		p++;
		break;
	      case NR_KEY_ALGO_ATTR_DEC:
		algo_attr_dec_p = p - 1;
		p++;
		break;
	      case NR_KEY_ALGO_ATTR_AUT:
		algo_attr_aut_p = p - 1;
		p++;
		break;
	      case NR_DO_UIF_SIG:
	      case NR_DO_UIF_DEC:
	      case NR_DO_UIF_AUT:
		uif_flags &= ~(3 << ((nr - NR_DO_UIF_SIG) * 2));
		uif_flags |= (second_byte & 3) << ((nr - NR_DO_UIF_SIG) * 2);
		p++;
		break;
	      case NR_COUNTER_123:
		p++;
		if (second_byte <= PW_ERR_PW3)
		  pw_err_counter_p[second_byte] = p;
		p += 2;
		break;
	      default:
		/* Something going wrong.  ignore this word. */
		p++;
		break;
	      }
	}
    }

  flash_set_data_pool_last (p);

  num_prv_keys = 0;
  if (do_ptr[NR_DO_PRVKEY_SIG] != NULL)
    num_prv_keys++;
  if (do_ptr[NR_DO_PRVKEY_DEC] != NULL)
    num_prv_keys++;
  if (do_ptr[NR_DO_PRVKEY_AUT] != NULL)
    num_prv_keys++;

  data_objects_number_of_bytes = 0;
  for (i = 0; i < NR_DO__LAST__; i++)
    if (do_ptr[i] != NULL)
      data_objects_number_of_bytes += *do_ptr[i];

  if (dsc_l10_p == NULL)
    dsc_l10 = 0;
  else
    dsc_l10 = ((*dsc_l10_p - 0xc0) << 8) | *(dsc_l10_p + 1);

  if (dsc_h14_p == NULL)
    dsc_h14 = 0;
  else
    {
      dsc_h14 = ((*dsc_h14_p - 0x80) << 8) | *(dsc_h14_p + 1);
      if (dsc_l10_p == NULL)
	DEBUG_INFO ("something wrong in DSC\r\n"); /* weird??? */
      else if (dsc_l10_p < dsc_h14_p)
	/* Possibly, power off during writing dsc_l10 */
	dsc_l10 = 0;
    }

  digital_signature_counter = (dsc_h14 << 10) | dsc_l10;
}

/*
 * Write all data to newly allocated Flash ROM page (from P_START),
 * updating PW1_LIFETIME_P, PW_ERR_COUNTER_P, and DO_PTR.
 * Called by flash_copying_gc.
 */
void
gpg_data_copy (const uint8_t *p_start)
{
  const uint8_t *p;
  int i;
  int v;

  p = gpg_write_digital_signature_counter (p_start, digital_signature_counter);

  if (pw1_lifetime_p != NULL)
    {
      flash_bool_write_internal (p, NR_BOOL_PW1_LIFETIME);
      pw1_lifetime_p = p;
      p += 2;
    }

  if (algo_attr_sig_p != NULL)
    {
      flash_enum_write_internal (p, NR_KEY_ALGO_ATTR_SIG, algo_attr_sig_p[1]);
      algo_attr_sig_p = p;
      p += 2;
    }

  if (algo_attr_dec_p != NULL)
    {
      flash_enum_write_internal (p, NR_KEY_ALGO_ATTR_DEC, algo_attr_dec_p[1]);
      algo_attr_dec_p = p;
      p += 2;
    }

  if (algo_attr_aut_p != NULL)
    {
      flash_enum_write_internal (p, NR_KEY_ALGO_ATTR_AUT, algo_attr_aut_p[1]);
      algo_attr_aut_p = p;
      p += 2;
    }

  for (i = 0; i < 3; i++)
    if ((v = flash_cnt123_get_value (pw_err_counter_p[i])) != 0)
      {
	flash_cnt123_write_internal (p, i, v);
	pw_err_counter_p[i] = p + 2;
	p += 4;
      }

  for (i = 0; i < 3; i++)
    if ((v = (uif_flags >> (i * 2)) & 3))
      {
	flash_enum_write_internal (p, NR_DO_UIF_SIG + i, v);
	p += 2;
      }

  data_objects_number_of_bytes = 0;
  for (i = 0; i < NR_DO__LAST__; i++)
    if (do_ptr[i] != NULL)
      {
	const uint8_t *do_data = do_ptr[i];
	int len = do_data[0];

	flash_do_write_internal (p, i, &do_data[1], len);
	do_ptr[i] = p + 1;
	p += 2 + ((len + 1) & ~1);
	data_objects_number_of_bytes += len;
      }

  flash_set_data_pool_last (p);
}

static const struct do_table_entry *
get_do_entry (uint16_t tag)
{
  int i;

  for (i = 0; i < NUM_DO_ENTRIES; i++)
    if (gpg_do_table[i].tag == tag)
      return &gpg_do_table[i];

  return NULL;
}

static void
copy_do_1 (uint16_t tag, const uint8_t *do_data, int with_tag)
{
  int len;

  if (with_tag)
    {
      copy_tag (tag);

      if (do_data[0] >= 128)
	*res_p++ = 0x81;

      len = do_data[0] + 1;
    }
  else
    {
      len = do_data[0];
      do_data++;
    }

  memcpy (res_p, do_data, len);
  res_p += len;
}

static int
copy_do (const struct do_table_entry *do_p, int with_tag)
{
  if (do_p == NULL)
    return 0;

  if (!ac_check_status (do_p->ac_read))
    return -1;

  switch (do_p->do_type)
    {
    case DO_FIXED:
      {
	const uint8_t *do_data = (const uint8_t *)do_p->obj;
	if (do_data == NULL)
	  return 0;
	else
	  copy_do_1 (do_p->tag, do_data, with_tag);
	break;
      }
    case DO_VAR:
      {
	const uint8_t *do_data = *(const uint8_t **)do_p->obj;
	if (do_data == NULL)
	  return 0;
	else
	  copy_do_1 (do_p->tag, do_data, with_tag);
	break;
      }
    case DO_CMP_READ:
      {
	int i;
	const uint16_t *cmp_data = (const uint16_t *)do_p->obj;
	int num_components = cmp_data[0];
	uint8_t *len_p = NULL;

	if (with_tag)
	  {
	    copy_tag (do_p->tag);
	    *res_p++ = 0x81;	/* Assume it's less than 256 */
	    len_p = res_p;
	    *res_p++ = 0;	/* for now */
	  }

	for (i = 0; i < num_components; i++)
	  {
	    uint16_t tag0;
	    const struct do_table_entry *do0_p;

	    tag0 = cmp_data[i+1];
	    do0_p = get_do_entry (tag0);
	    if (copy_do (do0_p, 1) < 0)
	      return -1;
	  }

	if (len_p)
	  *len_p = res_p - len_p - 1;
	break;
      }
    case DO_PROC_READ:
      {
	void (*do_func)(uint16_t, int) = (void (*)(uint16_t, int))do_p->obj;

	do_func (do_p->tag, with_tag);
	return 1;
      }
    case DO_PROC_READWRITE:
      {
	int (*rw_func)(uint16_t, int, const uint8_t *, int, int)
	  = (int (*)(uint16_t, int, const uint8_t *, int, int))do_p->obj;

	return rw_func (do_p->tag, with_tag, NULL, 0, 0);
      }
    case DO_PROC_WRITE:
      return -1;
    }

  return 1;
}

/*
 * Process GET_DATA request on Data Object specified by TAG
 *   Call write_res_adpu to fill data returned
 */
void
gpg_do_get_data (uint16_t tag, int with_tag)
{
#if defined(CERTDO_SUPPORT)
  if (tag == GPG_DO_CH_CERTIFICATE)
    {
      apdu.res_apdu_data = (uint8_t *)ch_certificate_start;
      apdu.res_apdu_data_len = ((apdu.res_apdu_data[2] << 8) | apdu.res_apdu_data[3]);
      if (apdu.res_apdu_data_len == 0xffff)
	{
	  apdu.res_apdu_data_len = 0;
	  GPG_NO_RECORD ();
	}
      else
	/* Add length of (tag+len) */
	apdu.res_apdu_data_len += 4;
    }
  else
#endif
    {
      const struct do_table_entry *do_p = get_do_entry (tag);

      res_p = res_APDU;

      DEBUG_INFO ("   ");
      DEBUG_SHORT (tag);

      if (do_p)
	{
	  if (copy_do (do_p, with_tag) < 0)
	    /* Overwriting partially written result  */
	    GPG_SECURITY_FAILURE ();
	  else
	    {
	      res_APDU_size = res_p - res_APDU;
	      GPG_SUCCESS ();
	    }
	}
      else
	GPG_NO_RECORD ();
    }
}

void
gpg_do_put_data (uint16_t tag, const uint8_t *data, int len)
{
  const struct do_table_entry *do_p = get_do_entry (tag);

  DEBUG_INFO ("   ");
  DEBUG_SHORT (tag);

  if (do_p)
    {
      if (!ac_check_status (do_p->ac_write))
	{
	  GPG_SECURITY_FAILURE ();
	  return;
	}

      switch (do_p->do_type)
	{
	case DO_FIXED:
	case DO_CMP_READ:
	case DO_PROC_READ:
	  GPG_SECURITY_FAILURE ();
	  break;
	case DO_VAR:
	  {
	    const uint8_t **do_data_p = (const uint8_t **)do_p->obj;

	    if (*do_data_p)
	      flash_do_release (*do_data_p);

	    if (len == 0)
	      {
		/* make DO empty */
		*do_data_p = NULL;
		GPG_SUCCESS ();
	      }
	    else if (len > 255)
	      GPG_MEMORY_FAILURE ();
	    else
	      {
		int nr = do_tag_to_nr (tag);

		if (nr < 0)
		  GPG_MEMORY_FAILURE ();
		else
		  {
		    *do_data_p = NULL;
		    *do_data_p = flash_do_write (nr, data, len);
		    if (*do_data_p)
		      GPG_SUCCESS ();
		    else
		      GPG_MEMORY_FAILURE ();
		  }
	      }
	    break;
	  }
	case DO_PROC_READWRITE:
	  {
	    int (*rw_func)(uint16_t, int, const uint8_t *, int, int)
	      = (int (*)(uint16_t, int, const uint8_t *, int, int))do_p->obj;

	    if (rw_func (tag, 0, data, len, 1))
	      GPG_SUCCESS ();
	    else
	      GPG_ERROR ();
	    break;
	  }
	case DO_PROC_WRITE:
	  {
	    int (*proc_func)(const uint8_t *, int)
	      = (int (*)(const uint8_t *, int))do_p->obj;

	    if (proc_func (data, len))
	      GPG_SUCCESS ();
	    else
	      GPG_ERROR ();
	    break;
	  }
	}
    }
  else
    GPG_NO_RECORD ();
}

void
gpg_do_public_key (uint8_t kk_byte)
{
  enum kind_of_key kk = kkb_to_kk (kk_byte);
  int attr = gpg_get_algo_attr (kk);
  int pubkey_len = gpg_get_algo_attr_key_size (kk, GPG_KEY_PUBLIC);
  const uint8_t *pubkey = kd[kk].pubkey;

  DEBUG_INFO ("Public key\r\n");
  DEBUG_BYTE (kk_byte);

  if (pubkey == NULL)
    {
      DEBUG_INFO ("none.\r\n");
      GPG_NO_RECORD ();
      return;
    }

  res_p = res_APDU;

  /* TAG */
  *res_p++ = 0x7f; *res_p++ = 0x49;

  if (attr == ALGO_SECP256K1)
    {				/* ECDSA or ECDH */
      /* LEN */
      *res_p++ = 2 + 1 + 64;
      {
	/*TAG*/          /* LEN = 1+64 */
	*res_p++ = 0x86; *res_p++ = 0x41;
	*res_p++ = 0x04; 	/* No compression of EC point.  */
	/* 64-byte binary (big endian): X || Y */
	memcpy (res_p, pubkey, 64);
	res_p += 64;
      }
    }
  else if (attr == ALGO_ED25519 || attr == ALGO_CURVE25519)
    {				/* EdDSA or ECDH on curve25519 */
      /* LEN */
      *res_p++ = 2 + 32;
      {
	/*TAG*/          /* LEN = 32 */
	*res_p++ = 0x86; *res_p++ = 0x20;
	/* 32-byte binary (little endian): Y with parity or X */
	memcpy (res_p, pubkey, 32);
	res_p += 32;
      }
    }
  else if (attr == ALGO_ED448)
    {				/* EdDSA using Ed448 */
      /* LEN */
      *res_p++ = 2 + 57;
      {
	/*TAG*/          /* LEN = 57 */
	*res_p++ = 0x86; *res_p++ = 0x39;
	/* 57-byte binary (little endian): X */
	memcpy (res_p, pubkey, 57);
	res_p += 57;
      }
    }
  else if (attr == ALGO_X448)
    {				/* ECDH using X448 */
      /* LEN */
      *res_p++ = 2 + 56;
      {
	/*TAG*/          /* LEN = 56 */
	*res_p++ = 0x86; *res_p++ = 0x38;
	/* 56-byte binary (little endian): X */
	memcpy (res_p, pubkey, 56);
	res_p += 56;
      }
    }
  else
    {				/* RSA */
      /* LEN = 9+256or512 */
      *res_p++ = 0x82; *res_p++ = pubkey_len > 256? 0x02: 0x01; *res_p++ = 0x09;

      {
	/*TAG*/          /* LEN = 256or512 */
	*res_p++ = 0x81;
	*res_p++ = 0x82; *res_p++ = pubkey_len > 256? 0x02: 0x01;*res_p++ = 0x00;
	/* PUBKEY_LEN-byte binary (big endian) */
	memcpy (res_p, pubkey, pubkey_len);
	res_p += pubkey_len;
      }
      {
	/*TAG*/          /* LEN= 3 */
	*res_p++ = 0x82; *res_p++ = 3;
	/* 3-byte E=0x10001 (big endian) */
	*res_p++ = 0x01; *res_p++ = 0x00; *res_p++ = 0x01;
      }
    }

  /* Success */
  res_APDU_size = res_p - res_APDU;
  GPG_SUCCESS ();

  DEBUG_INFO ("done.\r\n");
  return;
}

const uint8_t *
gpg_do_read_simple (uint8_t nr)
{
  const uint8_t *do_data;

  do_data = do_ptr[nr];
  if (do_data == NULL)
    return NULL;

  return do_data+1;
}

void
gpg_do_write_simple (uint8_t nr, const uint8_t *data, int size)
{
  const uint8_t **do_data_p;

  do_data_p = (const uint8_t **)&do_ptr[nr];
  if (*do_data_p)
    flash_do_release (*do_data_p);

  if (data != NULL)
    {
      *do_data_p = NULL;
      *do_data_p = flash_do_write (nr, data, size);
      if (*do_data_p == NULL)
	flash_warning ("DO WRITE ERROR");
    }
  else
    *do_data_p = NULL;
}

#include "hsm2040.h"
#include "tusb.h"

void
gpg_do_keygen (uint8_t *buf)
{
  uint8_t kk_byte = buf[0];
  enum kind_of_key kk = kkb_to_kk (kk_byte);
  int attr = gpg_get_algo_attr (kk);;
  int prvkey_len = gpg_get_algo_attr_key_size (kk, GPG_KEY_PRIVATE);
  const uint8_t *prv;
  const uint8_t *rnd;
  int r = 0;
#define p_q (&buf[3])
#define d (&buf[3])
#define d1 (&buf[3+64])
#define pubkey (&buf[3+256])

  DEBUG_INFO ("Keygen\r\n");
  DEBUG_BYTE (kk_byte);

  if (attr == ALGO_RSA2K || attr == ALGO_RSA4K)
    {
      if (rsa_genkey (prvkey_len, pubkey, p_q) < 0)
	{
	  GPG_MEMORY_FAILURE ();
	  return;
	}

      prv = p_q;
    }
  else if (attr == ALGO_SECP256K1)
    {
      const uint8_t *p;
      int i;

      rnd = NULL;
      do
	{
	  if (rnd)
	    random_bytes_free (rnd);
	  rnd = random_bytes_get ();
	  r = ecc_check_secret_p256k1 (rnd, d1);
	}
      while (r == 0);

      /* Convert it to big endian */

      if (r < 0)
	p = (const uint8_t *)d1;
      else
	p = rnd;
      for (i = 0; i < 32; i++)
	d[32 - i - 1] = p[i];

      random_bytes_free (rnd);

      prv = d;
      r = ecc_compute_public_p256k1 (prv, pubkey);
    }
  else if (attr == ALGO_CURVE25519)
    {
      rnd = random_bytes_get ();
      memcpy (d, rnd, 32);
      random_bytes_free (rnd);
      d[0] &= 248;
      d[31] &= 127;
      d[31] |= 64;
      prv = d;
      ecdh_compute_public_25519 (prv, pubkey);
    }
  else if (attr == ALGO_ED25519)
    {
      rnd = random_bytes_get ();
      
      mbedtls_sha512_context ctx;
      mbedtls_sha512_init(&ctx);

      mbedtls_sha512_starts (&ctx, 0);
      mbedtls_sha512_update (&ctx, rnd, 32);
      mbedtls_sha512_finish (&ctx, d);
      mbedtls_sha512_free (&ctx);
      
      random_bytes_free (rnd);
      d[0] &= 248;
      d[31] &= 127;
      d[31] |= 64;
      prv = d;
      eddsa_compute_public_25519 (d, pubkey);
    }
  else if (attr == ALGO_ED448)
    {
      shake_context ctx;
      rnd = random_bytes_get ();
      shake256_start (&ctx);
      shake256_update (&ctx, rnd, 32);
      random_bytes_free (rnd);
      rnd = random_bytes_get ();
      shake256_update (&ctx, rnd, 25);
      shake256_finish (&ctx, d, 2*57);
      random_bytes_free (rnd);
      prv = d;
      ed448_compute_public (pubkey, prv);
      pubkey[57] = 0;
    }
  else if (attr == ALGO_X448)
    {
      rnd = random_bytes_get ();
      memcpy (d, rnd, 32);
      random_bytes_free (rnd);
      rnd = random_bytes_get ();
      memcpy (d+32, rnd, 24);
      prv = d;
      ecdh_compute_public_x448 (pubkey, prv);
    }
  else
    {
      GPG_CONDITION_NOT_SATISFIED ();
      return;
    }

  if (r >= 0)
    {
      const uint8_t *keystring_admin;

      if (admin_authorized == BY_ADMIN)
	keystring_admin = keystring_md_pw3;
      else
	keystring_admin = NULL;

      r = gpg_do_write_prvkey (kk, prv, prvkey_len, keystring_admin, pubkey);
    }

  /* Clear private key data in the buffer.  */
  memset (buf, 0, 256);

  if (r < 0)
    {
      GPG_ERROR ();
      return;
    }

  DEBUG_INFO ("Calling gpg_do_public_key...\r\n");

  if (kk == GPG_KEY_FOR_SIGNING)
    {
      int pw_len;
      const uint8_t *initial_pw;
      uint8_t keystring[KEYSTRING_MD_SIZE];

      /* GnuPG expects it's ready for signing. */
      /* Don't call ac_reset_pso_cds here, but load the private key */

      gpg_reset_digital_signature_counter ();
      gpg_do_get_initial_pw_setting (0, &pw_len, &initial_pw);
      s2k (NULL, 0, initial_pw, pw_len, keystring);
      gpg_do_load_prvkey (GPG_KEY_FOR_SIGNING, BY_USER, keystring);
    }
  else
    ac_reset_other ();

  gpg_do_public_key (kk_byte);
}
