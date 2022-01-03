/*
 * ac.c -- Check access condition
 *
 * Copyright (C) 2010, 2012, 2013, 2017 Free Software Initiative of Japan
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
#include "sha256.h"
#include "random.h"

uint8_t volatile auth_status;	/* Initialized to AC_NONE_AUTHORIZED */

int
ac_check_status (uint8_t ac_flag)
{
  if (ac_flag == AC_ALWAYS)
    return 1;
  else if (ac_flag == AC_NEVER)
    return 0;
  else
    return (ac_flag & auth_status)? 1 : 0;
}

void
ac_reset_pso_cds (void)
{
  gpg_do_clear_prvkey (GPG_KEY_FOR_SIGNING);
  auth_status &= ~AC_PSO_CDS_AUTHORIZED;
}

void
ac_reset_other (void)
{
  gpg_do_clear_prvkey (GPG_KEY_FOR_DECRYPTION);
  gpg_do_clear_prvkey (GPG_KEY_FOR_AUTHENTICATION);
  auth_status &= ~AC_OTHER_AUTHORIZED;
}

int
verify_user_0 (uint8_t access, const uint8_t *pw, int buf_len, int pw_len_known,
	       const uint8_t *ks_pw1, int save_ks)
{
  int pw_len;
  int r;
  uint8_t keystring[KEYSTRING_MD_SIZE];
  const uint8_t *salt;
  int salt_len;

  if (gpg_pw_locked (PW_ERR_PW1))
    return 0;

  if (ks_pw1 == NULL)
    {
      const uint8_t *initial_pw;

      salt = NULL;
      salt_len = 0;
      gpg_do_get_initial_pw_setting (0, &pw_len, &initial_pw);
      if ((pw_len_known >= 0 && pw_len_known != pw_len)
	  || buf_len < pw_len
	  || memcmp (pw, initial_pw, pw_len))
	goto failure;
    }
  else
    {
      pw_len = ks_pw1[0] & PW_LEN_MASK;
      salt = KS_GET_SALT (ks_pw1);
      salt_len = SALT_SIZE;

      if ((pw_len_known >= 0 && pw_len_known != pw_len)
	  || buf_len < pw_len)
	goto failure;
    }

  s2k (salt, salt_len, pw, pw_len, keystring);
  if (save_ks)
    memcpy (keystring_md_pw3, keystring, KEYSTRING_MD_SIZE);

  if (access == AC_PSO_CDS_AUTHORIZED)
    r = gpg_do_load_prvkey (GPG_KEY_FOR_SIGNING, BY_USER, keystring);
  else
    {
      int r1, r2;

      r1 = gpg_do_load_prvkey (GPG_KEY_FOR_DECRYPTION, BY_USER, keystring);
      r2 = gpg_do_load_prvkey (GPG_KEY_FOR_AUTHENTICATION, BY_USER, keystring);

      if (r1 < 0 || r2 < 0)
	r = -1;
      else if (r1 == 0)
	{
	  if (r2 == 0)
	    /* No encryption/authentication keys, then, check signing key.  */
	    r = gpg_do_load_prvkey (GPG_KEY_FOR_SIGNING, BY_USER, keystring);
	  else
	    r = r2;
	}
      else if (r2 == 0)
	r = r1;
      else
	r = 1;
    }

  if (r < 0)
    {
    failure:
      gpg_pw_increment_err_counter (PW_ERR_PW1);
      return -1;
    }

  gpg_pw_reset_err_counter (PW_ERR_PW1);
  return pw_len;
}

/*
 * Verify for "Perform Security Operation : Compute Digital Signature"
 */
int
verify_pso_cds (const uint8_t *pw, int pw_len)
{
  const uint8_t *ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);
  int r;

  DEBUG_INFO ("verify_pso_cds\r\n");
  DEBUG_BYTE (pw_len);

  r = verify_user_0 (AC_PSO_CDS_AUTHORIZED, pw, pw_len, pw_len, ks_pw1, 0);
  if (r > 0)
    auth_status |= AC_PSO_CDS_AUTHORIZED;
  return r;
}

int
verify_other (const uint8_t *pw, int pw_len)
{
  const uint8_t *ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);
  int r;

  DEBUG_INFO ("verify_other\r\n");
  DEBUG_BYTE (pw_len);

  r = verify_user_0 (AC_OTHER_AUTHORIZED, pw, pw_len, pw_len, ks_pw1, 0);
  if (r > 0)
    auth_status |= AC_OTHER_AUTHORIZED;
  return r;
}


static int
verify_admin_00 (const uint8_t *pw, int buf_len, int pw_len_known,
		 const uint8_t *ks, int save_ks)
{
  int pw_len;
  int r;
  uint8_t keystring[KEYSTRING_MD_SIZE];
  const uint8_t *salt;
  int salt_len;

  pw_len = ks[0] & PW_LEN_MASK;
  salt = KS_GET_SALT (ks);
  salt_len = SALT_SIZE;

  if ((pw_len_known >= 0 && pw_len_known != pw_len) || buf_len < pw_len)
    return -1;

  s2k (salt, salt_len, pw, pw_len, keystring);
  if (save_ks)
    memcpy (keystring_md_pw3, keystring, KEYSTRING_MD_SIZE);

  r = gpg_do_load_prvkey (GPG_KEY_FOR_SIGNING, BY_ADMIN, keystring);

  if (r < 0)
    return -1;
  else if (r == 0)
    if ((ks[0] & PW_LEN_KEYSTRING_BIT) == 0
	|| memcmp (KS_GET_KEYSTRING (ks), keystring, KEYSTRING_MD_SIZE) != 0)
      return -1;

  return pw_len;
}

uint8_t keystring_md_pw3[KEYSTRING_MD_SIZE];
uint8_t admin_authorized;

int
verify_admin_0 (const uint8_t *pw, int buf_len, int pw_len_known,
		const uint8_t *pw3_keystring, int save_ks)
{
  int pw_len;

  if (pw3_keystring != NULL)
    {
      if (gpg_pw_locked (PW_ERR_PW3))
	return 0;

      pw_len = verify_admin_00 (pw, buf_len, pw_len_known, pw3_keystring,
				save_ks);
      if (pw_len < 0)
	{
	failure:
	  gpg_pw_increment_err_counter (PW_ERR_PW3);
	  return -1;
	}

      admin_authorized = BY_ADMIN;
    success:		       /* OK, the admin is now authenticated.  */
      gpg_pw_reset_err_counter (PW_ERR_PW3);
      return pw_len;
    }
  else
    {
      const uint8_t *initial_pw;
      const uint8_t *ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);

      if (ks_pw1 != NULL)
	{	  /* empty PW3, but PW1 exists */
	  int r = verify_user_0 (AC_PSO_CDS_AUTHORIZED,
				 pw, buf_len, pw_len_known, ks_pw1, save_ks);

	  if (r > 0)
	    admin_authorized = BY_USER;

	  return r;
	}

      if (gpg_pw_locked (PW_ERR_PW3))
	return 0;

      /*
       * For the case of empty PW3 (with empty PW1), passphrase is
       * OPENPGP_CARD_INITIAL_PW3, or defined by KDF DO.
       */
      gpg_do_get_initial_pw_setting (1, &pw_len, &initial_pw);
      if ((pw_len_known >=0 && pw_len_known != pw_len)
	  || buf_len < pw_len
	  || memcmp (pw, initial_pw, pw_len))
	goto failure;

      admin_authorized = BY_ADMIN;
      if (save_ks)
	s2k (NULL, 0, pw, pw_len, keystring_md_pw3);
      goto success;
    }
}


int
verify_admin (const uint8_t *pw, int pw_len)
{
  int r;
  const uint8_t *pw3_keystring;

  pw3_keystring = gpg_do_read_simple (NR_DO_KEYSTRING_PW3);
  r = verify_admin_0 (pw, pw_len, pw_len, pw3_keystring, 1);
  if (r <= 0)
    return r;

  auth_status |= AC_ADMIN_AUTHORIZED;
  return 1;
}

void
ac_reset_admin (void)
{
  memset (keystring_md_pw3, 0, KEYSTRING_MD_SIZE);
  auth_status &= ~AC_ADMIN_AUTHORIZED;
  admin_authorized = 0;
}

void
ac_fini (void)
{
  memset (keystring_md_pw3, 0, KEYSTRING_MD_SIZE);
  gpg_do_clear_prvkey (GPG_KEY_FOR_SIGNING);
  gpg_do_clear_prvkey (GPG_KEY_FOR_DECRYPTION);
  gpg_do_clear_prvkey (GPG_KEY_FOR_AUTHENTICATION);
  auth_status = AC_NONE_AUTHORIZED;
  admin_authorized = 0;
}
