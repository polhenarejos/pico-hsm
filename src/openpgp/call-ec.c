/*
 * call-ec.c - interface between Gnuk and Elliptic curve over GF(prime)
 *
 * Copyright (C) 2013, 2014, 2017  Free Software Initiative of Japan
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

#include "field-group-select.h"

/* We are little-endian in the computation, but the protocol is big-endian.  */

#define ECDSA_BYTE_SIZE 32
#define ECDH_BYTE_SIZE 32

int
FUNC(ecdsa_sign) (const uint8_t *hash, uint8_t *output,
		  const uint8_t *key_data)
{
  int i;
  bn256 r[1], s[1], z[1], d[1];
  uint8_t *p;

  p = (uint8_t *)d;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    p[ECDSA_BYTE_SIZE - i - 1] = key_data[i];

  p = (uint8_t *)z;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    p[ECDSA_BYTE_SIZE - i - 1] = hash[i];

  FUNC(ecdsa) (r, s, z, d);
  p = (uint8_t *)r;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    *output++ = p[ECDSA_BYTE_SIZE - i - 1];
  p = (uint8_t *)s;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    *output++ = p[ECDSA_BYTE_SIZE - i - 1];
  return 0;
}

int
FUNC(ecc_compute_public) (const uint8_t *key_data, uint8_t *pubkey)
{
  uint8_t *p, *p1;
  ac q[1];
  bn256 k[1];
  int i;

  p = (uint8_t *)k;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    p[ECDSA_BYTE_SIZE - i - 1] = key_data[i];
  if (FUNC(compute_kG) (q, k) < 0)
    return -1;

  p = pubkey;
  p1 = (uint8_t *)q->x;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    *p++ = p1[ECDSA_BYTE_SIZE - i - 1];
  p1 = (uint8_t *)q->y;
  for (i = 0; i < ECDSA_BYTE_SIZE; i++)
    *p++ = p1[ECDSA_BYTE_SIZE - i - 1];

  return 0;
}

int
FUNC(ecdh_decrypt) (const uint8_t *input, uint8_t *output,
		    const uint8_t *key_data)
{
  bn256 k[1];
  ac X[1], P[1];
  int i;
  uint8_t *p0;
  const uint8_t *p1;
  int r;

  p0 = (uint8_t *)k;
  for (i = 0; i < ECDH_BYTE_SIZE; i++)
    p0[ECDH_BYTE_SIZE - i - 1] = key_data[i];

  p1 = input+1;			/* skip '04' */
  p0 = (uint8_t *)P->x;
  for (i = 0; i < ECDH_BYTE_SIZE; i++)
    p0[ECDH_BYTE_SIZE - i - 1] = *p1++;
  p0 = (uint8_t *)P->y;
  for (i = 0; i < ECDH_BYTE_SIZE; i++)
    p0[ECDH_BYTE_SIZE - i - 1] = *p1++;

  r = FUNC(compute_kP) (X, k, P);
  if (r == 0)
    {
      p0 = output;
      p1 = (const uint8_t *)X->x;
      *p0++ = 4;
      for (i = 0; i < ECDH_BYTE_SIZE; i++)
	*p0++ = p1[ECDH_BYTE_SIZE - i - 1];
      p1 = (const uint8_t *)X->y;
      for (i = 0; i < ECDH_BYTE_SIZE; i++)
	*p0++ = p1[ECDH_BYTE_SIZE - i - 1];
    }

  return r;
}


/**
 * @brief Check if a secret d0 is valid or not
 *
 * @param D0	scalar D0: secret
 * @param D1	scalar D1: secret candidate N-D0
 *
 * Return 0 on error.
 * Return -1 when D1 should be used as the secret
 * Return 1 when D0 should be used as the secret
 */
int
FUNC(ecc_check_secret) (const uint8_t *d0, uint8_t *d1)
{
  return FUNC(check_secret) ((const bn256 *)d0, (bn256 *)d1);
}
