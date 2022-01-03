/*                                                    -*- coding: utf-8 -*-
 * ecc.c - Elliptic curve over GF(prime)
 *
 * Copyright (C) 2011, 2013, 2014, 2015
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

/*
 * References:
 *
 * [1] Suite B Implementer's Guide to FIPS 186-3 (ECDSA), February 3, 2010.
 *
 * [2] Michael Brown, Darrel Hankerson, Julio López, and Alfred Menezes,
 *     Software Implementation of the NIST Elliptic Curves Over Prime Fields,
 *     Proceedings of the 2001 Conference on Topics in Cryptology: The
 *     Cryptographer's Track at RSA
 *     Pages 250-265, Springer-Verlag London, UK, 2001
 *     ISBN:3-540-41898-9
 *
 * [3] Mustapha Hedabou, Pierre Pinel, Lucien Bénéteau,
 *     A comb method to render ECC resistant against Side Channel Attacks,
 *     2004
 */

#include "field-group-select.h"

/*
 * Coefficients
 */
/*
 * static const bn256 *coefficient_a;
 * static const bn256 *coefficient_b;
 */
/*
 * N: order of G
 */
/*
 * static const bn256 N[1];
 */
/*
 * MU = 2^512 / N
 * MU = ( (1 << 256) | MU_lower )
 */
/*
 * static const bn256 MU_lower[1];
 */

/*
 * w = 4
 * m = 256
 * d = 64
 * e = 32
 */

/*
 * static const ac precomputed_KG[15];
 * static const ac precomputed_2E_KG[15];
 */

#if TEST
/*
 * Generator of Elliptic curve over GF(p256)
 */
const ac *G = &precomputed_KG[0];
#endif


static int
get_vk (const bn256 *K, int i)
{
  uint32_t w0, w1, w2, w3;

  if (i < 32)
    {
      w3 = K->word[6]; w2 = K->word[4]; w1 = K->word[2]; w0 = K->word[0];
    }
  else
    {
      w3 = K->word[7]; w2 = K->word[5]; w1 = K->word[3]; w0 = K->word[1];
      i -= 32;
    }

  w3 >>= i;  w2 >>= i;  w1 >>= i;  w0 >>= i;
  return ((w3 & 1) << 3) | ((w2 & 1) << 2) | ((w1 & 1) << 1) | (w0 & 1);
}


/**
 * @brief	X  = k * G
 *
 * @param K	scalar k
 *
 * Return -1 on error.
 * Return 0 on success.
 */
int
FUNC(compute_kG) (ac *X, const bn256 *K)
{
  uint8_t index[64]; /* Lower 4-bit for index absolute value, msb is
			for sign (encoded as: 0 means 1, 1 means -1).  */
  bn256 K_dash[1];
  jpc Q[1], tmp[1], *dst;
  int i;
  int vk;
  uint32_t k_is_even = bn256_is_even (K);

  bn256_sub_uint (K_dash, K, k_is_even);
  /* It keeps the condition: 1 <= K' <= N - 2, and K' is odd.  */

  /* Fill index.  */
  vk = get_vk (K_dash, 0);
  for (i = 1; i < 64; i++)
    {
      int vk_next, is_zero;

      vk_next = get_vk (K_dash, i);
      is_zero = (vk_next == 0);
      index[i-1] = (vk - 1) | (is_zero << 7);
      vk = (is_zero ? vk : vk_next);
    }
  index[63] = vk - 1;

  memset (Q->z, 0, sizeof (bn256)); /* infinity */
  for (i = 31; i >= 0; i--)
    {
      FUNC(jpc_double) (Q, Q);
      FUNC(jpc_add_ac_signed) (Q, Q, &precomputed_2E_KG[index[i+32]&0x0f],
			       index[i+32] >> 7);
      FUNC(jpc_add_ac_signed) (Q, Q, &precomputed_KG[index[i]&0x0f],
			       index[i] >> 7);
    }

  dst = k_is_even ? Q : tmp;
  FUNC(jpc_add_ac) (dst, Q, &precomputed_KG[0]);

  return FUNC(jpc_to_ac) (X, Q);
}



/**
 * check if P is on the curve.
 *
 * Return -1 on error.
 * Return 0 on success.
 */
static int
point_is_on_the_curve (const ac *P)
{
  bn256 s[1], t[1];

  /* Elliptic curve: y^2 = x^3 + a*x + b */
  MFNC(sqr) (s, P->x);
  MFNC(mul) (s, s, P->x);

#ifndef COEFFICIENT_A_IS_ZERO
  MFNC(mul) (t, coefficient_a, P->x);
  MFNC(add) (s, s, t);
#endif
  MFNC(add) (s, s, coefficient_b);

  MFNC(sqr) (t, P->y);
  if (bn256_cmp (s, t) == 0)
    return 0;
  else
    return -1;
}


static int
get_vk_kP (const bn256 *K, int i)
{
  uint32_t w;
  uint8_t blk = i/32;
  uint8_t pos = i%32;
  uint8_t col = 3*(pos % 11) + (pos >= 11) + (pos >= 22);
  uint8_t word_index = (blk * 3) + (pos / 11);

  w = ((K->word[word_index] >> col) & 7);
  if (word_index < 7 && (pos == 10 || pos == 21))
    {
      uint8_t mask;
      uint8_t shift;

      word_index++;
      if (pos == 10)
	{
	  shift = 2;
	  mask = 4;
	}
      else
	{
	  shift = 1;
	  mask = 6;
	}

      w |= ((K->word[word_index] << shift) & mask);
    }

  return w;
}

/**
 * @brief	X  = k * P
 *
 * @param K	scalar k
 * @param P	P in affine coordiate
 *
 * Return -1 on error.
 * Return 0 on success.
 *
 * For the curve (cofactor is 1 and n is prime), possible error cases are:
 *
 *     P is not on the curve.
 *     P = G, k = n
 *     Something wrong in the code.
 *
 * Mathmatically, k=1 and P=O is another possible case, but O cannot be
 * represented by affine coordinate.
 */
int
FUNC(compute_kP) (ac *X, const bn256 *K, const ac *P)
{
  uint8_t index[86]; /* Lower 2-bit for index absolute value, msb is
			for sign (encoded as: 0 means 1, 1 means -1).  */
  bn256 K_dash[1];
  uint32_t k_is_even = bn256_is_even (K);
  jpc Q[1], tmp[1], *dst;
  int i;
  int vk;
  ac P3[1], P5[1], P7[1];
  const ac *p_Pi[4];

  if (point_is_on_the_curve (P) < 0)
    return -1;

  if (bn256_sub (K_dash, K, N) == 0)	/* >= N, it's too big.  */
    return -1;

  bn256_sub_uint (K_dash, K, k_is_even);
  /* It keeps the condition: 1 <= K' <= N - 2, and K' is odd.  */

  p_Pi[0] = P;
  p_Pi[1] = P3;
  p_Pi[2] = P5;
  p_Pi[3] = P7;

  {
    jpc Q1[1];

    memcpy (Q->x, P->x, sizeof (bn256));
    memcpy (Q->y, P->y, sizeof (bn256));
    memset (Q->z, 0, sizeof (bn256));
    Q->z->word[0] = 1;

    FUNC(jpc_double) (Q, Q);
    FUNC(jpc_add_ac) (Q1, Q, P);
    if (FUNC(jpc_to_ac) (P3, Q1) < 0) /* Never occurs, except coding errors.  */
      return -1;
    FUNC(jpc_double) (Q, Q);
    FUNC(jpc_add_ac) (Q1, Q, P);
    if (FUNC(jpc_to_ac) (P5, Q1) < 0) /* Never occurs, except coding errors.  */
      return -1;

    memcpy (Q->x, P3->x, sizeof (bn256));
    memcpy (Q->y, P3->y, sizeof (bn256));
    memset (Q->z, 0, sizeof (bn256));
    Q->z->word[0] = 1;
    FUNC(jpc_double) (Q, Q);
    FUNC(jpc_add_ac) (Q1, Q, P);
    if (FUNC(jpc_to_ac) (P7, Q1) < 0) /* Never occurs, except coding errors.  */
      return -1;
  }

  /* Fill index.  */
  vk = get_vk_kP (K_dash, 0);
  for (i = 1; i < 86; i++)
    {
      int vk_next, is_even;

      vk_next = get_vk_kP (K_dash, i);
      is_even = ((vk_next & 1) == 0);
      index[i-1] = (is_even << 7) | ((is_even?7-vk:vk-1) >> 1);
      vk = vk_next + is_even;
    }
  index[85] = ((vk - 1) >> 1);

  memset (Q->z, 0, sizeof (bn256)); /* infinity */
  for (i = 85; i >= 0; i--)
    {
      FUNC(jpc_double) (Q, Q);
      FUNC(jpc_double) (Q, Q);
      FUNC(jpc_double) (Q, Q);
      FUNC(jpc_add_ac_signed) (Q, Q, p_Pi[index[i]&0x03], index[i] >> 7);
    }

  dst = k_is_even ? Q : tmp;
  FUNC(jpc_add_ac) (dst, Q, P);

  return FUNC(jpc_to_ac) (X, Q);
}


/**
 * @brief Compute signature (r,s) of hash string z with secret key d
 */
void
FUNC(ecdsa) (bn256 *r, bn256 *s, const bn256 *z, const bn256 *d)
{
  bn256 k[1];
  ac KG[1];
  bn512 tmp[1];
  bn256 k_inv[1];
  uint32_t carry;
#define borrow carry
#define tmp_k k_inv

  do
    {
      do
	{
	  bn256_random (k);
	  if (bn256_add_uint (k, k, 1))
	    continue;
	  if (bn256_sub (tmp_k, k, N) == 0)	/* >= N, it's too big.  */
	    continue;
	  /* 1 <= k <= N - 1 */
	  FUNC(compute_kG) (KG, k);
	  borrow = bn256_sub (r, KG->x, N);
	  if (borrow)
	    memcpy (r, KG->x, sizeof (bn256));
	  else
	    memcpy (KG->x, r, sizeof (bn256));
	}
      while (bn256_is_zero (r));

      mod_inv (k_inv, k, N);
      bn256_mul (tmp, r, d);
      mod_reduce (s, tmp, N, MU_lower);
      carry = bn256_add (s, s, z);
      if (carry)
	bn256_sub (s, s, N);
      else
	bn256_sub ((bn256 *)tmp, s, N);
      bn256_mul (tmp, s, k_inv);
      mod_reduce (s, tmp, N, MU_lower);
    }
  while (bn256_is_zero (s));

#undef tmp_k
#undef borrow
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
FUNC(check_secret) (const bn256 *d0, bn256 *d1)
{
  ac Q0[1], Q1[1];

  if (bn256_is_zero (d0) || bn256_sub (d1, N, d0) != 0)
    /* == 0 or >= N, it's not valid.  */
    return 0;

  FUNC(compute_kG) (Q0, d0);
  FUNC(compute_kG) (Q1, d1);

  /*
   * Jivsov compliant key check
   */
  return bn256_cmp (Q1[0].y, Q0[0].y);
}
