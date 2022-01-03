/*                                                    -*- coding: utf-8 -*-
 * ecc-mont.c - Elliptic curve computation for
 *              the Montgomery curve: y^2 = x^3 + 486662*x^2 + x.
 *
 * Copyright (C) 2014, 2015, 2017  Free Software Initiative of Japan
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
#include "bn.h"
#include "mod25638.h"
#include "mod.h"

/*
 * References:
 *
 * [1] D. J. Bernstein. Curve25519: new Diffie-Hellman speed records.
 *     Proceedings of PKC 2006, to appear.
 *     http://cr.yp.to/papers.html#curve25519. Date: 2006.02.09.
 *
 * [2] D. J. Bernstein. Can we avoid tests for zero in fast
 *     elliptic-curve arithmetic?
 *     http://cr.yp.to/papers.html#curvezero. Date: 2006.07.26.
 *
 */

/*
 * IMPLEMENTATION NOTE
 *
 * (0) We assume that the processor has no cache, nor branch target
 *     prediction.  Thus, we don't avoid indexing by secret value.
 *     We don't avoid conditional jump if both cases have same timing,
 *     either.
 *
 * (1) We use Radix-32 field arithmetic.  It's a representation like
 *     2^256-38, but it's more redundant.  For example, "1" can be
 *     represented in three ways in 256-bit: 1, 2^255-18, and
 *     2^256-37.
 *
 * (2) We use Montgomery double-and-add.
 *
 */

#ifndef BN256_C_IMPLEMENTATION
#define ASM_IMPLEMENTATION 0
#endif
/*
 *
 * 121665 = 0x1db41
 *            1 1101 1011 0100 0001
 */
static void
mod25638_mul_121665 (bn256 *x, const bn256 *a)
{
#if ASM_IMPLEMENTATION
#include "muladd_256.h"
  const uint32_t *s;
  uint32_t *d;
  uint32_t w;
  uint32_t c;

  s = a->word;
  d = x->word;
  memset (d, 0, sizeof (bn256));
  w = 121665;
  MULADD_256_ASM (s, d, w, c);
#else
  uint32_t c, c1;
  bn256 m[1];

  c = c1 = bn256_shift (m, a, 6); c += bn256_add (x, a, m);
  c1 <<= 2; c1 |= bn256_shift (m, m, 2); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 1; c1 |= bn256_shift (m, m, 1); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 2; c1 |= bn256_shift (m, m, 2); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 1; c1 |= bn256_shift (m, m, 1); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 2; c1 |= bn256_shift (m, m, 2); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 1; c1 |= bn256_shift (m, m, 1); c = c + c1 + bn256_add (x, x, m);
  c1 <<= 1; c1 |= bn256_shift (m, m, 1); c = c + c1 + bn256_add (x, x, m);
#endif
  c = bn256_add_uint (x, x, c*38);
  x->word[0] += c * 38;
}


typedef struct
{
  bn256 x[1];
  bn256 z[1];
} pt;


/**
 * @brief  Process Montgomery double-and-add
 *
 * With Q0, Q1, DIF (= Q0 - Q1), compute PRD = 2Q0, SUM = Q0 + Q1
 * Q0 and Q1 are clobbered.
 *
 */
static void
mont_d_and_a (pt *prd, pt *sum, pt *q0, pt *q1, const bn256 *dif_x)
{
                                        mod25638_add (sum->x, q1->x, q1->z);
                                        mod25638_sub (q1->z, q1->x, q1->z);
  mod25638_add (prd->x, q0->x, q0->z);
  mod25638_sub (q0->z, q0->x, q0->z);
                                        mod25638_mul (q1->x, q0->z, sum->x);
                                        mod25638_mul (q1->z, prd->x, q1->z);
  mod25638_sqr (q0->x, prd->x);
  mod25638_sqr (q0->z, q0->z);
                                        mod25638_add (sum->x, q1->x, q1->z);
                                        mod25638_sub (q1->z, q1->x, q1->z);
  mod25638_mul (prd->x, q0->x, q0->z);
  mod25638_sub (q0->z, q0->x, q0->z);
                                        mod25638_sqr (sum->x, sum->x);
                                        mod25638_sqr (sum->z, q1->z);
  mod25638_mul_121665 (prd->z, q0->z);
                                        mod25638_mul (sum->z, sum->z, dif_x);
  mod25638_add (prd->z, q0->x, prd->z);
  mod25638_mul (prd->z, prd->z, q0->z);
}


/**
 * @brief	RES  = x-coordinate of [n]Q
 *
 * @param N	Scalar N (three least significant bits are 000)
 * @param Q_X	x-coordinate of Q
 *
 */
static void
compute_nQ (bn256 *res, const bn256 *n, const bn256 *q_x)
{
  int i, j;
  pt p0[1], p1[1], p0_[1], p1_[1];

  /* P0 = O = (1:0)  */
  memset (p0->x, 0, sizeof (bn256));
  p0->x->word[0] = 1;
  memset (p0->z, 0, sizeof (bn256));

  /* P1 = (X:1) */
  memcpy (p1->x, q_x, sizeof (bn256));
  memset (p1->z, 0, sizeof (bn256));
  p1->z->word[0] = 1;

  for (i = 0; i < 8; i++)
    {
      uint32_t u = n->word[7-i];

      for (j = 0; j < 16; j++)
	{
	  pt *q0, *q1;
	  pt *sum_n, *prd_n;

	  if ((u & 0x80000000))
	    q0 = p1,  q1 = p0,  sum_n = p0_, prd_n = p1_;
	  else
	    q0 = p0,  q1 = p1,  sum_n = p1_, prd_n = p0_;
	  mont_d_and_a (prd_n, sum_n, q0, q1, q_x);

	  if ((u & 0x40000000))
	    q0 = p1_, q1 = p0_, sum_n = p0,  prd_n = p1;
	  else
	    q0 = p0_, q1 = p1_, sum_n = p1,  prd_n = p0;
	  mont_d_and_a (prd_n, sum_n, q0, q1, q_x);

	  u <<= 2;
	}
    }

  /* We know the LSB of N is always 0.  Thus, result is always in P0.  */
  /*
   * p0->z may be zero here, but our mod_inv doesn't raise error for 0,
   * but returns 0 (like the implementation of z^(p-2)), thus, RES will
   * be 0 in that case, which is correct value.
   */
  mod_inv (res, p0->z, p25519);
  mod25638_mul (res, res, p0->x);
  mod25519_reduce (res);
}


void
ecdh_compute_public_25519 (const uint8_t *key_data, uint8_t *pubkey)
{
  bn256 gx[1];
  bn256 k[1];

  memset (gx, 0, sizeof (bn256));
  gx[0].word[0] = 9;			/* Gx = 9 */
  memcpy (k, key_data, sizeof (bn256));

  compute_nQ ((bn256 *)pubkey, k, gx);
}

int
ecdh_decrypt_curve25519 (const uint8_t *input, uint8_t *output,
			 const uint8_t *key_data)
{
  bn256 q_x[1];
  bn256 k[1];
  bn256 shared[1];

  memcpy (q_x, input, sizeof (bn256));
  memcpy (k, key_data, sizeof (bn256));
  compute_nQ (shared, k, q_x);
  memcpy (output, shared, sizeof (bn256));
  return 0;
}
