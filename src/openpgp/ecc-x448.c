/*                                                    -*- coding: utf-8 -*-
 * ecc-x448.c - Elliptic curve computation for
 *              the Montgomery curve: y^2 = x^3 + 156326*x^2 + x
 *
 * Copyright (C) 2021  Free Software Initiative of Japan
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
 * IMPLEMENTATION NOTE
 *
 * (0) We assume that the processor has no cache, nor branch target
 *     prediction.
 *     We don't avoid conditional jump if both cases have same timing,
 *     either.
 *
 */

#include <stdint.h>
#include <string.h>

#include "p448.h"

#define N_LIMBS 14

/**
 * @brief  Process Montgomery double-and-add
 *
 * With Q0, Q1, DIF (= Q0 - Q1), compute PRD = 2Q0 into Q0,
 * and computute SUM = Q0 + Q1 into Q1
 *
 */
static void
mont_d_and_a (p448_t q0_x[1], p448_t q0_z[1], p448_t q1_x[1], p448_t q1_z[1],
	      const p448_t dif_x[1])
{
  p448_t reg0[1], reg1[1];
#define c  reg0
#define d  reg1
#define a  q1_x
#define b  q1_z
#define cb q0_x
#define da reg0
#define aa reg1
#define bb q0_z
#define da_plus_cb  q1_z
#define da_minus_cb q1_x
#define e      reg0
#define dacb_2 q0_z
#define a24_e  q1_x
#define aa_    aa /* override is allowed by p448_add */

					p448_add (c, q1_x, q1_z);
					p448_sub (d, q1_x, q1_z);
  p448_add (a, q0_x, q0_z);
  p448_sub (b, q0_x, q0_z);
					p448_mul (cb, c, b);
					p448_mul (da, d, a);
  p448_sqr (aa, a);
  p448_sqr (bb, b);
					p448_add (da_plus_cb, da, cb);
					p448_sub (da_minus_cb, da, cb);
  p448_mul (q0_x, aa, bb);
  p448_sub (e, aa, bb);
					p448_sqr (dacb_2, da_minus_cb);
  p448_mul_39081 (a24_e, e);
  p448_add (aa_, aa, a24_e);
					p448_sqr (q1_x, da_plus_cb);
					p448_mul (q1_z, dacb_2, dif_x);
  p448_mul (q0_z, e, aa_);
}


typedef struct
{
  p448_t x[1];
  p448_t z[1];
} pt;


/**
 * @brief	RES  = x-coordinate of [n]Q
 *
 * @param N	Scalar N (three least significant bits are 00)
 * @param Q_X	x-coordinate of Q
 *
 */
static void
compute_nQ (uint8_t *res, const uint32_t n[N_LIMBS], const p448_t q_x[1])
{
  int i, j;
  pt p0[1], p1[1];
#define tmp0 p0->z
#define tmp1 p1->z

  /* P0 = O = (1:0)  */
  memset (p0->x, 0, sizeof (p0->x));
  p0->x->limb[0] = 1;
  memset (p0->z, 0, sizeof (p0->z));

  /* P1 = (X:1) */
  memcpy (p1->x, q_x, N_REDUNDANT_LIMBS*4);
  memset (p1->z, 0, sizeof (p1->z));
  p1->z->limb[0] = 1;

  for (i = 0; i < N_LIMBS; i++)
    {
      uint32_t u = n[N_LIMBS-i-1];

      for (j = 0; j < 32; j++)
	{
	  p448_t *q0_x, *q0_z, *q1_x, *q1_z;

	  if ((u & 0x80000000))
	    q0_x = p1->x, q0_z = p1->z,   q1_x = p0->x, q1_z = p0->z;
	  else
	    q0_x = p0->x, q0_z = p0->z,   q1_x = p1->x, q1_z = p1->z;
	  mont_d_and_a (q0_x, q0_z, q1_x, q1_z, q_x);

	  u <<= 1;
	}
    }

  /* We know the LSB of N is always 0.  Thus, result is always in P0.  */
  /*
   * p0->z may be zero here, but our inverse function doesn't raise
   * error for 0, but returns 0, thus, RES will be 0 in that case,
   * which is correct value.
   */
  p448_inv (tmp1, p0->z);
  p448_mul (tmp0, tmp1, p0->x);
  p448_serialize (res, tmp0);
}


void
ecdh_compute_public_x448 (uint8_t *pubkey, const uint8_t *key_data)
{
  const p448_t gx[1] = { { { 5, 0, }, } };
  uint32_t k[N_LIMBS];

  memcpy (k, key_data, N_LIMBS*4);
  k[0] &= ~3;
  k[N_LIMBS-1] |= 0x80000000;
  compute_nQ (pubkey, k, gx);
}

int
ecdh_decrypt_x448 (uint8_t *output, const uint8_t *input,
		   const uint8_t *key_data)
{
  p448_t q_x[1];
  uint32_t k[N_LIMBS];

  p448_deserialize (q_x, input);
  memcpy (k, key_data, N_LIMBS*4);
  k[0] &= ~3;
  k[N_LIMBS-1] |= 0x80000000;
  compute_nQ (output, k, q_x);
  return 0;
}
