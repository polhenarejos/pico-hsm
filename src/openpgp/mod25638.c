/*
 * mod25638.c -- modulo arithmetic of 2^256-38 for 2^255-19 field
 *
 * Copyright (C) 2014 Free Software Initiative of Japan
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
 * The field is \Z/(2^255-19)
 *
 * We use radix-32.  During computation, it's not reduced to 2^255-19,
 * but it is represented in 256-bit (it is redundant representation),
 * that is, something like 2^256-38.
 *
 * The idea is, keeping within 256-bit until it will be converted to
 * affine coordinates.
 */

#include <stdint.h>
#include <string.h>

#include "bn.h"
#include "mod25638.h"

#ifndef BN256_C_IMPLEMENTATION
#define ASM_IMPLEMENTATION 0
#endif

#if ASM_IMPLEMENTATION
#include "muladd_256.h"
#define ADDWORD_256(d_,s_,w_,c_)		        \
 asm ( "ldmia  %[s]!, { r4, r5, r6, r7 } \n\t"          \
       "adds   r4, r4, %[w]             \n\t"           \
       "adcs   r5, r5, #0               \n\t"           \
       "adcs   r6, r6, #0               \n\t"           \
       "adcs   r7, r7, #0               \n\t"           \
       "stmia  %[d]!, { r4, r5, r6, r7 }\n\t"           \
       "ldmia  %[s]!, { r4, r5, r6, r7 } \n\t"          \
       "adcs   r4, r4, #0               \n\t"           \
       "adcs   r5, r5, #0               \n\t"           \
       "adcs   r6, r6, #0               \n\t"           \
       "adcs   r7, r7, #0               \n\t"           \
       "stmia  %[d]!, { r4, r5, r6, r7 }\n\t"           \
       "mov    %[c], #0                 \n\t"           \
       "adc    %[c], %[c], #0"                          \
       : [s] "=&r" (s_), [d] "=&r" (d_), [c] "=&r" (c_)	\
       : "[s]" (s_), "[d]" (d_), [w] "r" (w_)		\
       : "r4", "r5", "r6", "r7", "memory", "cc" )
#endif

/*
256      224      192      160      128       96       64       32        0
2^256
  1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
2^256 - 16
  0 ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffff0
2^256 - 16 - 2
  0 ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffee
2^256 - 16 - 2 - 1
  0 ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffed
*/
const bn256 p25519[1] = {
  {{ 0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
     0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff }} };


/*
 * Implementation Note.
 *
 * It's not always modulo n25638.  The representation is redundant
 * during computation.  For example, when we add the number - 1 and 1,
 * it won't overflow to 2^256, and the result is represented within
 * 256-bit.
 */


/**
 * @brief  X = (A + B) mod 2^256-38
 */
void
mod25638_add (bn256 *X, const bn256 *A, const bn256 *B)
{
  uint32_t carry;

  carry = bn256_add (X, A, B);
  carry = bn256_add_uint (X, X, carry*38);
  X->word[0] += carry * 38;
}

/**
 * @brief  X = (A - B) mod 2^256-38
 */
void
mod25638_sub (bn256 *X, const bn256 *A, const bn256 *B)
{
  uint32_t borrow;

  borrow = bn256_sub (X, A, B);
  borrow = bn256_sub_uint (X, X, borrow*38);
  X->word[0] -= borrow * 38;
}


/**
 * @brief  X = A mod 2^256-38
 *
 * Note that the second argument is not "const bn512 *".
 * A is modified during the computation of modulo.
 *
 * It's not precisely modulo 2^256-38 for all cases,
 * but result may be redundant.
 */
static void
mod25638_reduce (bn256 *X, bn512 *A)
{
  const uint32_t *s;
  uint32_t *d;
  uint32_t w;

#if ASM_IMPLEMENTATION
  uint32_t c, c0;

  s = &A->word[8]; d = &A->word[0]; w = 38; MULADD_256 (s, d, w, c);
  c0 = A->word[8] * 38;
  d = &X->word[0];
  s = &A->word[0];
  ADDWORD_256 (d, s, c0, c);
  X->word[0] += c * 38;
#else
  s = &A->word[8]; d = &A->word[0]; w = 38;
  {
    int i;
    uint64_t r;
    uint32_t carry;

    r = 0;
    for (i = 0; i < BN256_WORDS; i++)
      {
	uint64_t uv;

	r += d[i];
	carry = (r < d[i]);

	uv = ((uint64_t)s[i])*w;
	r += uv;
	carry += (r < uv);

	d[i] = (uint32_t)r;
	r = ((r >> 32) | ((uint64_t)carry << 32));
      }

    carry = bn256_add_uint (X, (bn256 *)A, r * 38);
    X->word[0] += carry * 38;
  }
#endif
}

/**
 * @brief  X = (A * B) mod 2^256-38
 */
void
mod25638_mul (bn256 *X, const bn256 *A, const bn256 *B)
{
  bn512 tmp[1];

  bn256_mul (tmp, A, B);
  mod25638_reduce (X, tmp);
}

/**
 * @brief  X = A * A mod 2^256-38
 */
void
mod25638_sqr (bn256 *X, const bn256 *A)
{
  bn512 tmp[1];

  bn256_sqr (tmp, A);
  mod25638_reduce (X, tmp);
}


/**
 * @brief  X = (A << shift) mod 2^256-38
 * @note   shift < 32
 */
void
mod25638_shift (bn256 *X, const bn256 *A, int shift)
{
  uint32_t carry;
  bn256 tmp[1];

  carry = bn256_shift (X, A, shift);
  if (shift < 0)
    return;

  memset (tmp, 0, sizeof (bn256));
  tmp->word[0] = (carry << 1);
  /* tmp->word[1] = (carry >> 31);  always zero.  */
  tmp->word[0] = tmp->word[0] + (carry << 2);
  tmp->word[1] = (tmp->word[0] < (carry << 2)) + (carry >> 30);
  tmp->word[0] = tmp->word[0] + (carry << 5);
  tmp->word[1] = tmp->word[1] + (tmp->word[0] < (carry << 5)) + (carry >> 27);

  mod25638_add (X, X, tmp);
}


/*
 * @brief  X = A mod 2^255-19
 *
 * It's precisely modulo 2^255-19 (unlike mod25638_reduce).
 */
void
mod25519_reduce (bn256 *X)
{
  uint32_t q;
  bn256 r0[1], r1[1];
  int flag;

  memcpy (r0, X, sizeof (bn256));
  q = (r0->word[7] >> 31);
  r0->word[7] &= 0x7fffffff;
  if (q)
    {
      bn256_add_uint (r0, r0, 19);
      q = (r0->word[7] >> 31);
      r0->word[7] &= 0x7fffffff;
      if (q)
	{
	  bn256_add_uint (r1, r0, 19);
	  q = (r1->word[7] >> 31);
	  r1->word[7] &= 0x7fffffff;
	  flag = 0;
	}
      else
	flag = 1;
    }
  else
    {
      bn256_add_uint (r1, r0, 19);
      q = (r1->word[7] >> 31);	 /* dummy */
      r1->word[7] &= 0x7fffffff; /* dummy */
      if (q)
	flag = 2;
      else
	flag = 3;
    }

  if (flag)
    {
      bn256_add_uint (r1, r0, 19);
      q = (r1->word[7] >> 31);
      r1->word[7] &= 0x7fffffff;
      if (q)
	memcpy (X, r1, sizeof (bn256));
      else
	memcpy (X, r0, sizeof (bn256));
    }
  else
    {
      if (q)
	{
	  asm volatile ("" : : "r" (q) : "memory");
	  memcpy (X, r1, sizeof (bn256));
	  asm volatile ("" : : "r" (q) : "memory");
	}
      else
	memcpy (X, r1, sizeof (bn256));
    }
}
