/*
 * bn.c -- 256-bit (and 512-bit) bignum calculation
 *
 * Copyright (C) 2011, 2013, 2014, 2019
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
#ifndef BN256_NO_RANDOM
#include "random.h"
#endif
#include "bn.h"

uint32_t
bn256_add (bn256 *X, const bn256 *A, const bn256 *B)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN256_WORDS; i++)
    {
      v = *pb;
      *px = *pa + carry;
      carry = (*px < carry);
      *px += v;
      carry += (*px < v);
      px++;
      pa++;
      pb++;
    }

  return carry;
}

uint32_t
bn256_sub (bn256 *X, const bn256 *A, const bn256 *B)
{
  int i;
  uint32_t v;
  uint32_t borrow = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN256_WORDS; i++)
    {
      uint32_t borrow0 = (*pa < borrow);

      v = *pb;
      *px = *pa - borrow;
      borrow = (*px < v) + borrow0;
      *px -= v;
      px++;
      pa++;
      pb++;
    }

  return borrow;
}

uint32_t
bn256_add_uint (bn256 *X, const bn256 *A, uint32_t w)
{
  int i;
  uint32_t carry = w;
  uint32_t *px;
  const uint32_t *pa;

  px = X->word;
  pa = A->word;

  for (i = 0; i < BN256_WORDS; i++)
    {
      *px = *pa + carry;
      carry = (*px < carry);
      px++;
      pa++;
    }

  return carry;
}

uint32_t
bn256_sub_uint (bn256 *X, const bn256 *A, uint32_t w)
{
  int i;
  uint32_t borrow = w;
  uint32_t *px;
  const uint32_t *pa;

  px = X->word;
  pa = A->word;

  for (i = 0; i < BN256_WORDS; i++)
    {
      uint32_t borrow0 = (*pa < borrow);

      *px = *pa - borrow;
      borrow = borrow0;
      px++;
      pa++;
    }

  return borrow;
}

#ifndef BN256_C_IMPLEMENTATION
#define ASM_IMPLEMENTATION 0
#endif
void
bn256_mul (bn512 *X, const bn256 *A, const bn256 *B)
{
#if ASM_IMPLEMENTATION
#include "muladd_256.h"
  const uint32_t *s;
  uint32_t *d;
  uint32_t w;
  uint32_t c;

  memset (X->word, 0, sizeof (uint32_t)*BN256_WORDS*2);

  s = A->word;  d = &X->word[0];  w = B->word[0];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[1];  w = B->word[1];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[2];  w = B->word[2];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[3];  w = B->word[3];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[4];  w = B->word[4];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[5];  w = B->word[5];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[6];  w = B->word[6];  MULADD_256 (s, d, w, c);
  s = A->word;  d = &X->word[7];  w = B->word[7];  MULADD_256 (s, d, w, c);
#else
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= (BN256_WORDS - 1)*2; k++)
    {
      if (k < BN256_WORDS)
	{
	  i_beg = 0;
	  i_end = k;
	}
      else
	{
	  i_beg = k - BN256_WORDS + 1;
	  i_end = BN256_WORDS - 1;
	}

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;

	  uv = ((uint64_t )A->word[i])*((uint64_t )B->word[j]);
	  v = uv;
	  u = (uv >> 32);
	  r0 += v;
	  carry = (r0 < v);
	  r1 += carry;
	  carry = (r1 < carry);
	  r1 += u;
	  carry += (r1 < u);
	  r2 += carry;
	}

      X->word[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  X->word[k] = r0;
#endif
}

void
bn256_sqr (bn512 *X, const bn256 *A)
{
#if ASM_IMPLEMENTATION
  int i;

  memset (X->word, 0, sizeof (bn512));
  for (i = 0; i < BN256_WORDS; i++)
    {
      uint32_t *wij = &X->word[i*2];
      const uint32_t *xj = &A->word[i];
      uint32_t x_i = *xj++;
      uint32_t c;

      asm (/* (C,R4,R5) := w_i_i + x_i*x_i; w_i_i := R5; */
           "mov    %[c], #0\n\t"
           "ldr    r5, [%[wij]]\n\t"          /* R5 := w_i_i; */
           "mov    r4, %[c]\n\t"
           "umlal  r5, r4, %[x_i], %[x_i]\n\t"
           "str    r5, [%[wij]], #4\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bhi    0f\n\t"
           "mov    r9, %[c]\n\t"  /* R9 := 0, the constant ZERO from here.  */
           "beq    1f\n"
   "2:\n\t"
           "ldmia  %[xj]!, { r7, r8 }\n\t"
           "ldmia  %[wij], { r5, r6 }\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "umull  r7, r12, %[x_i], r7\n\t"
           "adds   r5, r5, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           /* (C,R4,R6) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "adds   r6, r6, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "umull  r7, r12, %[x_i], r8\n\t"
           "adds   r6, r6, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r6, r6, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           /**/
           "stmia  %[wij]!, { r5, r6 }\n\t"
           "cmp    %[xj], %[x_max1]\n\t"
           "bcc    2b\n\t"
           "bne    0f\n"
   "1:\n\t"
           /* (C,R4,R5) := (C,R4) + w_i_j + 2*x_i*x_j; */
           "ldr    r5, [%[wij]]\n\t"
           "ldr    r6, [%[xj]], #4\n\t"
           "adds   r5, r5, r4\n\t"
           "adc    r4, %[c], r9\n\t"
           "umull  r7, r12, %[x_i], r6\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], r9, r9\n\t"
           "adds   r5, r5, r7\n\t"
           "adcs   r4, r4, r12\n\t"
           "adc    %[c], %[c], r9\n\t"
           "str    r5, [%[wij]], #4\n"
   "0:\n\t"
           "ldr    r5, [%[wij]]\n\t"
           "adds   r4, r4, r5\n\t"
           "adc    %[c], %[c], #0\n\t"
           "str    r4, [%[wij]], #4"
           : [c] "=&r" (c), [wij] "=r" (wij), [xj] "=r" (xj)
           : [x_i] "r" (x_i), [x_max1] "r" (&A->word[BN256_WORDS-1]),
             "[wij]" (wij), "[xj]" (xj)
           : "r4", "r5", "r6", "r7", "r8", "r9", "r12", "memory", "cc");

      if (i < BN256_WORDS - 1)
	*wij = c;
    }
#else
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= (BN256_WORDS - 1)*2; k++)
    {
      if (k < BN256_WORDS)
	{
	  i_beg = 0;
	  i_end = k/2;
	}
      else
	{
	  i_beg = k - BN256_WORDS + 1;
	  i_end = k/2;
	}

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;

	  uv = ((uint64_t )A->word[i])*((uint64_t )A->word[j]);
	  if (i < j)
	    {
	      r2 += ((uv >> 63) != 0);
	      uv <<= 1;
	    }
	  v = uv;
	  u = (uv >> 32);
	  r0 += v;
	  carry = (r0 < v);
	  r1 += carry;
	  carry = (r1 < carry);
	  r1 += u;
	  carry += (r1 < u);
	  r2 += carry;
	}

      X->word[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  X->word[k] = r0;
#endif
}

uint32_t
bn256_shift (bn256 *X, const bn256 *A, int shift)
{
  int i;
  uint32_t carry = 0, next_carry;

  if (shift > 0)
    {
      for (i = 0; i < BN256_WORDS; i++)
	{
	  next_carry = A->word[i] >> (32 - shift);
	  X->word[i] = (A->word[i] << shift) | carry;
	  carry = next_carry;
	}
    }
  else
    {
      shift = -shift;

      for (i = BN256_WORDS - 1; i >= 0; i--)
	{
	  next_carry = A->word[i] & ((1 << shift) - 1);
	  X->word[i] = (A->word[i] >> shift) | (carry << (32 - shift));
	  carry = next_carry;
	}
    }

  return carry;
}

int
bn256_is_zero (const bn256 *X)
{
  int i;
  int r = 1;

  for (i = 0; i < BN256_WORDS; i++)
    r &=  (X->word[i] == 0);

  return r;
}

int
bn256_is_even (const bn256 *X)
{
  return !(X->word[0] & 1);
}

int
bn256_is_ge (const bn256 *A, const bn256 *B)
{
  uint32_t borrow;
  bn256 tmp[1];

  borrow = bn256_sub (tmp, A, B);
  return borrow == 0;
}


int
bn256_cmp (const bn256 *A, const bn256 *B)
{
  uint32_t borrow;
  int is_zero;
  bn256 tmp[1];

  borrow = bn256_sub (tmp, A, B);
  is_zero = bn256_is_zero (tmp);
  return is_zero ? 0 : (borrow ? -1 : 1);
}


#ifndef BN256_NO_RANDOM
void
bn256_random (bn256 *X)
{
  int i, j;
  const uint8_t *rand;

  for (i = 0; i < 256/256; i++)
    {
      rand = random_bytes_get (32);
      for (j = 0; j < BN256_WORDS; j++)
	X->word[i*BN256_WORDS+j] = ((uint32_t *)rand)[j];
      random_bytes_free (rand);
    }
}
#endif
