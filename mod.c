/*
 * mod.c -- modulo arithmetic
 *
 * Copyright (C) 2011, 2014 Free Software Initiative of Japan
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

/**
 * @brief X = A mod B (using MU=(1<<(256)+MU_lower)) (Barret reduction)
 *
 */
void
mod_reduce (bn256 *X, const bn512 *A, const bn256 *B, const bn256 *MU_lower)
{
  bn256 q[1];
  bn512 q_big[1], tmp[1];
  uint32_t carry;
#define borrow carry

  memset (q, 0, sizeof (bn256));
  q->word[0] = A->word[15];
  bn256_mul (tmp, q, MU_lower);
  tmp->word[8] += A->word[15];
  carry = (tmp->word[8] < A->word[15]);
  tmp->word[9] += carry;

  q->word[7] = A->word[14];
  q->word[6] = A->word[13];
  q->word[5] = A->word[12];
  q->word[4] = A->word[11];
  q->word[3] = A->word[10];
  q->word[2] = A->word[9];
  q->word[1] = A->word[8];
  q->word[0] = A->word[7];
  bn256_mul (q_big, q, MU_lower);
  bn256_add ((bn256 *)&q_big->word[8], (bn256 *)&q_big->word[8], q);

  q->word[0] = q_big->word[9] + tmp->word[1];
  carry = (q->word[0] < tmp->word[1]);

  q->word[1] = q_big->word[10] + carry;
  carry = (q->word[1] < carry);
  q->word[1] += tmp->word[2];
  carry += (q->word[1] < tmp->word[2]);

  q->word[2] = q_big->word[11] + carry;
  carry = (q->word[2] < carry);
  q->word[2] += tmp->word[3];
  carry += (q->word[2] < tmp->word[3]);

  q->word[3] = q_big->word[12] + carry;
  carry = (q->word[3] < carry);
  q->word[3] += tmp->word[4];
  carry += (q->word[3] < tmp->word[4]);

  q->word[4] = q_big->word[13] + carry;
  carry = (q->word[4] < carry);
  q->word[4] += tmp->word[5];
  carry += (q->word[4] < tmp->word[5]);

  q->word[5] = q_big->word[14] + carry;
  carry = (q->word[5] < carry);
  q->word[5] += tmp->word[6];
  carry += (q->word[5] < tmp->word[6]);

  q->word[6] = q_big->word[15] + carry;
  carry = (q->word[6] < carry);
  q->word[6] += tmp->word[7];
  carry += (q->word[6] < tmp->word[7]);

  q->word[7] = carry;
  q->word[7] += tmp->word[8];
  carry = (q->word[7] < tmp->word[8]);

  memset (q_big, 0, sizeof (bn512));
  q_big->word[8] = A->word[8];
  q_big->word[7] = A->word[7];
  q_big->word[6] = A->word[6];
  q_big->word[5] = A->word[5];
  q_big->word[4] = A->word[4];
  q_big->word[3] = A->word[3];
  q_big->word[2] = A->word[2];
  q_big->word[1] = A->word[1];
  q_big->word[0] = A->word[0];

  bn256_mul (tmp, q, B);
  tmp->word[8] += carry * B->word[0];
  tmp->word[15] = tmp->word[14] = tmp->word[13] = tmp->word[12]
    = tmp->word[11] = tmp->word[10] = tmp->word[9] = 0;

  borrow = bn256_sub (X, (bn256 *)&q_big->word[0], (bn256 *)&tmp->word[0]);
  q_big->word[8] -= borrow;
  q_big->word[8] -= tmp->word[8];

  carry = q_big->word[8];
  if (carry)
    carry -= bn256_sub (X, X, B);
  else
    bn256_sub (q, X, B);

  if (carry)
    bn256_sub (X, X, B);
  else
    bn256_sub (q, X, B);

  borrow = bn256_sub (q, X, B);
  if (borrow)
    memcpy (q, X, sizeof (bn256));
  else
    memcpy (X, q, sizeof (bn256));
#undef borrow
}

/*
 * Reference:
 * Donald E. Knuth, The Art of Computer Programming, Vol. 2:
 * Seminumerical Algorithms, 3rd ed. Reading, MA: Addison-Wesley, 1998
 *
 * Max loop: X=0x8000...0000 and N=0xffff...ffff
 */
#define MAX_GCD_STEPS_BN256 (3*256-2)

/**
 * @brief C = X^(-1) mod N
 *
 * Assume X and N are co-prime (or N is prime).
 * NOTE: If X==0, it return 0.
 *
 */
void
mod_inv (bn256 *C, const bn256 *X, const bn256 *N)
{
  bn256 u[1], v[1], tmp[1];
  bn256 A[1] = { { { 1, 0, 0, 0, 0, 0, 0, 0 } } };
  uint32_t carry;
#define borrow carry
  int n = MAX_GCD_STEPS_BN256;

  memset (tmp, 0, sizeof (bn256));
  memset (C, 0, sizeof (bn256));
  memcpy (u, X, sizeof (bn256));
  memcpy (v, N, sizeof (bn256));

  while (n--)
    {
      int c = (bn256_is_even (u) << 1) + bn256_is_even (v);

      switch (c)
	{
	case 3:
	  bn256_shift (u, u, -1);
	  if (bn256_is_even (A))
	    {
	      bn256_add (tmp, A, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (A, A, N);

	  bn256_shift (A, A, -1);
	  A->word[7] |= carry * 0x80000000;

	  bn256_shift (v, v, -1);
	  if (bn256_is_even (C))
	    {
	      bn256_add (tmp, C, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (C, C, N);

	  bn256_shift (C, C, -1);
	  C->word[7] |= carry * 0x80000000;

	  if (bn256_is_ge (tmp, tmp))
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, A, N);
	    }
	  else
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, tmp, N);
	    }
	  break;

	case 1:
	  bn256_shift (tmp, tmp, -1);
	  if (bn256_is_even (tmp))
	    {
	      bn256_add (tmp, tmp, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (tmp, tmp, N);

	  bn256_shift (tmp, tmp, -1);
	  tmp->word[7] |= carry * 0x80000000;

	  bn256_shift (v, v, -1);
	  if (bn256_is_even (C))
	    {
	      bn256_add (tmp, C, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (C, C, N);

	  bn256_shift (C, C, -1);
	  C->word[7] |= carry * 0x80000000;

	  if (bn256_is_ge (tmp, tmp))
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, A, N);
	    }
	  else
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, tmp, N);
	    }
	  break;

	case 2:
	  bn256_shift (u, u, -1);
	  if (bn256_is_even (A))
	    {
	      bn256_add (tmp, A, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (A, A, N);

	  bn256_shift (A, A, -1);
	  A->word[7] |= carry * 0x80000000;

	  bn256_shift (tmp, tmp, -1);
	  if (bn256_is_even (tmp))
	    {
	      bn256_add (tmp, tmp, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (tmp, tmp, N);

	  bn256_shift (tmp, tmp, -1);
	  tmp->word[7] |= carry * 0x80000000;

	  if (bn256_is_ge (tmp, tmp))
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, A, N);
	    }
	  else
	    {
	      bn256_sub (tmp, tmp, tmp);
	      borrow = bn256_sub (tmp, tmp, tmp);
	      if (borrow)
		bn256_add (tmp, tmp, tmp);
	      else
		bn256_add (tmp, tmp, N);
	    }
	  break;

	case 0:
	  bn256_shift (tmp, tmp, -1);
	  if (bn256_is_even (tmp))
	    {
	      bn256_add (tmp, tmp, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (tmp, tmp, N);

	  bn256_shift (tmp, tmp, -1);
	  tmp->word[7] |= carry * 0x80000000;

	  bn256_shift (tmp, tmp, -1);
	  if (bn256_is_even (tmp))
	    {
	      bn256_add (tmp, tmp, N);
	      carry = 0;
	    }
	  else
	    carry = bn256_add (tmp, tmp, N);

	  bn256_shift (tmp, tmp, -1);
	  tmp->word[7] |= carry * 0x80000000;

	  if (bn256_is_ge (u, v))
	    {
	      bn256_sub (u, u, v);
	      borrow = bn256_sub (A, A, C);
	      if (borrow)
		bn256_add (A, A, N);
	      else
		bn256_add (tmp, A, N);
	    }
	  else
	    {
	      bn256_sub (v, v, u);
	      borrow = bn256_sub (C, C, A);
	      if (borrow)
		bn256_add (C, C, N);
	      else
		bn256_add (tmp, C, N);
	    }
	  break;
	}
    }
#undef borrow
}
