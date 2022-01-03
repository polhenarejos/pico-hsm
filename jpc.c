/*
 * jpc.c -- arithmetic on Jacobian projective coordinates.
 *
 * Copyright (C) 2011, 2013 Free Software Initiative of Japan
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

/**
 * @brief	X = 2 * A
 *
 * @param X	Destination JPC
 * @param A	JPC
 */
void
FUNC(jpc_double) (jpc *X, const jpc *A)
{
  bn256 a[1], b[1], c[1], tmp0[1];
  bn256 *d;

  if (bn256_is_zero (A->z))		/* A is infinite */
    return;

  d = X->x;
  MFNC(sqr) (a, A->y);
  memcpy (b, a, sizeof (bn256));
  MFNC(mul) (a, a, A->x);
  MFNC(shift) (a, a, 2);

  MFNC(sqr) (b, b);
  MFNC(shift) (b, b, 3);

#if defined(COEFFICIENT_A_IS_MINUS_3)
  MFNC(sqr) (tmp0, A->z);
  MFNC(sub) (c, A->x, tmp0);
  MFNC(add) (tmp0, tmp0, A->x);
  MFNC(mul) (tmp0, tmp0, c);
  MFNC(shift) (c, tmp0, 1);
  MFNC(add) (c, c, tmp0);
#elif defined (COEFFICIENT_A_IS_ZERO)
  MFNC(sqr) (tmp0, A->x);
  MFNC(shift) (c, tmp0, 1);
  MFNC(add) (c, c, tmp0);
#else
#error "not supported."
#endif

  MFNC(sqr) (d, c);
  MFNC(shift) (tmp0, a, 1);
  MFNC(sub) (d, d, tmp0);

  MFNC(mul) (X->z, A->y, A->z);
  MFNC(shift) (X->z, X->z, 1);

  MFNC(sub) (tmp0, a, d);
  MFNC(mul) (tmp0, c, tmp0);
  MFNC(sub) (X->y, tmp0, b);
}

/**
 * @brief	X = A + B
 *
 * @param X	Destination JPC
 * @param A	JPC
 * @param B	AC
 * @param MINUS if 1 subtraction, addition otherwise.
 */
void
FUNC(jpc_add_ac_signed) (jpc *X, const jpc *A, const ac *B, int minus)
{
  bn256 a[1], b[1], c[1], d[1], tmp[1];
#define minus_B_y c
#define c_sqr a
#define c_cube b
#define x1_c_sqr c
#define x1_c_sqr_2 c
#define c_cube_plus_x1_c_sqr_2 c
#define x1_c_sqr_copy a
#define y3_tmp c
#define y1_c_cube a

  if (bn256_is_zero (A->z))		/* A is infinite */
    {
      memcpy (X->x, B->x, sizeof (bn256));
      if (minus)
	{
	  memcpy (tmp, B->y, sizeof (bn256));
	  bn256_sub (X->y, CONST_P256, B->y);
	}
      else
	{
	  memcpy (X->y, B->y, sizeof (bn256));
	  bn256_sub (tmp, CONST_P256, B->y);
	}
      memset (X->z, 0, sizeof (bn256));
      X->z->word[0] = 1;
      return;
    }

  MFNC(sqr) (a, A->z);
  memcpy (b, a, sizeof (bn256));
  MFNC(mul) (a, a, B->x);

  MFNC(mul) (b, b, A->z);
  if (minus)
    {
      bn256_sub (minus_B_y, CONST_P256, B->y);
      MFNC(mul) (b, b, minus_B_y);
    }
  else
    {
      bn256_sub (tmp, CONST_P256, B->y);
      MFNC(mul) (b, b, B->y);
    }

  if (bn256_cmp (A->x, a) == 0 && bn256_cmp (A->y, b) == 0)
    {
      FUNC(jpc_double) (X, A);
      return;
    }

  MFNC(sub) (c, a, A->x);
  MFNC(sub) (d, b, A->y);

  MFNC(mul) (X->z, A->z, c);

  MFNC(sqr) (c_sqr, c);
  MFNC(mul) (c_cube, c_sqr, c);

  MFNC(mul) (x1_c_sqr, A->x, c_sqr);

  MFNC(sqr) (X->x, d);
  memcpy (x1_c_sqr_copy, x1_c_sqr, sizeof (bn256));
  MFNC(shift) (x1_c_sqr_2, x1_c_sqr, 1);
  MFNC(add) (c_cube_plus_x1_c_sqr_2, x1_c_sqr_2, c_cube);
  MFNC(sub) (X->x, X->x, c_cube_plus_x1_c_sqr_2);

  MFNC(sub) (y3_tmp, x1_c_sqr_copy, X->x);
  MFNC(mul) (y3_tmp, y3_tmp, d);
  MFNC(mul) (y1_c_cube, A->y, c_cube);
  MFNC(sub) (X->y, y3_tmp, y1_c_cube);
}

/**
 * @brief	X = A + B
 *
 * @param X	Destination JPC
 * @param A	JPC
 * @param B	AC
 */
void
FUNC(jpc_add_ac) (jpc *X, const jpc *A, const ac *B)
{
  FUNC(jpc_add_ac_signed) (X, A, B, 0);
}

/**
 * @brief	X = convert A
 *
 * @param X	Destination AC
 * @param A	JPC
 *
 * Return -1 on error (infinite).
 * Return 0 on success.
 */
int
FUNC(jpc_to_ac) (ac *X, const jpc *A)
{
  bn256 z_inv[1], z_inv_sqr[1];

  if (bn256_is_zero (A->z))
    return -1;

  mod_inv (z_inv, A->z, CONST_P256);

  MFNC(sqr) (z_inv_sqr, z_inv);
  MFNC(mul) (z_inv, z_inv, z_inv_sqr);

  MFNC(mul) (X->x, A->x, z_inv_sqr);
  MFNC(mul) (X->y, A->y, z_inv);
  return 0;
}
