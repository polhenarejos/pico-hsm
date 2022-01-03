/*                                                    -*- coding: utf-8 -*-
 * ecc-ed448.c - Elliptic curve computation for
 *               the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
 *               d = -39081
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
 *     prediction.  Thus, we don't avoid indexing by secret value.
 *     We don't avoid conditional jump if both cases have same timing,
 *     either.
 *
 * (1) We use fixed base comb multiplication.  Scalar is 448-bit.
 *     We use two tables, and a table has 16 points.
 *     Window size W = 4-bit, E = 56.
 *
 */

#include <stdint.h>
#include <string.h>

#include "p448.h"
#include "shake256.h"


#define C_WORDS      7
#define BN448_WORDS 14
#define BN690_WORDS 22
#define BN896_WORDS 28
#define BN912_WORDS 29 /* 28.5 */

typedef struct bn448 {
  uint32_t word[ BN448_WORDS ]; /* Little endian */
} bn448;

typedef struct bn896 {
  uint32_t word[ BN896_WORDS ]; /* Little endian */
} bn896;

typedef struct bn912 {
  uint32_t word[ BN912_WORDS ]; /* Little endian */
} bn912;

static const bn448 M[1] = {{{
  0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272,
  0xaed63690, 0xc44edb49, 0x7cca23e9, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0x3fffffff
}}};

static const uint32_t C[C_WORDS] = {
  0x54a7bb0d, 0xdc873d6d, 0x723a70aa, 0xde933d8d,
  0x5129c96f, 0x3bb124b6, 0x8335dc16
};


static uint32_t
bn448_add (bn448 *X, const bn448 *A, const bn448 *B)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN448_WORDS; i++)
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

static uint32_t
bn448_sub (bn448 *X, const bn448 *A, const bn448 *B)
{
  int i;
  uint32_t v;
  uint32_t borrow = 0;
  uint32_t *px;
  const uint32_t *pa, *pb;

  px = X->word;
  pa = A->word;
  pb = B->word;

  for (i = 0; i < BN448_WORDS; i++)
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


static void
bnX_mul_C (uint32_t *r, const uint32_t *q, int q_size)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= q_size + C_WORDS - 2; k++)
    {
      if (q_size < C_WORDS)
	if (k < q_size)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - q_size + 1;
	    i_end = k;
	    if (i_end > C_WORDS - 1)
	      i_end = C_WORDS - 1;
	  }
      else
	if (k < C_WORDS)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - C_WORDS + 1;
	    i_end = k;
	    if (i_end > q_size - 1)
	      i_end = q_size - 1;
	  }

      for (i = i_beg; i <= i_end; i++)
	{
	  uint64_t uv;
	  uint32_t u, v;
	  uint32_t carry;

	  j = k - i;
	  if (q_size < C_WORDS)
	    uv = ((uint64_t)q[j])*((uint64_t)C[i]);
	  else
	    uv = ((uint64_t)q[i])*((uint64_t)C[j]);
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

      r[k] = r0;
      r0 = r1;
      r1 = r2;
      r2 = 0;
    }

  r[k] = r0;
}

/* X <= X + A when COND!=0 */
/* X <= X when COND==0 */
static void
bn448_add_cond (bn448 *X, const bn448 *A, int cond)
{
  int i;
  uint32_t v;
  uint32_t carry = 0;
  uint32_t *px;
  const uint32_t *pa;
  uint32_t mask = -(!!cond);

  px = X->word;
  pa = A->word;

  for (i = 0; i < BN448_WORDS; i++)
    {
      v = *px;
      *px = (*pa & mask) + carry;
      carry = (*px < carry);
      *px += v;
      carry += (*px < v);
      px++;
      pa++;
    }
}


/* X <= X + A mod M */
static void
bn448_addm (bn448 *X, const bn448 *A)
{
  uint32_t borrow;

  bn448_add (X, X, A);
  borrow = bn448_sub (X, X, M);
  bn448_add_cond (X, M, borrow);
}

/**
 * @brief R = A mod M (using M=2^446-C) (Barret reduction)
 *
 * See HAC 14.47.
 */
void
mod_reduce_M (bn448 *R, const bn912 *A)
{
  uint32_t q[BN448_WORDS+1];
  uint32_t tmp[BN690_WORDS];
  bn448 r[1];
  uint32_t carry, next_carry;
  int i;

  /* Q = A / 2^446 *//* 466-bit */
  /* Upper half of A->word[28] must be zero.  */
  q[14] = (A->word[28] << 2) | (A->word[27] >> 30);
  carry = A->word[27] & 0x3fffffff;
  for (i = BN448_WORDS - 1; i >= 0; i--)
    {
      next_carry = A->word[i+13] & 0x3fffffff;
      q[i] = (A->word[i+13] >> 30) | (carry << 2);
      carry = next_carry;
    }
  memcpy (R, A, sizeof (bn448));
  R->word[13] &= 0x3fffffff;

  /* Q_size: 15 *//* 466-bit */
  bnX_mul_C (tmp, q, 15); /* TMP = Q*C *//* 690-bit */
  /* Q = tmp / 2^446 *//* 244-bit */
  carry = tmp[21];
  for (i = 7; i >= 0; i--)
    {
      next_carry = tmp[i+13] & 0x3fffffff;
      q[i] = (tmp[i+13] >> 30) | (carry << 2);
      carry = next_carry;
    }
  /* R' = tmp % 2^446 */
  memcpy (r, tmp, sizeof (bn448));
  r->word[13] &= 0x3fffffff;
  /* R += R' */
  bn448_addm (R, r);

  /* Q_size: 8 *//* 244-bit */
  bnX_mul_C (tmp, q, 8); /* TMP = Q*C *//* 468-bit */
  /* Q = tmp / 2^446 *//* 22-bit */
  carry = tmp[14];
  q[0] = (tmp[13] >> 30) | (carry << 2);
  /* R' = tmp % 2^446 */
  memcpy (r, tmp, sizeof (bn448));
  r->word[13] &= 0x3fffffff;
  /* R += R' */
  bn448_addm (R, r);

  /* Q_size: 1 */
  bnX_mul_C (tmp, q, 1); /* TMP = Q*C *//* 246-bit */
  /* R' = tmp % 2^446 */
  memset (((uint8_t *)r)+(sizeof (uint32_t)*8), 0, sizeof (uint32_t)*6);
  memcpy (r, tmp, sizeof (uint32_t)*8);
  /* R += R' */
  bn448_addm (R, r);
}


static void
bn448_mul (bn896 *X, const bn448 *A, const bn448 *B)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= (BN448_WORDS - 1)*2; k++)
    {
      if (k < BN448_WORDS)
	{
	  i_beg = 0;
	  i_end = k;
	}
      else
	{
	  i_beg = k - BN448_WORDS + 1;
	  i_end = BN448_WORDS - 1;
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
}

static const p448_t nGx0[16] = {
  { { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x070cc05e, 0x026a82bc, 0x00938e26, 0x080e18b0, 
      0x0511433b, 0x0f72ab66, 0x0412ae1a, 0x0a3d3a46, 
      0x0a6de324, 0x00f1767e, 0x04657047, 0x036da9e1, 
      0x05a622bf, 0x0ed221d1, 0x066bed0d, 0x04f1970c } },
  { { 0x0464238e, 0x00079817, 0x00d381ca, 0x02110302, 
      0x0d9f01b5, 0x01cc4c6e, 0x05a131b1, 0x05e35dc5, 
      0x006944eb, 0x0b61848d, 0x029631a3, 0x083792a0, 
      0x0afca0dd, 0x0be1017f, 0x0782fcbb, 0x070aaa01 } },
  { { 0x0e7661f9, 0x0b2f9f62, 0x009fae89, 0x03b99803, 
      0x066014d2, 0x067900ef, 0x06556c10, 0x0c8eacf3, 
      0x0ad4a82e, 0x020a44d0, 0x00572f1c, 0x0e7819e7, 
      0x0fd08cdf, 0x0c0ed140, 0x09aee1da, 0x0a16934a } },
  { { 0x091780c7, 0x0a7ea989, 0x0d2476b6, 0x004e4ecc, 
      0x0c494b68, 0x00af9f58, 0x0dee64fd, 0x0e0f269f, 
      0x0021bd26, 0x085a61f6, 0x0b5d284b, 0x0c265c35, 
      0x03775afd, 0x058755ea, 0x02ecf2c6, 0x0617f174 } },
  { { 0x067f4947, 0x0dbf4eb6, 0x0b8716d9, 0x02206a2a, 
      0x0e7cad5a, 0x04a148b0, 0x0e483133, 0x0fbf12cd, 
      0x0c6458f7, 0x0e022d5a, 0x01b7e39d, 0x0a60afe6, 
      0x05a5208c, 0x0c62f458, 0x03311553, 0x0a08a4c3 } },
  { { 0x0054a90d, 0x0ad5dc54, 0x00ac9fd6, 0x097f2af4, 
      0x0f4ddbc7, 0x01b0f7b3, 0x0324ce0b, 0x01d5d092, 
      0x0cd2798f, 0x08cb96e2, 0x0957bc39, 0x0bd045b5, 
      0x0f76fbfb, 0x046308a9, 0x0ef679ce, 0x0c86d628 } },
  { { 0x0d5d9262, 0x0f251539, 0x0711a956, 0x0240708f, 
      0x04a0b0bc, 0x07f7e4dd, 0x055b70a8, 0x065dd24f, 
      0x07ef8979, 0x0e83cec7, 0x09589db8, 0x0f1db2d1, 
      0x09d93037, 0x0fcc7e8a, 0x04e0b8f4, 0x0cb99f0b } },
  { { 0x04acea57, 0x06f24100, 0x0da68597, 0x0dace1c6, 
      0x050ce77f, 0x0ea7dd41, 0x01585884, 0x01aecb84, 
      0x0ea4a85c, 0x092ff208, 0x088eebd2, 0x0de9433c, 
      0x03f4d289, 0x053cd318, 0x026539af, 0x03970858 } },
  { { 0x0d229665, 0x06e9fd2b, 0x0878dd51, 0x049345aa, 
      0x0f45bacf, 0x0ccde72a, 0x0be16b6f, 0x0bc249d1, 
      0x0448a61d, 0x0a25bae9, 0x0d773878, 0x0c93b6ea, 
      0x02cda508, 0x055f708a, 0x08cf49e6, 0x0fa56852 } },
  { { 0x093bfef9, 0x07bec8db, 0x0fafda3d, 0x0ce4dcdc, 
      0x06f62ed7, 0x0a75c872, 0x07b3dadd, 0x0c39ac92, 
      0x0f926d90, 0x0ae1b8d1, 0x048da0a9, 0x0d7dbeca, 
      0x02a52b3b, 0x0ec13f74, 0x0d4c5ce2, 0x02071cee } },
  { { 0x05a644a6, 0x0e56b0a9, 0x0be6360b, 0x01ecf90e, 
      0x023b73a8, 0x0c3bbcf7, 0x0292054b, 0x05417d25, 
      0x07b91b46, 0x0ca1ea05, 0x07ea6c44, 0x01560b21, 
      0x04f12989, 0x0463cd2a, 0x03d7e086, 0x0092781c } },
  { { 0x0d59796d, 0x0ce08d7e, 0x055bc822, 0x0e464443, 
      0x0d243cc4, 0x0542002f, 0x098259b3, 0x044fc576, 
      0x012781de, 0x08650550, 0x0055e6b4, 0x0137f762, 
      0x0fbf007e, 0x0a391ccc, 0x039fe6f6, 0x0a9c9ad3 } },
  { { 0x01ca2765, 0x0ccddbb0, 0x0563b46c, 0x05d18f4c, 
      0x0462647e, 0x02ff700d, 0x0822dc83, 0x0670b143, 
      0x00013963, 0x01627d78, 0x055dbfb9, 0x0435f413, 
      0x063d41e8, 0x066c95cd, 0x0c797bba, 0x08e27dfb } },
  { { 0x03da4531, 0x01ff4dd6, 0x0cd39a3c, 0x02d0de4c, 
      0x0bc9da8d, 0x0003561e, 0x033e1e9a, 0x001eea00, 
      0x078bf710, 0x05458c53, 0x0f56338e, 0x069043ab, 
      0x061ffba0, 0x0637cf41, 0x039fb551, 0x0fc09757 } },
  { { 0x0256141f, 0x0f1e0e38, 0x00ab2673, 0x0efd5f47, 
      0x0af4a4af, 0x0b749116, 0x0ac6540b, 0x04242f82, 
      0x0abaf195, 0x0b26730c, 0x0d06842d, 0x076fbe60, 
      0x0580cad8, 0x02613d91, 0x0b568ae0, 0x0c2e5b1d } }
};

static const p448_t nGy0[16] = {
  { { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x0230fa14, 0x008795bf, 0x07c8ad98, 0x0132c4ed, 
      0x09c4fdbd, 0x01ce67c3, 0x073ad3ff, 0x005a0c2d, 
      0x07789c1e, 0x0a398408, 0x0a73736c, 0x0c7624be, 
      0x003756c9, 0x02488762, 0x016eb6bc, 0x0693f467 } },
  { { 0x099945e7, 0x0c63b7a0, 0x0c4486c1, 0x0e9164ec, 
      0x0885f2c1, 0x0b133e35, 0x0c99ae02, 0x0186f0d3, 
      0x02bf53e6, 0x02fca492, 0x048a02bc, 0x0f922aa2, 
      0x00dd3dca, 0x04fe6490, 0x0f6a8207, 0x0e8c313f } },
  { { 0x0579a4e2, 0x0a1ffe8b, 0x0ce472b4, 0x01d006b3, 
      0x089def96, 0x07c8f689, 0x0a32ae93, 0x079d7bd1, 
      0x03a02760, 0x0ebb4776, 0x05b4c55e, 0x019b3c6c, 
      0x07da436f, 0x066ff782, 0x0659536d, 0x0ee40076 } },
  { { 0x05ec556a, 0x050109e2, 0x0fd57e39, 0x0235366b, 
      0x044b6b2e, 0x07b3c976, 0x0b2b7b9c, 0x0f7f9e82, 
      0x00ec6409, 0x0b6196ab, 0x00a20d9e, 0x088f1d16, 
      0x0586f761, 0x0e3be3b4, 0x0e26395d, 0x09983c26 } },
  { { 0x0fab8e56, 0x0ded288e, 0x057277e6, 0x0a4e6f4e, 
      0x0e949681, 0x0a2a4c4f, 0x0721fdb3, 0x0508a46c, 
      0x0fb44de2, 0x0f98049e, 0x02fb0f31, 0x071f3724, 
      0x09067763, 0x0d3fbbb3, 0x0a83faaa, 0x0696ec4a } },
  { { 0x07a04bb0, 0x0f52ae70, 0x0ae14cdb, 0x0784d14b, 
      0x034acc37, 0x09aa3869, 0x09703f7b, 0x08f79c87, 
      0x0264026c, 0x0859cde5, 0x0486b035, 0x0b2a45f7, 
      0x03d5144b, 0x0809740f, 0x0416dc87, 0x0dcf324d } },
  { { 0x0a0c8bc7, 0x04125cec, 0x0eac3f20, 0x0d30ff7e, 
      0x029ad678, 0x06901f05, 0x04805ff1, 0x033c307d, 
      0x049d6a79, 0x080f0710, 0x02dece6c, 0x0d1ba22b, 
      0x0778cccb, 0x01692a0b, 0x02df78fb, 0x0f8c02d3 } },
  { { 0x0b827d87, 0x04b57599, 0x03d77638, 0x0dc82ac0, 
      0x052f6e61, 0x06943366, 0x0ad5e8a6, 0x0b8fc4b0, 
      0x0f388642, 0x01b6f7dc, 0x0a74dd57, 0x06f24533, 
      0x041750cf, 0x0c669378, 0x028a37af, 0x006757eb } },
  { { 0x080128d5, 0x0ef186a8, 0x04a54843, 0x01ceb43b, 
      0x045be148, 0x0c112a42, 0x01ac9412, 0x0621b93a, 
      0x05e16552, 0x0a2ca24f, 0x086301c0, 0x0cf3fecf, 
      0x05c2e2e0, 0x05108805, 0x09e9d8ab, 0x0d2ba341 } },
  { { 0x02138911, 0x0f0d3e4c, 0x0c1a371b, 0x062382ce, 
      0x05b3a392, 0x09d954e7, 0x0517d2a1, 0x0047d71a, 
      0x07f70073, 0x09cd1733, 0x0efc3aea, 0x0549d0d1, 
      0x0df78457, 0x0666e074, 0x0a48e084, 0x0f67e924 } },
  { { 0x0b3114fe, 0x073bec50, 0x0e8b6172, 0x01c5e7b6, 
      0x0e896bcc, 0x0a1c3ae1, 0x0bcd8cab, 0x0bb3f870, 
      0x07e9fa9d, 0x0eea8546, 0x0042e2cf, 0x056431f0, 
      0x0469e8d2, 0x08eb9b9c, 0x0a9adf2c, 0x06856458 } },
  { { 0x07b2cfdd, 0x01855530, 0x073bd43a, 0x01816246, 
      0x08897062, 0x02f82d12, 0x03563816, 0x06517857, 
      0x0394a8c7, 0x0529bf2e, 0x075a3141, 0x0660c4f2, 
      0x018e5a16, 0x0787c8ad, 0x045b679e, 0x0abaec01 } },
  { { 0x06d87d9e, 0x07c9fabb, 0x03b2a99d, 0x0673b28a, 
      0x068816ee, 0x0efb205e, 0x0dd5e3d5, 0x03d21920, 
      0x07544f4d, 0x085f40c2, 0x06fb538d, 0x057d045b, 
      0x05470e4e, 0x028a93c3, 0x063adfd4, 0x0d1cf7a5 } },
  { { 0x06699694, 0x0c83c837, 0x0386dade, 0x0621103f, 
      0x0f247dc3, 0x06058f43, 0x0aec07c3, 0x0b1ac29a, 
      0x0bde5d50, 0x06e35e33, 0x078fd31c, 0x0516263c, 
      0x00a9d127, 0x04a13379, 0x078bec6e, 0x0f39316a } },
  { { 0x0e26ea19, 0x05ecf40e, 0x03bdf1b5, 0x07c284a0, 
      0x06f461fa, 0x08393462, 0x064a69aa, 0x07d4f6a5, 
      0x06e88ea4, 0x023059e9, 0x0f92bd0b, 0x0c4a8035, 
      0x0c5c44a2, 0x0fccec22, 0x07f57ea1, 0x0598207c } }
};

static const p448_t nGx1[16] = {
  { { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x0528af6f, 0x078c6f13, 0x094b74d9, 0x00001fe2, 
      0x001aab44, 0x0ae77425, 0x0ef0039c, 0x07cbe937, 
      0x00fa2a67, 0x0af3e4f0, 0x0da1378e, 0x0e28175f, 
      0x08ccd90e, 0x072adeed, 0x000af22f, 0x016a8ce1 } },
  { { 0x0fa0459e, 0x0f31f53f, 0x0315cd6b, 0x0f8742a1, 
      0x0ae64e97, 0x0abe2f50, 0x09b9da48, 0x0bd78741, 
      0x051e526e, 0x04521a33, 0x0e10ba45, 0x0fa05935, 
      0x0e8f903c, 0x05c947e1, 0x05a754ee, 0x00aa47d1 } },
  { { 0x00d9a33b, 0x0284f76f, 0x0e4d41e7, 0x09461141, 
      0x0cc79344, 0x015371b9, 0x03dd8bdd, 0x0173f667, 
      0x053f866b, 0x0c0d0f83, 0x030b45ea, 0x08b7d59b, 
      0x0044dc82, 0x02b4cdec, 0x094fa772, 0x0e245b21 } },
  { { 0x04ddc8a8, 0x02fe182d, 0x0ac056bf, 0x088d6e79, 
      0x00e41e4e, 0x0c3ff2d1, 0x02c3679f, 0x032ec7f9, 
      0x04e61051, 0x03561f09, 0x06c6250a, 0x04553f5a, 
      0x0dd25c5b, 0x02b765ef, 0x06a1cd7f, 0x0e3a40a2 } },
  { { 0x05e1f4b2, 0x0e9485c4, 0x070a1e6b, 0x01d85e53, 
      0x077730a7, 0x0db61fa9, 0x050d418e, 0x0201a6bd, 
      0x02774433, 0x0e78a475, 0x0622ea3a, 0x016424e5, 
      0x0d5b9631, 0x01c7734d, 0x0f5064f2, 0x0c7586d3 } },
  { { 0x0af6151d, 0x0c3ed603, 0x0aa19b93, 0x05a5e4a6, 
      0x0536ff03, 0x07e465ce, 0x0b0be710, 0x0bbb36bf, 
      0x09249bff, 0x0d15454d, 0x03736654, 0x0ba934d9, 
      0x0370dc86, 0x0675c04e, 0x0d86eb3b, 0x06cd21cb } },
  { { 0x030c7ce7, 0x04217221, 0x0e9dba4d, 0x0ec314cd, 
      0x05439062, 0x0d7196cd, 0x0dd96166, 0x0b8295cd, 
      0x0c15796f, 0x0c767da7, 0x00ab2036, 0x059120e7, 
      0x0b7d07ec, 0x0e1562a9, 0x0231cdd9, 0x07d5c89f } },
  { { 0x01a82a12, 0x091a5884, 0x080f3a62, 0x0a754175, 
      0x0f73417a, 0x0399009f, 0x00a8c5cd, 0x02db1fb9, 
      0x0c046d51, 0x082c8912, 0x08f18274, 0x00a3f577, 
      0x026ccae2, 0x02ad0ede, 0x08a4e9c2, 0x07d6bd8b } },
  { { 0x0afd28b4, 0x02b7b7be, 0x0298d67e, 0x0e834401, 
      0x04b11493, 0x0e070d60, 0x063ce6fb, 0x04b67725, 
      0x0a0cfb04, 0x0d3a0f67, 0x0f08f1b2, 0x0debe82e, 
      0x0b402b9e, 0x07114482, 0x0b307043, 0x0af532e6 } },
  { { 0x049ab457, 0x0f6483c2, 0x0818ac81, 0x05aced0a, 
      0x0a900e3a, 0x080916bc, 0x02948675, 0x0145adb9, 
      0x0d8b7821, 0x04fe2b0e, 0x0b1a62cc, 0x0a9e1bce, 
      0x096c2408, 0x048f1f80, 0x0ac552fe, 0x0d17e7a0 } },
  { { 0x08ce3344, 0x0ea48915, 0x0434ae70, 0x0c6cf019, 
      0x0c48f5d2, 0x089d3c0f, 0x0ca7aa7e, 0x0c550a00, 
      0x017fb3ab, 0x09f8b49f, 0x024844a0, 0x0366a6d5, 
      0x0ceb4a83, 0x0f1f5bf4, 0x03b782f0, 0x099fd2f7 } },
  { { 0x052daf76, 0x038fbbd7, 0x0bced01d, 0x0ffb0a8b, 
      0x07c6bd6c, 0x0dc3b0ff, 0x041d595c, 0x03814ee7, 
      0x01941d44, 0x0e1f8343, 0x0f89b18d, 0x0c083601, 
      0x0e52ec62, 0x0fc338ff, 0x0e971788, 0x04601008 } },
  { { 0x0add862e, 0x0e8c3a8e, 0x033cea23, 0x06d00cf1, 
      0x0cdc039a, 0x0d7bda40, 0x0e0a2ac3, 0x04750dcb, 
      0x0bec4388, 0x0a1bb0bc, 0x0d20c0f9, 0x077a4a7b, 
      0x0b9e1f0b, 0x02ff072d, 0x07bd3e06, 0x0bd796d7 } },
  { { 0x08e321b4, 0x08757de1, 0x0151699c, 0x06ba6bd4, 
      0x0a156df0, 0x02ec93a1, 0x0dad4f9e, 0x04e547c5, 
      0x0ee9310d, 0x01dcc8bf, 0x0f7b5016, 0x0355f710, 
      0x0ce8f36d, 0x0389d7a9, 0x02b8056d, 0x0ff83804 } },
  { { 0x060f6dcf, 0x0dcaa234, 0x0285b23d, 0x0ec8d56f, 
      0x083dac2b, 0x01042255, 0x08e1bed7, 0x0c3fe788, 
      0x0832c0af, 0x07258b0e, 0x02b2affc, 0x0a901bdb, 
      0x0038f36e, 0x01a28d5f, 0x0dbb618d, 0x080838af } }
};

static const p448_t nGy1[16] = {
  { { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 
      0x00000000, 0x00000000, 0x00000000, 0x00000000 } },
  { { 0x0cbf63dd, 0x069fae17, 0x09e39e26, 0x06786172, 
      0x0f827a18, 0x0e92b3d5, 0x08403682, 0x04d75e41, 
      0x09056a79, 0x001a4fd9, 0x020008f5, 0x089efb2d, 
      0x0b78ff15, 0x0a2f6918, 0x0a3437f5, 0x0f41c870 } },
  { { 0x0d814825, 0x0b2849ef, 0x05c9968d, 0x09c2a5d2, 
      0x004e634c, 0x024dbb26, 0x0db38194, 0x033f3a4c, 
      0x0c8a2b6b, 0x0e04f609, 0x0abbbfdb, 0x0caefd8e, 
      0x0404498b, 0x0683119a, 0x08b21cbd, 0x024ab7a9 } },
  { { 0x0ede77b3, 0x0043b728, 0x0a043f1d, 0x003cf736, 
      0x0ab4e700, 0x0d95a612, 0x0c8fe17c, 0x05ccaac2, 
      0x0177bd28, 0x0dc3bd14, 0x05360c86, 0x0b3d5c96, 
      0x04ec7e48, 0x01880c26, 0x04bb47c6, 0x0fd5dba8 } },
  { { 0x05d821dd, 0x0b27309b, 0x0c2c17ca, 0x0950fb8d, 
      0x08fb0d4c, 0x0feed015, 0x0f550179, 0x0762c479, 
      0x0e095840, 0x0306cf44, 0x0d379e66, 0x084b413a, 
      0x0bb2e4f1, 0x0d6e5d5a, 0x094b085d, 0x08bc12b7 } },
  { { 0x0b8a16f6, 0x0b4dacd9, 0x003afc96, 0x0000b9b9, 
      0x03f19cbf, 0x0ab930b8, 0x0b077171, 0x0541f92e, 
      0x019baa42, 0x08758d9c, 0x0fea31a2, 0x0299b935, 
      0x081d9e24, 0x03bc7232, 0x09d91676, 0x0fc081c2 } },
  { { 0x02f05282, 0x04ca6fb6, 0x02e9801e, 0x051928b6, 
      0x0b609dcb, 0x0c6f37b6, 0x06e32803, 0x06617fd7, 
      0x0166f0bb, 0x07d1bffb, 0x0ac137d4, 0x0bfdebdd, 
      0x0df8f3cb, 0x0d558ac9, 0x08fabbb4, 0x00217c7c } },
  { { 0x0f5d72ad, 0x04c71050, 0x008880dd, 0x093209a0, 
      0x07c3fef0, 0x0e1857c5, 0x022b21d2, 0x07584709, 
      0x0e52fe8a, 0x039aeffa, 0x0a384e66, 0x0bd7c58b, 
      0x0bfbbfe2, 0x022fc035, 0x0506e447, 0x0bc96411 } },
  { { 0x04b3de44, 0x0aa0d797, 0x096ac9bb, 0x0f8658b9, 
      0x05f6c334, 0x031e7be2, 0x04df12c9, 0x023836ce, 
      0x059eb5c9, 0x0029027b, 0x05b8649d, 0x02f22531, 
      0x0d907162, 0x0a0fdf03, 0x09e80226, 0x0101d9df } },
  { { 0x05237b19, 0x00d0c997, 0x04a2bcdb, 0x0692bae3, 
      0x0805b9e0, 0x0a0d3a98, 0x08c7dd07, 0x0a253f11, 
      0x0e19738e, 0x0c0794d0, 0x019812a1, 0x041a8569, 
      0x025d360c, 0x078e4ebd, 0x07ee8567, 0x0f02e9d6 } },
  { { 0x00548584, 0x0bb1ee61, 0x0549030f, 0x0026e17a, 
      0x0b4c52fb, 0x0a4e4e61, 0x0a1ca8f9, 0x0339754c, 
      0x0ee8806f, 0x03d2a45e, 0x0e2028fa, 0x03c44782, 
      0x0072e42b, 0x03328ae4, 0x0d21c91f, 0x07e98738 } },
  { { 0x0b9618ad, 0x07f781fa, 0x09cf7662, 0x0855bfab, 
      0x0c316a14, 0x0d98f9ff, 0x07b3046a, 0x0109f273, 
      0x042cecfe, 0x0cc21cdc, 0x05be5a36, 0x05236b10, 
      0x058a0700, 0x0ff2cf95, 0x005ad57d, 0x09cbf152 } },
  { { 0x0ebe90d2, 0x049f0de4, 0x02243779, 0x0221424d, 
      0x09051808, 0x0b52f44b, 0x0bb9c3fb, 0x0a5d64e3, 
      0x07690354, 0x0d8bf65d, 0x0bc06e3f, 0x05d039f6, 
      0x033a3443, 0x04e11c79, 0x04147a83, 0x06a7e42c } },
  { { 0x082e4773, 0x00d276be, 0x0e1b9057, 0x0e9dd324, 
      0x0369bc97, 0x0b3181ef, 0x002f04fa, 0x01d08726, 
      0x07c2c5d3, 0x0bf49cbf, 0x09ecb59b, 0x098eae7e, 
      0x02e09293, 0x052e08b6, 0x0c40f3e6, 0x04096c37 } },
  { { 0x06074e1f, 0x07bc94ed, 0x0790175a, 0x040b2a81, 
      0x0e307782, 0x0b7958e8, 0x089ff273, 0x07ed27c6, 
      0x026db869, 0x0b6a32f8, 0x03d2e15c, 0x00446ef9, 
      0x0777e1ac, 0x0492d2de, 0x01b69b63, 0x06b8dbab } },
  { { 0x07e98bea, 0x0e7c9e7a, 0x02e17335, 0x09302c64, 
      0x0acc1e93, 0x05dcdcd8, 0x04d90baa, 0x05982bae, 
      0x0c686ed6, 0x07c08c6c, 0x0fce2c72, 0x04dd3cce, 
      0x01dc8f12, 0x029ca465, 0x0161cbd7, 0x09324c0a } }
};

static void
compute_kG_448 (uint8_t *out, const uint32_t k[16])
{
  int i;
  p448_t x0[1], y0[1], z0[1]; /* P0 */
  p448_t tmp0[1], tmp1[1];

  /* P0 <= O */
  memset (x0, 0, sizeof (p448_t));
  memset (y0, 0, sizeof (p448_t));
  memset (z0, 0, sizeof (p448_t));
  y0->limb[0] = 1;
  z0->limb[0] = 1;

  for (i = 0; i < 56; i++)
    {
      p448_t b[1], c[1], d[1];
      p448_t e[1], f[1], g[1], h[1];
      int index0, index1;

      if (i < 28)
	{
	  int i0 = 28 - i - 1;

	  index0 = ((k[1] >> i0) & 1) | (((k[5] >> i0) & 1)<<1)
	    | (((k[ 9] >> i0) & 1)<<2) | (((k[13] >> i0) & 1)<<3);
	  index1 = ((k[3] >> i0) & 1) | (((k[7] >> i0) & 1)<<1)
	    | (((k[11] >> i0) & 1)<<2) | (((k[15] >> i0) & 1)<<3);
	}
      else
	{
	  int i0 = 56 - i - 1;

	  index0 = ((k[0] >> i0) & 1) | (((k[4] >> i0) & 1)<<1)
	    | (((k[ 8] >> i0) & 1)<<2) | (((k[12] >> i0) & 1)<<3);
	  index1 = ((k[2] >> i0) & 1) | (((k[6] >> i0) & 1)<<1)
	    | (((k[10] >> i0) & 1)<<2) | (((k[14] >> i0) & 1)<<3);
	}

      /* Point double P0' <= P0 + P0 */
      p448_add (tmp0, x0, y0);
      p448_sqr (b, tmp0);
      p448_sqr (c, x0);
      p448_sqr (d, y0);
      p448_add (e, c, d);
      p448_sqr (h, z0);
      p448_add (tmp0, h, h);
      p448_sub (tmp1, e, tmp0);
      p448_sub (tmp0, b, e);
      p448_mul (x0, tmp0, tmp1);
      p448_sub (tmp0, c, d);
      p448_mul (y0, e, tmp0);
      p448_mul (z0, e, tmp1);
      /*
	B = (X1+Y1)^2
	C = X1^2
	D = Y1^2
	E = C+D
	H = Z1^2
	J = E-2*H
	X3 = (B-E)*J
	Y3 = E*(C-D)
	Z3 = E*J
      */

      /* Point addition P0' <= P0 + [v0(index0)]G */
      p448_sqr (b, z0);
      p448_mul (c, x0, &nGx0[index0]);
      p448_mul (d, y0, &nGy0[index0]);
      p448_mul (tmp0, c, d);
      p448_mul_39081 (e, tmp0);
      p448_add (f, b, e);
      p448_sub (g, b, e);
      p448_add (tmp0, x0, y0);
      p448_add (tmp1, &nGx0[index0], &nGy0[index0]);
      p448_mul (h, tmp0, tmp1);
      p448_sub (tmp0, h, c);
      p448_sub (tmp1, tmp0, d);
      p448_mul (tmp0, f, tmp1);
      p448_mul (x0, z0, tmp0);
      p448_sub (tmp0, d, c);
      p448_mul (tmp1, g, tmp0);
      p448_mul (y0, z0, tmp1);
      p448_mul (z0, f, g);
      /*
	A = Z1*Z2
	B = A^2
	C = X1*X2
	D = Y1*Y2
	E = d*C*D
	F = B-E
	G = B+E
	H = (X1+Y1)*(X2+Y2)
	X3 = A*F*(H-C-D)
	Y3 = A*G*(D-C)
	Z3 = F*G
      */
      /* Point addition P0' <= P0 + [v1(index1)]G */
      p448_sqr (b, z0);
      p448_mul (c, x0, &nGx1[index1]);
      p448_mul (d, y0, &nGy1[index1]);
      p448_mul (tmp0, c, d);
      p448_mul_39081 (e, tmp0);
      p448_add (f, b, e);
      p448_sub (g, b, e);
      p448_add (tmp0, x0, y0);
      p448_add (tmp1, &nGx1[index1], &nGy1[index1]);
      p448_mul (h, tmp0, tmp1);
      p448_sub (tmp0, h, c);
      p448_sub (tmp1, tmp0, d);
      p448_mul (tmp0, f, tmp1);
      p448_mul (x0, z0, tmp0);
      p448_sub (tmp0, d, c);
      p448_mul (tmp1, g, tmp0);
      p448_mul (y0, z0, tmp1);
      p448_mul (z0, f, g);
    }

  /* Convert to affine coordinate.  */
  p448_inv (tmp0, z0);
  p448_mul (tmp1, x0, tmp0);
  p448_serialize (out, tmp1);
  /* EdDSA encoding.  */
  out[56] = (out[0] & 1) << 7;
  p448_mul (tmp1, y0, tmp0);
  p448_serialize (out, tmp1);
}


#define SEED_SIZE 57

#define DOM448       (const uint8_t *)"SigEd448"
#define DOM448_LEN   8

int
ed448_sign (uint8_t *out, const uint8_t *input, unsigned int ilen,
	    const uint8_t *a_in, const uint8_t *seed, const uint8_t *pk)
{
  bn448 a[1], k[1], s[1];
  shake_context ctx;
  const unsigned char x_olen[2] = { 0, 0 };
  uint32_t hash[BN912_WORDS];
  uint8_t r[57];
  uint32_t carry, borrow;
  p448_t k_redundant[1];

  memset (hash, 0, sizeof (hash));

  memcpy (a, a_in, sizeof (bn448));
  a->word[13] |= 0x80000000;
  a->word[0] &= ~3;

  shake256_start (&ctx);
  shake256_update (&ctx, DOM448, DOM448_LEN);
  shake256_update (&ctx, x_olen, 2);
  shake256_update (&ctx, seed, 57);
  shake256_update (&ctx, input, ilen);
  shake256_finish (&ctx, (uint8_t *)hash, 2*57);

  mod_reduce_M (k, (const bn912 *)hash);
  p448_deserialize (k_redundant, (uint8_t *)k);
  compute_kG_448 (r, (uint32_t *)k_redundant);

  shake256_start (&ctx);
  shake256_update (&ctx, DOM448, DOM448_LEN);
  shake256_update (&ctx, x_olen, 2);
  shake256_update (&ctx, r, 57);
  shake256_update (&ctx, pk, 57);
  shake256_update (&ctx, input, ilen);
  shake256_finish (&ctx, (uint8_t *)hash, 2*57);

  mod_reduce_M (s, (const bn912 *)hash);

  memset (hash, 0, sizeof (hash));
  bn448_mul ((bn896 *)hash, s, a);
  mod_reduce_M (s, (const bn912 *)hash);

  carry = bn448_add (s, s, k);
  borrow = bn448_sub (s, s, M);
  bn448_add_cond (s, M, (borrow && !carry));

  memcpy (out, r, 57);
  memcpy (out+57, s, 56);
  out[114-1] = 0;

  return 0;
}


void
ed448_compute_public (uint8_t *pk, const uint8_t *a_in)
{
  p448_t a[1];

  p448_deserialize (a, a_in);
  a->limb[15] |= 0x08000000;
  a->limb[0] &= ~3;

  compute_kG_448 (pk, (uint32_t *)a);
}
