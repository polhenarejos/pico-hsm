/*                                                    -*- coding: utf-8 -*-
 * ecc-ed25519.c - Elliptic curve computation for
 *                 the twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
 *                 d = -121665/121666
 *
 * Copyright (C) 2014, 2017  Free Software Initiative of Japan
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
#include "mod.h"
#include "mod25638.h"
#include "sha512.h"

/*
 * References:
 *
 * [1] Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, Bo-Yin Yang.
 *     High-speed high-security signatures.
 *     Journal of Cryptographic Engineering 2 (2012), 77--89.
 *     http://cr.yp.to/papers.html#ed25519
 *
 * [2] Daniel J. Bernstein, Peter Birkner, Marc Joye, Tanja Lange,
 *     Christiane Peters.
 *     Twisted Edwards curves.
 *     Pages 389--405 in Progress in cryptology---AFRICACRYPT 2008.
 *     http://cr.yp.to/papers.html#twisted
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
 * (2) We use fixed base comb multiplication.  Scalar is 252-bit.
 *     There are various possible choices for 252 = 2 * 2 * 3 * 3 * 7.
 *     Current choice of total size is 3KB.  We use three tables, and
 *     a table has 16 points (3 * 1KB).
 *
 *     Window size W = 4-bit, E = 21.
 *                                                       <--21-bit-
 *                                             <---42-bit----------
 *     [        ][########][////////][        ][########][////////]
 *                                   <-------63-bit----------------
 *                         <-----------84-bit----------------------
 *               <--------------105-bit----------------------------
 *
 *     [        ][########][////////][        ][########][////////]
 *                                                                 <-126-bit-
 *                                                       <-147-bit-
 *                                             <----168-bit--------
 *
 *                                   <-------189-bit---------------
 *                         <----------210-bit----------------------
 *               <-------------231-bit-----------------------------
 */

/*
 * Identity element: (0,1)
 * Negation: -(x,y) = (-x,y)
 *
 * d: -0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A
 * order:
 *     0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 * Gx: 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
 * Gy: 0x6666666666666666666666666666666666666666666666666666666666666658
 */

/* d + 2^255 - 19 */
static const bn256 coefficient_d[1] = {
  {{ 0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d,
     0x7779e898, 0x8cc74079, 0x2b6ffe73, 0x52036cee }} };


/**
 * @brief	Projective Twisted Coordinates
 */
typedef struct
{
  bn256 x[1];
  bn256 y[1];
  bn256 z[1];
} ptc;

#include "affine.h"


static int
mod25519_is_neg (const bn256 *a)
{
  return (a->word[0] & 1);
}


/**
 * @brief  X = 2 * A
 *
 * Compute (X3 : Y3 : Z3) = 2 * (X1 : Y1 : Z1)
 */
static void
point_double (ptc *X, const ptc *A)
{
  bn256 b[1], d[1], e[1];

  /* Compute: B = (X1 + Y1)^2 */
  mod25638_add (b, A->x, A->y);
  mod25638_sqr (b, b);

  /* Compute: C = X1^2        : E      */
  mod25638_sqr (e, A->x);

  /* Compute: D = Y1^2             */
  mod25638_sqr (d, A->y);

  /* E = aC; where a = -1 */
  /* Compute: D - E = D + C : Y3_tmp */
  mod25638_add (X->y, e, d);

  /* Compute: -F = -(E + D) = C - D; where a = -1 : E */
  mod25638_sub (e, e, d);

  /* Compute: H = Z1^2        : D     */
  mod25638_sqr (d, A->z);

  /* Compute: -J = 2*H - F    : D     */
  mod25638_add (d, d, d);
  mod25638_add (d, d, e);

  /* Compute: X3 = (B-C-D)*J = -J*(C+D-B) = -J*(Y3_tmp-B)  */
  mod25638_sub (X->x, X->y, b);
  mod25638_mul (X->x, X->x, d);

  /* Compute: Y3 = -F*(D-E) = -F*Y3_tmp            */
  mod25638_mul (X->y, X->y, e);

  /* Z3 = -F*-J             */
  mod25638_mul (X->z, e, d);
}


/**
 * @brief	X = A + B
 *
 * @param X	Destination PTC
 * @param A	PTC
 * @param B	AC
 *
 * Compute: (X3 : Y3 : Z3) = (X1 : Y1 : Z1) + (X2 : Y2 : 1)
 */
static void
point_add (ptc *X, const ptc *A, const ac *B)
{
  bn256 c[1], d[1], e[1], tmp[1];

  /* Compute: C = X1 * X2 */
  mod25638_mul (c, A->x, B->x);

  /* Compute: D = Y1 * Y2 */
  mod25638_mul (d, A->y, B->y);

  /* Compute: E = d * C * D */
  mod25638_mul (e, c, d);
  mod25638_mul (e, coefficient_d, e);

  /* Compute: C_1 = C + D */
  mod25638_add (c, c, d);

  /* Compute: D_1 = Z1^2 : B */
  mod25638_sqr (d, A->z);

  /* tmp = D_1 - E : F */
  mod25638_sub (tmp, d, e);

  /* D_2 = D_1 + E : G */
  mod25638_add (d, d, e);

  /* X3_final = Z1 * tmp * ((X1 + Y1) * (X2 + Y2) - C_1) */
  mod25638_add (X->x, A->x, A->y);
  mod25638_add (e, B->x, B->y);
  mod25638_mul (e, X->x, e);
  mod25638_sub (e, e, c);
  mod25638_mul (e, tmp, e);
  mod25638_mul (X->x, A->z, e);

  /* Y3_final = Z1 * D_2 * C_1 */
  mod25638_mul (c, d, c);
  mod25638_mul (X->y, A->z, c);

  /* Z3_final = tmp * D_2 */
  mod25638_mul (X->z, tmp, d);

  /* A = Z1 */
  /* B = A^2 */
  /* C = X1 * X2 */
  /* D = Y1 * Y2 */
  /* E = d * C * D */
  /* F = B - E */
  /* G = B + E */
  /* X3 = A * F * ((X1 + Y1) * (X2 + Y2) - C - D) */
  /* Y3 = A * G * (D - aC); where a = -1 */
  /* Z3 = F * G */
}


/**
 * @brief	X = convert A
 *
 * @param X	Destination AC
 * @param A	PTC
 *
 * (X1:Y1:Z1) represents the affine point (x=X1/Z1, y=Y1/Z1)
 */
static void
point_ptc_to_ac (ac *X, const ptc *A)
{
  bn256 z_inv[1];

  /*
   * A->z may be bigger than p25519, or two times bigger than p25519.
   * But this is no problem for computation of mod_inv.
   */
  mod_inv (z_inv, A->z, p25519);

  mod25638_mul (X->x, A->x, z_inv);
  mod25519_reduce (X->x);
  mod25638_mul (X->y, A->y, z_inv);
  mod25519_reduce (X->y);
}


static const ac precomputed_KG[16] = {
  { {{{ 0, 0, 0, 0, 0, 0, 0, 0 }}},
    {{{ 1, 0, 0, 0, 0, 0, 0, 0 }}}                         },
  { {{{ 0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760,
        0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3 }}},
    {{{ 0x66666658, 0x66666666, 0x66666666, 0x66666666,
        0x66666666, 0x66666666, 0x66666666, 0x66666666 }}} },
  { {{{ 0x3713af22, 0xac7137bd, 0xac634604, 0x25ed77a4,
        0xa815e038, 0xce0d0064, 0xbca90151, 0x041c030f }}},
    {{{ 0x0780f989, 0xe9b33fcf, 0x3d4445e7, 0xe4e97c2a,
        0x655e5c16, 0xc67dc71c, 0xee43fb7a, 0x72467625 }}} },
  { {{{ 0x3ee99893, 0x76a19171, 0x7ba9b065, 0xe647edd9,
        0x6aeae260, 0x31f39299, 0x5f4a9bb2, 0x6d9e4545 }}},
    {{{ 0x94cae280, 0xc41433da, 0x79061211, 0x8e842de8,
        0xa259dc8a, 0xaab95e0b, 0x99013cd0, 0x28bd5fc3 }}} },
  { {{{ 0x7d23ea24, 0x59e22c56, 0x0460850e, 0x1e745a88,
        0xda13ef4b, 0x4583ff4c, 0x95083f85, 0x1f13202c }}},
    {{{ 0x90275f48, 0xad42025c, 0xb55c4778, 0x0085087e,
        0xfdfd7ffa, 0xf21109e7, 0x6c381b7e, 0x66336d35 }}} },
  { {{{ 0xd00851f2, 0xaa9476ab, 0x4a61600b, 0xe7838534,
        0x1a52df87, 0x0de65625, 0xbd675870, 0x5f0dd494 }}},
    {{{ 0xe23493ba, 0xf20aec1b, 0x3414b0a8, 0x8f7f2741,
        0xa80e1eb6, 0x497e74bd, 0xe9365b15, 0x1648eaac }}} },
  { {{{ 0x04ac2b69, 0x5b78dcec, 0x32001a73, 0xecdb66ce,
        0xb34cf697, 0xb75832f4, 0x3a2bce94, 0x7aaf57c5 }}},
    {{{ 0x60fdfc6f, 0xb32ed2ce, 0x757924c6, 0x77bf20be,
        0x48742dd1, 0xaebd15dd, 0x55d38439, 0x6311bb16 }}} },
  { {{{ 0x42ff5c97, 0x139cdd73, 0xdbd82964, 0xee4c359e,
        0x70611a3f, 0x91c1cd94, 0x8075dbcb, 0x1d0c34f6 }}},
    {{{ 0x5f931219, 0x43eaa549, 0xa23d35a6, 0x3737aba7,
        0x46f167bb, 0x54b1992f, 0xb74a9944, 0x01a11f3c }}} },
  { {{{ 0xba46b161, 0x67a5310e, 0xd9d67f6c, 0x790f8527,
        0x2f6cc814, 0x359c5b5f, 0x7786383d, 0x7b6a5565 }}},
    {{{ 0x663ab0d3, 0xf1431b60, 0x09995826, 0x14a32d8f,
        0xeddb8571, 0x61d526f6, 0x0eac739a, 0x0cb7acea }}} },
  { {{{ 0x4a2d009f, 0x5eb1a697, 0xd8df987a, 0xdacb43b4,
        0x8397f958, 0x4870f214, 0x8a175fbb, 0x5aa0c67c }}},
    {{{ 0x78887db3, 0x27dbbd4c, 0x64e322ab, 0xe327b707,
        0x7cbe4e3b, 0x87e293fa, 0xbda72395, 0x17040799 }}} },
  { {{{ 0x99d1e696, 0xc833a5a2, 0x2d9d5877, 0x969bff8e,
        0x2216fa67, 0x383a533a, 0x684d3925, 0x338bbe0a }}},
    {{{ 0xd6cfb491, 0x35b5aae8, 0xaa12f3f8, 0x4a588279,
        0x2e30380e, 0xa7c2e708, 0x9e4b3d62, 0x69f13e09 }}} },
  { {{{ 0x27f1cd56, 0xec0dc2ef, 0xdb11cc97, 0x1af11548,
        0x9ebc7613, 0xb642f86a, 0xcb77c3b9, 0x5ce45e73 }}},
    {{{ 0x3eddd6de, 0x5d128786, 0x4859eab7, 0x16f9a6b4,
        0xd8782345, 0x55c53916, 0xdb7b202a, 0x6b1dfa87 }}} },
  { {{{ 0x19e30528, 0x2461a8ed, 0x665cfb1c, 0xaf756bf9,
        0x3a6e8673, 0x0fcafd1d, 0x45d10f48, 0x0d264435 }}},
    {{{ 0x5431db67, 0x543fd4c6, 0x60932432, 0xc153a5b3,
        0xd2119aa4, 0x41d5b8eb, 0x8b09b6a5, 0x36bd9ab4 }}} },
  { {{{ 0x21e06738, 0x6d39f935, 0x3765dd86, 0x4e6a7c59,
        0xa4730880, 0xefc0dd80, 0x4079fe2f, 0x40617e56 }}},
    {{{ 0x921439b9, 0xbc83cdff, 0x98833c09, 0xd5cccc06,
        0xda13cdcb, 0xe315c425, 0x67ff5370, 0x37bc6e84 }}} },
  { {{{ 0xf643b5f5, 0x65e7f028, 0x0ffbf5a8, 0x5b0d4831,
        0xf4085f62, 0x0f540498, 0x0db7bd1b, 0x6f0bb035 }}},
    {{{ 0x9733742c, 0x51f65571, 0xf513409f, 0x2fc047a0,
        0x355facf6, 0x07f45010, 0x3a989a9c, 0x5cd416a9 }}} },
  { {{{ 0x748f2a67, 0x0bdd7208, 0x415b7f7f, 0x0cf0b80b,
        0x57aa0119, 0x44afdd5f, 0x430dc946, 0x05d68802 }}},
    {{{ 0x1a60eeb2, 0x420c46e5, 0x665024f5, 0xc60a9b33,
        0x48c51347, 0x37520265, 0x00a21bfb, 0x6f4be0af }}} }
};

static const ac precomputed_2E_KG[16] = {
  { {{{ 0, 0, 0, 0, 0, 0, 0, 0 }}},
    {{{ 1, 0, 0, 0, 0, 0, 0, 0 }}}                         },
  { {{{ 0x199c4f7d, 0xec314ac0, 0xb2ebaaf9, 0x66a39c16,
        0xedd4d15f, 0xab1c92b8, 0x57d9eada, 0x482a4cdf }}},
    {{{ 0x6e4eb04b, 0xbd513b11, 0x25e4fd6a, 0x3f115fa5,
        0x14519298, 0x0b3c5fc6, 0x81c2f7a8, 0x7391de43 }}} },
  { {{{ 0x1254fe02, 0xa57dca18, 0x6da34368, 0xa56a2a14,
        0x63e7328e, 0x44c6e34f, 0xca63ab3e, 0x3f748617 }}},
    {{{ 0x7dc1641e, 0x5a13dc52, 0xee4e9ca1, 0x4cbb2899,
        0x1ba9acee, 0x3938a289, 0x420fc47b, 0x0fed89e6 }}} },
  { {{{ 0x49cbad08, 0x3c193f32, 0x15e80ef5, 0xdda71ef1,
        0x9d128c33, 0xda44186c, 0xbf98c24f, 0x54183ede }}},
    {{{ 0x93d165c1, 0x2cb483f7, 0x177f44aa, 0x51762ace,
        0xb4ab035d, 0xb3fe651b, 0xa0b0d4e5, 0x426c99c3 }}} },
  { {{{ 0xef3f3fb1, 0xb3fcf4d8, 0x065060a0, 0x7052292b,
        0x24240b15, 0x18795ff8, 0x9989ffcc, 0x13aea184 }}},
    {{{ 0xc2b81f44, 0x1930c101, 0x10600555, 0x672d6ca4,
        0x1b25e570, 0xfbddbff2, 0x8ca12b70, 0x0884949c }}} },
  { {{{ 0x00564bbf, 0x9983a033, 0xde61b72d, 0x95587d25,
        0xeb17ad71, 0xb6719dfb, 0xc0bc3517, 0x46871ad0 }}},
    {{{ 0xe95a6693, 0xb034fb61, 0x76eabad9, 0x5b0d8d18,
        0x884785dc, 0xad295dd0, 0x74a1276a, 0x359debad }}} },
  { {{{ 0xe89fb5ca, 0x2e5a2686, 0x5656c6c5, 0xd3d200ba,
        0x9c969001, 0xef4c051e, 0x02cb45f4, 0x0d4ea946 }}},
    {{{ 0x76d6e506, 0xa6f8a422, 0x63209e23, 0x454c768f,
        0x2b372386, 0x5c12fd04, 0xdbfee11f, 0x1aedbd3e }}} },
  { {{{ 0x00dbf569, 0x700ab50f, 0xd335b313, 0x9553643c,
        0xa17dc97e, 0xeea9bddf, 0x3350a2bd, 0x0d12fe3d }}},
    {{{ 0xa16a3dee, 0xe5ac35fe, 0xf81950c3, 0x4ae4664a,
        0x3dbbf921, 0x75c63df4, 0x2958a5a6, 0x545b109c }}} },
  { {{{ 0x0a61b29c, 0xd7a52a98, 0x65aca9ee, 0xe21e0acb,
        0x5985dcbe, 0x57a69c0f, 0xeb87a534, 0x3c0c1e7b }}},
    {{{ 0x6384bd2f, 0xf0a0b50d, 0xc6939e4b, 0xff349a34,
        0x6e2f1973, 0x922c4554, 0xf1347631, 0x74e826b2 }}} },
  { {{{ 0xa655803c, 0xd7eaa066, 0x38292c5c, 0x09504e76,
        0x2c874953, 0xe298a02e, 0x8932b73f, 0x225093ed }}},
    {{{ 0xe69c3efd, 0xf93e2b4d, 0x8a87c799, 0xa2cbd5fc,
        0x85dba986, 0xdf41da94, 0xccee8edc, 0x36fe85e7 }}} },
  { {{{ 0x7d742813, 0x78df7dc5, 0x4a193e64, 0x333bcc6d,
        0x6a966d2d, 0x8242aa25, 0x4cd36d32, 0x03500a94 }}},
    {{{ 0x580505d7, 0xd5d110fc, 0xfa11e1e9, 0xb2f47e16,
        0x06eab6b4, 0xd0030f92, 0x62c91d46, 0x2dc80d5f }}} },
  { {{{ 0x2a75e492, 0x5788b01a, 0xbae31352, 0x992acf54,
        0x8159db27, 0x4591b980, 0xd3d84740, 0x36c6533c }}},
    {{{ 0x103883b5, 0xc44c7c00, 0x515d0820, 0x10329423,
        0x71b9dc16, 0xbd306903, 0xf88f8d32, 0x7edd5a95 }}} },
  { {{{ 0x005523d7, 0xfd63b1ac, 0xad70dd21, 0x74482e0d,
        0x02b56105, 0x67c9d9d0, 0x5971b456, 0x4d318012 }}},
    {{{ 0x841106df, 0xdc9a6f6d, 0xa326987f, 0x7c52ed9d,
        0x00607ea0, 0x4dbeaa6f, 0x6959e688, 0x115c221d }}} },
  { {{{ 0xc80f7c16, 0xf8718464, 0xe9930634, 0x05dc8f40,
        0xc2e9d5f4, 0xefa699bb, 0x021da209, 0x2469e813 }}},
    {{{ 0xc602a3c4, 0x75c02845, 0x0a200f9d, 0x49d1b2ce,
        0x2fb3ec8f, 0xd21b75e4, 0xd72a7545, 0x10dd726a }}} },
  { {{{ 0x63ef1a6c, 0xeda58527, 0x051705e0, 0xb3fc0e72,
        0x44f1161f, 0xbda6f3ee, 0xf339efe5, 0x7680aebf }}},
    {{{ 0xb1b070a7, 0xe8d3fd01, 0xdbfbaaa0, 0xc3ff7dbf,
        0xa320c916, 0xd81ef6f2, 0x62a3b54d, 0x3e22a1fb }}} },
  { {{{ 0xb1fa18c8, 0xcdbb9187, 0xcb483a17, 0x8ddb5f6b,
        0xea49af98, 0xc0a880b9, 0xf2dfddd0, 0x53bf600b }}},
    {{{ 0x9e25b164, 0x4217404c, 0xafb74aa7, 0xfabf06ee,
        0x2b9f233c, 0xb17712ae, 0xd0eb909e, 0x71f0b344 }}} }
};

static const ac precomputed_4E_KG[16] = {
  { {{{ 0, 0, 0, 0, 0, 0, 0, 0 }}},
    {{{ 1, 0, 0, 0, 0, 0, 0, 0 }}}                         },
  { {{{ 0xe388a820, 0xbb6ec091, 0x5182278a, 0xa928b283,
        0xa9a6eb83, 0x2259174d, 0x45500054, 0x184b48cb }}},
    {{{ 0x26e77c33, 0xfe324dba, 0x83faf453, 0x6679a5e3,
        0x2380ef73, 0xdd60c268, 0x03dc33a9, 0x3ee0e07a }}} },
  { {{{ 0xce974493, 0x403aff28, 0x9bf6f5c4, 0x84076bf4,
        0xecd898fb, 0xec57038c, 0xb663ed49, 0x2898ffaa }}},
    {{{ 0xf335163d, 0xf4b3bc46, 0xfa4fb6c6, 0xe613a0f4,
        0xb9934557, 0xe759d6bc, 0xab6c9477, 0x094f3b96 }}} },
  { {{{ 0x6afffe9e, 0x168bb5a0, 0xee748c29, 0x950f7ad7,
        0xda17203d, 0xa4850a2b, 0x77289e0f, 0x0062f7a7 }}},
    {{{ 0x4b3829fa, 0x6265d4e9, 0xbdfcd386, 0x4f155ada,
        0x475795f6, 0x9f38bda4, 0xdece4a4c, 0x560ed4b3 }}} },
  { {{{ 0x141e648a, 0xdad4570a, 0x019b965c, 0x8bbf674c,
        0xdb08fe30, 0xd7a8d50d, 0xa2851109, 0x7efb45d3 }}},
    {{{ 0xd0c28cda, 0x52e818ac, 0xa321d436, 0x792257dd,
        0x9d71f8b7, 0x867091c6, 0x11a1bf56, 0x0fe1198b }}} },
  { {{{ 0x06137ab1, 0x4e848339, 0x3e6674cc, 0x5673e864,
        0x0140502b, 0xad882043, 0x6ea1e46a, 0x34b5c0cb }}},
    {{{ 0x1d70aa7c, 0x29786814, 0x8cdbb8aa, 0x840ae3f9,
        0xbd4801fb, 0x78b4d622, 0xcf18ae9a, 0x6cf4e146 }}} },
  { {{{ 0x36297168, 0x95c270ad, 0x942e7812, 0x2303ce80,
        0x0205cf0e, 0x71908cc2, 0x32bcd754, 0x0cc15edd }}},
    {{{ 0x2c7ded86, 0x1db94364, 0xf141b22c, 0xc694e39b,
        0x5e5a9312, 0xf22f64ef, 0x3c5e6155, 0x649b8859 }}} },
  { {{{ 0xb6417945, 0x0d5611c6, 0xac306c97, 0x9643fdbf,
        0x0df500ff, 0xe81faaa4, 0x6f50e615, 0x0792c79b }}},
    {{{ 0xd2af8c8d, 0xb45bbc49, 0x84f51bfe, 0x16c615ab,
        0xc1d02d32, 0xdc57c526, 0x3c8aaa55, 0x5fb9a9a6 }}} },
  { {{{ 0xdee40b98, 0x82faa8db, 0x6d520674, 0xff8a5208,
        0x446ac562, 0x1f8c510f, 0x2cc6b66e, 0x4676d381 }}},
    {{{ 0x2e7429f4, 0x8f1aa780, 0x8ed6bdf6, 0x2a95c1bf,
        0x457fa0eb, 0x051450a0, 0x744c57b1, 0x7d89e2b7 }}} },
  { {{{ 0x3f95ea15, 0xb6bdacd2, 0x2f1a5d69, 0xc9a9d1b1,
        0xf4d22d72, 0xd4c2f1a9, 0x4dc516b5, 0x73ecfdf1 }}},
    {{{ 0x05391e08, 0xa1ce93cd, 0x7b8aac17, 0x98f1e99e,
        0xa098cbb3, 0x9ba84f2e, 0xf9bdd37a, 0x1425aa8b }}} },
  { {{{ 0x966abfc0, 0x8a385bf4, 0xf081a640, 0x55e5e8bc,
        0xee26f5ff, 0x835dff85, 0xe509e1ea, 0x4927e622 }}},
    {{{ 0x352334b0, 0x164c8dbc, 0xa3fea31f, 0xcac1ad63,
        0x682fd457, 0x9b87a676, 0x1a53145f, 0x75f382ff }}} },
  { {{{ 0xc3efcb46, 0x16b944f5, 0x68cb184c, 0x1fb55714,
        0x9ccf2dc8, 0xf1c2b116, 0x808283d8, 0x7417e00f }}},
    {{{ 0x930199ba, 0x1ea67a22, 0x718990d8, 0x9fbaf765,
        0x8f3d5d57, 0x231fc664, 0xe5853194, 0x38141a19 }}} },
  { {{{ 0x2f81290d, 0xb9f00390, 0x04a9ca6c, 0x44877827,
        0xe1dbdd65, 0x65d7f9b9, 0xf7c6698a, 0x7133424c }}},
    {{{ 0xa7cd250f, 0x604cfb3c, 0x5acc18f3, 0x460c3c4b,
        0xb518e3eb, 0xa53e50e0, 0x98a40196, 0x2b4b9267 }}} },
  { {{{ 0xc5dbd06c, 0x591b0672, 0xaa1eeb65, 0x10d43dca,
        0xcd2517af, 0x420cdef8, 0x0b695a8a, 0x513a307e }}},
    {{{ 0x66503215, 0xee9d6a7b, 0x088fd9a4, 0xdea58720,
        0x973afe12, 0x8f3cbbea, 0x872f2538, 0x005c2350 }}} },
  { {{{ 0x35af3291, 0xe5024b70, 0x4f5e669a, 0x1d3eec2d,
        0x6e79d539, 0xc1f6d766, 0x795b5248, 0x34ec043f }}},
    {{{ 0x400960b6, 0xb2763511, 0x29e57df0, 0xff7a3d84,
        0x1666c1f1, 0xaeac7792, 0x66084bc0, 0x72426e97 }}} },
  { {{{ 0x44f826ca, 0x5b1c3199, 0x790aa408, 0x68b00b73,
        0x69e9b92b, 0xaf0984b4, 0x3ffe9093, 0x5fe6736f }}},
    {{{ 0xffd49312, 0xd67f2889, 0x5cb9ed21, 0x3520d747,
        0x3c65a606, 0x94f893b1, 0x2d65496f, 0x2fee5e8c }}} }
};

/**
 * @brief	X  = k * G
 *
 * @param K	scalar k
 *
 * Return -1 on error.
 * Return 0 on success.
 */
static void
compute_kG_25519 (ac *X, const bn256 *K)
{
  ptc Q[1];
  int i;

  /* identity element */
  memset (Q, 0, sizeof (ptc));
  Q->y->word[0] = 1;
  Q->z->word[0] = 1;

  for (i = 20; i >= 0; i--)
    {
      int k0, k1, k2;

      k0 = ((K->word[0] >> i) & 1)
	| (i < 1 ? ((K->word[1] >> 30) & 2)
	   : (((K->word[2] >> (i-1)) & 1) << 1))
	| (i < 2 ? ((K->word[3] >> (i+28)) & 4)
	   : (((K->word[4] >> (i-2)) & 1) << 2))
	| (i < 3 ? ((K->word[5] >> (i+26)) & 8)
	   : (((K->word[6] >> (i-3)) & 1) << 3));

      k1 = (i < 11 ? ((K->word[0] >> (i+21)) & 1)
	    : ((K->word[1] >> (i-11)) & 1))
	| (i < 12 ? ((K->word[2] >> (i+19)) & 2)
	   : (((K->word[3] >> (i-12)) & 1) << 1))
	| (i < 13 ? ((K->word[4] >> (i+17)) & 4)
	   : (((K->word[5] >> (i-13)) & 1) << 2))
	| (i < 14 ? ((K->word[6] >> (i+15)) & 8)
	   : (((K->word[7] >> (i-14)) & 1) << 3));

      k2 = ((K->word[1] >> (i+10)) & 1)
	| ((K->word[3] >> (i+8)) & 2)
	| ((K->word[5] >> (i+6)) & 4)
	| ((K->word[7] >> (i+4)) & 8);

      point_double (Q, Q);
      point_add (Q, Q, &precomputed_KG[k0]);
      point_add (Q, Q, &precomputed_2E_KG[k1]);
      point_add (Q, Q, &precomputed_4E_KG[k2]);
    }

  point_ptc_to_ac (X, Q);
}


#define BN416_WORDS 13
#define BN128_WORDS 4

/* M: The order of the generator G.  */
static const bn256 M[1] = {
  {{  0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE,
      0x00000000, 0x00000000, 0x00000000, 0x10000000  }}
};

#define C ((const uint32_t *)M)

static void
bnX_mul_C (uint32_t *r, const uint32_t *q, int q_size)
{
  int i, j, k;
  int i_beg, i_end;
  uint32_t r0, r1, r2;

  r0 = r1 = r2 = 0;
  for (k = 0; k <= q_size + BN128_WORDS - 2; k++)
    {
      if (q_size < BN128_WORDS)
	if (k < q_size)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - q_size + 1;
	    i_end = k;
	    if (i_end > BN128_WORDS - 1)
	      i_end = BN128_WORDS - 1;
	  }
      else
	if (k < BN128_WORDS)
	  {
	    i_beg = 0;
	    i_end = k;
	  }
	else
	  {
	    i_beg = k - BN128_WORDS + 1;
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
	  if (q_size < BN128_WORDS)
	    uv = ((uint64_t )q[j])*((uint64_t )C[i]);
	  else
	    uv = ((uint64_t )q[i])*((uint64_t )C[j]);
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

/**
 * @brief R = A mod M (using M=2^252+C) (Barret reduction)
 *
 * See HAC 14.47 and 14.52.
 */
static void
mod_reduce_M (bn256 *R, const bn512 *A)
{
  uint32_t q[BN256_WORDS+1];
  uint32_t tmp[BN416_WORDS];
  bn256 r[1];
  uint32_t carry, next_carry;
  int i;
#define borrow carry

  q[8] = A->word[15]>>28;
  carry = A->word[15] & 0x0fffffff;
  for (i = BN256_WORDS - 1; i >= 0; i--)
    {
      next_carry = A->word[i+7] & 0x0fffffff;
      q[i] = (A->word[i+7] >> 28) | (carry << 4);
      carry = next_carry;
    }
  memcpy (R, A, sizeof (bn256));
  R->word[7] &= 0x0fffffff;

  /* Q_size: 9 */
  bnX_mul_C (tmp, q, 9); /* TMP = Q*C */
  /* Q = tmp / 2^252 */
  carry = tmp[12] & 0x0fffffff;
  for (i = 4; i >= 0; i--)
    {
      next_carry = tmp[i+7] & 0x0fffffff;
      q[i] = (tmp[i+7] >> 28) | (carry << 4);
      carry = next_carry;
    }
  /* R' = tmp % 2^252 */
  memcpy (r, tmp, sizeof (bn256));
  r->word[7] &= 0x0fffffff;
  /* R -= R' */
  borrow = bn256_sub (R, R, r);
  if (borrow)
    bn256_add (R, R, M);
  else
    bn256_add ((bn256 *)tmp, R, M);

  /* Q_size: 5 */
  bnX_mul_C (tmp, q, 5); /* TMP = Q*C */
  carry = tmp[8] & 0x0fffffff;
  q[0] = (tmp[7] >> 28) | (carry << 4);
  /* R' = tmp % 2^252 */
  memcpy (r, tmp, sizeof (bn256));
  r->word[7] &= 0x0fffffff;
  /* R += R' */
  bn256_add (R, R, r);
  borrow = bn256_sub (R, R, M);
  if (borrow)
    bn256_add (R, R, M);
  else
    bn256_add ((bn256 *)tmp, R, M);

  /* Q_size: 1 */
  bnX_mul_C (tmp, q, 1); /* TMP = Q*C */
  /* R' = tmp % 2^252 */
  memset (((uint8_t *)r)+(sizeof (uint32_t)*5), 0, sizeof (uint32_t)*3);
  memcpy (r, tmp, sizeof (uint32_t)*5);
  /* R -= R' */
  borrow = bn256_sub (R, R, r);
  if (borrow)
    bn256_add (R, R, M);
  else
    bn256_add ((bn256 *)tmp, R, M);
#undef borrow
}


int
eddsa_sign_25519 (const uint8_t *input, size_t ilen, uint32_t *out,
		  const bn256 *a, const uint8_t *seed, const bn256 *pk)
{
  bn256 *r, *s;
  sha512_context ctx;
  uint8_t hash[64];
  bn256 tmp[1];
  ac R[1];
  uint32_t carry, borrow;

  r = (bn256 *)out;
  s = (bn256 *)(out+(32/4));

  sha512_start (&ctx);
  sha512_update (&ctx, seed, sizeof (bn256)); /* It's upper half of the hash */
  sha512_update (&ctx, input, ilen);
  sha512_finish (&ctx, hash);

  mod_reduce_M (r, (bn512 *)hash);
  compute_kG_25519 (R, r);

  /* EdDSA encoding.  */
  memcpy (tmp, R->y, sizeof (bn256));
  tmp->word[7] ^= mod25519_is_neg (R->x) * 0x80000000;

  sha512_start (&ctx);
  sha512_update (&ctx, (uint8_t *)tmp, sizeof (bn256));
  sha512_update (&ctx, (uint8_t *)pk, sizeof (bn256));
  sha512_update (&ctx, input, ilen);
  sha512_finish (&ctx, (uint8_t *)hash);

  mod_reduce_M (s, (bn512 *)hash);
  bn256_mul ((bn512 *)hash, s, a);
  mod_reduce_M (s, (bn512 *)hash);
  carry = bn256_add (s, s, r);
  borrow = bn256_sub (s, s, M);

  memcpy (r, tmp, sizeof (bn256));

  if ((borrow && !carry))
    bn256_add (s, s, M);
  else
    bn256_add (tmp, s, M);

  return 0;
}

static void
eddsa_public_key_25519 (bn256 *pk, const bn256 *a)
{
  ac R[1];
  ptc X[1];
  bn256 a0[1];

  bn256_shift (a0, a, -3);
  compute_kG_25519 (R, a0);
  memcpy (X, R, sizeof (ac));
  memset (X->z, 0, sizeof (bn256));
  X->z->word[0] = 1;
  point_double (X, X);
  point_double (X, X);
  point_double (X, X);
  point_ptc_to_ac (R, X);
  /* EdDSA encoding.  */
  memcpy (pk, R->y, sizeof (bn256));
  pk->word[7] ^= mod25519_is_neg (R->x) * 0x80000000;
}


void
eddsa_compute_public_25519 (const uint8_t *kd, uint8_t *pubkey)
{
  eddsa_public_key_25519 ((bn256 *)pubkey, (const bn256 *)kd);
}


#if 0
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

  /* Twisted Edwards curve: a*x^2 + y^2 = 1 + d*x^2*y^2 */
}

int
compute_kP_25519 (ac *X, const bn256 *K, const ac *P);
#endif

#ifdef PRINT_OUT_TABLE
static const ptc G[1] = {{
  {{{ 0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760,
      0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3 }}},
  {{{ 0x66666658, 0x66666666, 0x66666666, 0x66666666,
      0x66666666, 0x66666666, 0x66666666, 0x66666666 }}},
  {{{ 1, 0, 0, 0, 0, 0, 0, 0 }}},
}};

#include <stdio.h>

#ifdef TESTING_EDDSA
static void
print_bn256 (const bn256 *X)
{
  int i;

  for (i = 7; i >= 0; i--)
    printf ("%08x", X->word[i]);
  puts ("");
}
#endif

#if 0
static void
print_point (const ac *X)
{
  int i;

#ifdef PRINT_OUT_TABLE_AS_C
  fputs ("  { {{{ ", stdout);
  for (i = 0; i < 4; i++)
    printf ("0x%08x, ", X->x->word[i]);
  fputs ("\n        ", stdout);
  for (; i < 7; i++)
    printf ("0x%08x, ", X->x->word[i]);
  printf ("0x%08x }}},\n", X->x->word[i]);
  fputs ("    {{{ ", stdout);
  for (i = 0; i < 4; i++)
    printf ("0x%08x, ", X->y->word[i]);
  fputs ("\n        ", stdout);
  for (; i < 7; i++)
    printf ("0x%08x, ", X->y->word[i]);
  printf ("0x%08x }}} },\n", X->y->word[i]);
#else
  puts ("--");
  for (i = 7; i >= 0; i--)
    printf ("%08x", X->x->word[i]);
  puts ("");
  for (i = 7; i >= 0; i--)
    printf ("%08x", X->y->word[i]);
  puts ("");
  puts ("--");
#endif
}

static void
print_point_ptc (const ptc *X)
{
  int i;

  puts ("---");
  for (i = 7; i >= 0; i--)
    printf ("%08x", X->x->word[i]);
  puts ("");
  for (i = 7; i >= 0; i--)
    printf ("%08x", X->y->word[i]);
  puts ("");
  for (i = 7; i >= 0; i--)
    printf ("%08x", X->z->word[i]);
  puts ("");
  puts ("---");
}
#endif


#ifndef TESTING_EDDSA
static void power_2 (ac *A, ptc *a, int N)
{
  int i;

  for (i = 0; i < N; i++)
    ed_double_25638 (a, a);
  ptc_to_ac_25519 (A, a);
}

static void print_table (ac *a0001, ac *a0010, ac *a0100, ac *a1000)
{
  int i;
  ptc a[1];
  ac x[1];

  for (i = 1; i < 16; i++)
    {
      /* A := Identity Element  */
      memset (a, 0, sizeof (ptc));
      a->y->word[0] = 1;
      a->z->word[0] = 1;

      if ((i & 1))
	ed_add_25638 (a, a, a0001);
      if ((i & 2))
	ed_add_25638 (a, a, a0010);
      if ((i & 4))
	ed_add_25638 (a, a, a0100);
      if ((i & 8))
	ed_add_25638 (a, a, a1000);

      ptc_to_ac_25519 (x, a);
      print_point (x);
    }

  fputs ("\n", stdout);
}

static void compute_and_print_table (ac *a0001, ac *a0010, ac *a0100, ac *a1000)
{
  ptc a[1];

  memcpy (a, a0001, sizeof (ac));
  memset (a->z, 0, sizeof (bn256));
  a->z->word[0] = 1;
  power_2 (a0010, a, 63);
  power_2 (a0100, a, 63);
  power_2 (a1000, a, 63);
  print_table (a0001, a0010, a0100, a1000);
}
#endif

int
main (int argc, char *argv[])
{
#ifdef TESTING_EDDSA
  uint8_t hash[64];
  bn256 a[1];
  uint8_t r_s[64];
  bn256 pk[1];
  bn256 *r, *s;

  const bn256 sk[1] = {
    {{ 0x9db1619d, 0x605afdef, 0xf44a84ba, 0xc42cec92,
       0x69c54944, 0x1969327b, 0x03ac3b70, 0x607fae1c }} };

  const bn256 r_expected[1] = {
    {{ 0x004356e5, 0x72ac60c3, 0xcce28690, 0x8a826e80,
       0x1e7f8784, 0x74d9e5b8, 0x65e073d8, 0x55014922 }} };

  const bn256 s_expected[1] = {
    {{ 0x1582b85f, 0xac3ba390, 0x70391ec6, 0x6bb4f91c,
       0xf0f55bd2, 0x24be5b59, 0x43415165, 0x0b107a8e }} };

  r = (bn256 *)r_s;
  s = (bn256 *)(r_s+32);

  sha512 ((uint8_t *)sk, sizeof (bn256), hash);
  hash[0] &= 248;
  hash[31] &= 127;
  hash[31] |= 64;
  memcpy (a, hash, sizeof (bn256));

  eddsa_public_key_25519 (pk, a);
  eddsa_sign_25519 ((const uint8_t *)"", 0, r_s, a, hash+32, pk);

  if (memcmp (r, r_expected, sizeof (bn256)) != 0
      || memcmp (s, s_expected, sizeof (bn256)) != 0)
    {
      print_bn256 (r);
      print_bn256 (s);
      return 1;
    }
#else
  ac a0001[1], a0010[1], a0100[1], a1000[1];
  ptc a[1];

  memcpy (a, G, sizeof (ptc));
  ptc_to_ac_25519 (a0001, a);
  compute_and_print_table (a0001, a0010, a0100, a1000);

  memcpy (a, a0001, sizeof (ac));
  memset (a->z, 0, sizeof (bn256));
  a->z->word[0] = 1;
  power_2 (a0001, a, 21);
  compute_and_print_table (a0001, a0010, a0100, a1000);

  memcpy (a, a0001, sizeof (ac));
  memset (a->z, 0, sizeof (bn256));
  a->z->word[0] = 1;
  power_2 (a0001, a, 21);
  compute_and_print_table (a0001, a0010, a0100, a1000);
#endif

  return 0;
}
#endif
