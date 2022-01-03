/*
 * sha512.c -- Compute SHA-512 hash (for little endian architecture).
 *
 * This module is written by gniibe, following the API of sha256.c.
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
 * Reference:
 *
 * [1] FIPS PUB 180-4: Secure hash Standard (SHS), March, 2012.
 *
 */

#include <string.h>
#include <stdint.h>
#include "sha512.h"

#define SHA512_MASK (SHA512_BLOCK_SIZE - 1)

static void memcpy_output_bswap64 (unsigned char dst[64], const uint64_t *p)
{
  int i;
  uint64_t q = 0;

  for (i = 0; i < 64; i++)
    {
      if ((i & 7) == 0)
	q = __builtin_bswap64 (p[i >> 3]); /* bswap64 is GCC extention */
      dst[i] = q >> ((i & 7) * 8);
    }
}

#define rotr64(x,n)   (((x) >> n) | ((x) << (64 - n)))

#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

/* round transforms for SHA512 compression functions */
#define vf(n,i) v[(n - i) & 7]

#define hf(i) (p[i & 15] += \
    g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]))

#define v_cycle0(i)                                 \
    p[i] = __builtin_bswap64 (p[i]);                \
    vf(7,i) += p[i] + k_0[i]                        \
    + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
    vf(3,i) += vf(7,i);                             \
    vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define v_cycle(i, j)                               \
    vf(7,i) += hf(i) + k_0[i+j]                     \
    + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
    vf(3,i) += vf(7,i);                             \
    vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define s_0(x)  (rotr64((x), 28) ^ rotr64((x), 34) ^ rotr64((x), 39))
#define s_1(x)  (rotr64((x), 14) ^ rotr64((x), 18) ^ rotr64((x), 41))
#define g_0(x)  (rotr64((x),  1) ^ rotr64((x),  8) ^ ((x) >>  7))
#define g_1(x)  (rotr64((x), 19) ^ rotr64((x), 61) ^ ((x) >>  6))
#define k_0     k512

/* Taken from section 4.2.3 of [1].  */
static const uint64_t k512[80] = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void
sha512_process (sha512_context *ctx)
{
  uint32_t i;
  uint64_t *p = ctx->wbuf;
  uint64_t v[8];

  memcpy (v, ctx->state, 8 * sizeof (uint64_t));

  v_cycle0 ( 0); v_cycle0 ( 1); v_cycle0 ( 2); v_cycle0 ( 3);
  v_cycle0 ( 4); v_cycle0 ( 5); v_cycle0 ( 6); v_cycle0 ( 7);
  v_cycle0 ( 8); v_cycle0 ( 9); v_cycle0 (10); v_cycle0 (11);
  v_cycle0 (12); v_cycle0 (13); v_cycle0 (14); v_cycle0 (15);

  for (i = 16; i < 80; i += 16)
    {
      v_cycle ( 0, i); v_cycle ( 1, i); v_cycle ( 2, i); v_cycle ( 3, i);
      v_cycle ( 4, i); v_cycle ( 5, i); v_cycle ( 6, i); v_cycle ( 7, i);
      v_cycle ( 8, i); v_cycle ( 9, i); v_cycle (10, i); v_cycle (11, i);
      v_cycle (12, i); v_cycle (13, i); v_cycle (14, i); v_cycle (15, i);
    }

  ctx->state[0] += v[0];
  ctx->state[1] += v[1];
  ctx->state[2] += v[2];
  ctx->state[3] += v[3];
  ctx->state[4] += v[4];
  ctx->state[5] += v[5];
  ctx->state[6] += v[6];
  ctx->state[7] += v[7];
}

void
sha512_update (sha512_context *ctx, const unsigned char *input,
               unsigned int ilen)
{
  uint32_t left = (ctx->total[0] & SHA512_MASK);
  uint32_t fill = SHA512_BLOCK_SIZE - left;

  ctx->total[0] += ilen;
  if (ctx->total[0] < ilen)
    ctx->total[1]++;

  while (ilen >= fill)
    {
      memcpy (((unsigned char*)ctx->wbuf) + left, input, fill);
      sha512_process (ctx);
      input += fill;
      ilen -= fill;
      left = 0;
      fill = SHA512_BLOCK_SIZE;
    }

  memcpy (((unsigned char*)ctx->wbuf) + left, input, ilen);
}

void
sha512_finish (sha512_context *ctx, unsigned char output[64])
{
  uint32_t last = (ctx->total[0] & SHA512_MASK);

  ctx->wbuf[last >> 3] = __builtin_bswap64 (ctx->wbuf[last >> 3]);
  ctx->wbuf[last >> 3] &= 0xffffffffffffff80LL << (8 * (~last & 7));
  ctx->wbuf[last >> 3] |= 0x0000000000000080LL << (8 * (~last & 7));
  ctx->wbuf[last >> 3] = __builtin_bswap64 (ctx->wbuf[last >> 3]);

  if (last > SHA512_BLOCK_SIZE - 17)
    {
      if (last < 120)
        ctx->wbuf[15] = 0;
      sha512_process (ctx);
      last = 0;
    }
  else
    last = (last >> 3) + 1;

  while (last < 14)
    ctx->wbuf[last++] = 0;

  ctx->wbuf[14] = __builtin_bswap64 ((ctx->total[0] >> 61) | (ctx->total[1] << 3));
  ctx->wbuf[15] = __builtin_bswap64 (ctx->total[0] << 3);
  sha512_process (ctx);

  memcpy_output_bswap64 (output, ctx->state);
  memset (ctx, 0, sizeof (sha512_context));
}

/* Taken from section 5.3.5 of [1].  */
static const uint64_t initial_state[8] = {
0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

void
sha512_start (sha512_context *ctx)
{
  ctx->total[0] = ctx->total[1] = 0;
  memcpy (ctx->state, initial_state, 8 * sizeof(uint64_t));
}

void
sha512 (const unsigned char *input, unsigned int ilen,
        unsigned char output[64])
{
  sha512_context ctx;

  sha512_start (&ctx);
  sha512_update (&ctx, input, ilen);
  sha512_finish (&ctx, output);
}
