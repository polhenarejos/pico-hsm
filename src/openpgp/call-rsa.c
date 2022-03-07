/*
 * call-rsa.c -- Glue code between RSA computation and OpenPGP card protocol
 *
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2017
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

#include "common.h"

//#include <chopstx.h>

#include "config.h"

#include "gnuk.h"
#include "status-code.h"
#include "random.h"
//#include "polarssl/config.h"
#include "mbedtls/rsa.h"
#include "hsm2040.h"

static mbedtls_rsa_context rsa_ctx;
//static struct chx_cleanup clp;

static void
rsa_cleanup (void *arg)
{
  (void)arg;
  mbedtls_rsa_free (&rsa_ctx);
}


int
rsa_sign (const uint8_t *raw_message, uint8_t *output, int msg_len,
	  struct key_data *kd, int pubkey_len)
{
  mbedtls_mpi P1, Q1, H;
  int ret = 0;
  unsigned char temp[pubkey_len];

  mbedtls_rsa_init (&rsa_ctx);

  mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);

  rsa_ctx.len = pubkey_len;
  MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa_ctx.E, 0x10001) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa_ctx.P, &kd->data[0], pubkey_len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa_ctx.Q, &kd->data[pubkey_len / 2],
			    pubkey_len / 2) );
#if 0
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa_ctx.N, &rsa_ctx.P, &rsa_ctx.Q) );
#endif
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa_ctx.P, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa_ctx.Q, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa_ctx.D , &rsa_ctx.E, &H) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa_ctx.DP, &rsa_ctx.D, &P1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa_ctx.DQ, &rsa_ctx.D, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa_ctx.QP, &rsa_ctx.Q, &rsa_ctx.P) );
 cleanup:
  mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  if (ret == 0)
    {
      int cs;

      DEBUG_INFO ("RSA sign...");
      //clp.next = NULL;
      //clp.routine = rsa_cleanup;
      //clp.arg = NULL;
      //chopstx_cleanup_push (&clp);
      //cs = chopstx_setcancelstate (0); /* Allow cancellation.  */
      ret = mbedtls_rsa_rsassa_pkcs1_v15_sign (&rsa_ctx, NULL, NULL,
				       MBEDTLS_MD_NONE,
				       msg_len, raw_message, temp);
      memcpy (output, temp, pubkey_len);
      rsa_cleanup(NULL);
      //chopstx_setcancelstate (cs);
      //chopstx_cleanup_pop (0);
    }

  mbedtls_rsa_free (&rsa_ctx);
  if (ret != 0)
    {
      DEBUG_INFO ("fail:");
      DEBUG_SHORT (ret);
      return -1;
    }
  else
    {
      DEBUG_INFO ("done.\r\n");
      GPG_SUCCESS ();
      return 0;
    }
}

/*
 * LEN: length in byte
 */
int
modulus_calc (const uint8_t *p, int len, uint8_t *pubkey)
{
  mbedtls_mpi P, Q, N;
  int ret;

  mbedtls_mpi_init (&P);  mbedtls_mpi_init (&Q);  mbedtls_mpi_init (&N);
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&P, p, len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&Q, p + len / 2, len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&N, &P, &Q) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&N, pubkey, len) );
 cleanup:
  mbedtls_mpi_free (&P);  mbedtls_mpi_free (&Q);  mbedtls_mpi_free (&N);
  if (ret != 0)
    return -1;

  return 0;
}


int
rsa_decrypt (const uint8_t *input, uint8_t *output, int msg_len,
	     struct key_data *kd, unsigned int *output_len_p)
{
  mbedtls_mpi P1, Q1, H;
  int ret;

  DEBUG_INFO ("RSA decrypt:");
  DEBUG_WORD ((uint32_t)&ret);

  mbedtls_rsa_init (&rsa_ctx);
  mbedtls_mpi_init (&P1);  mbedtls_mpi_init (&Q1);  mbedtls_mpi_init (&H);

  rsa_ctx.len = msg_len;
  DEBUG_WORD (msg_len);

  MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa_ctx.E, 0x10001) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa_ctx.P, &kd->data[0], msg_len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa_ctx.Q, &kd->data[msg_len / 2], msg_len / 2) );
#if 0
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&rsa_ctx.N, &rsa_ctx.P, &rsa_ctx.Q) );
#endif
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&P1, &rsa_ctx.P, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int (&Q1, &rsa_ctx.Q, 1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi (&H, &P1, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa_ctx.D , &rsa_ctx.E, &H) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa_ctx.DP, &rsa_ctx.D, &P1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi (&rsa_ctx.DQ, &rsa_ctx.D, &Q1) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod (&rsa_ctx.QP, &rsa_ctx.Q, &rsa_ctx.P) );
 cleanup:
  mbedtls_mpi_free (&P1);  mbedtls_mpi_free (&Q1);  mbedtls_mpi_free (&H);
  if (ret == 0)
    {
      int cs;

      DEBUG_INFO ("RSA decrypt ...");
      //clp.next = NULL;
      //clp.routine = rsa_cleanup;
      //clp.arg = NULL;
      //chopstx_cleanup_push (&clp);
      //cs = chopstx_setcancelstate (0); /* Allow cancellation.  */
      ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt (&rsa_ctx, NULL, NULL,
					 output_len_p, input,
					 output, MAX_RES_APDU_DATA_SIZE);
      rsa_cleanup(NULL);
      //chopstx_setcancelstate (cs);
      //chopstx_cleanup_pop (0);
    }

  mbedtls_rsa_free (&rsa_ctx);
  if (ret != 0)
    {
      DEBUG_INFO ("fail:");
      DEBUG_SHORT (ret);
      return -1;
    }
  else
    {
      DEBUG_INFO ("done.\r\n");
      GPG_SUCCESS ();
      return 0;
    }
}

int
rsa_verify (const uint8_t *pubkey, int pubkey_len,
	    const uint8_t *hash, const uint8_t *sig)
{
  int ret;

  mbedtls_rsa_init (&rsa_ctx);
  rsa_ctx.len = pubkey_len;
  MBEDTLS_MPI_CHK( mbedtls_mpi_lset (&rsa_ctx.E, 0x10001) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary (&rsa_ctx.N, pubkey, pubkey_len) );

  DEBUG_INFO ("RSA verify...");

  MBEDTLS_MPI_CHK( mbedtls_rsa_rsassa_pkcs1_v15_verify (&rsa_ctx, 
					MBEDTLS_MD_SHA256, 32,
					hash, sig) );
 cleanup:
  mbedtls_rsa_free (&rsa_ctx);
  if (ret != 0)
    {
      DEBUG_INFO ("fail:");
      
      DEBUG_SHORT (ret);
      return -1;
    }
  else
    {
      DEBUG_INFO ("verified.\r\n");
      return 0;
    }
}

#define RSA_EXPONENT 0x10001

struct jkiss_state { uint32_t x, y, z, c; };
static struct jkiss_state jkiss_state_v;


int prng_seed (int (*f_rng)(void *, unsigned char *, size_t),
               void *p_rng)
{
  int ret;

  struct jkiss_state *s = &jkiss_state_v;

  MBEDTLS_MPI_CHK ( f_rng (p_rng, (unsigned char *)s, sizeof (struct jkiss_state)) );
  while (s->y == 0)
    MBEDTLS_MPI_CHK ( f_rng (p_rng, (unsigned char *)&s->y, sizeof (uint32_t)) );
  s->z |= 1;                    /* avoiding z=c=0 */

cleanup:
  return ret;
}


int
rsa_genkey (int pubkey_len, uint8_t *pubkey, uint8_t *p_q)
{
  int ret;
  uint8_t index = 0;
  uint8_t *p = p_q;
  uint8_t *q = p_q + pubkey_len / 2;
  int cs;

  extern void neug_flush (void);

  neug_flush ();
  prng_seed (random_gen, &index);
  mbedtls_rsa_init (&rsa_ctx);

  //clp.next = NULL;
  //clp.routine = rsa_cleanup;
  //clp.arg = NULL;
  //chopstx_cleanup_push (&clp);
  //cs = chopstx_setcancelstate (0); /* Allow cancellation.  */
  MBEDTLS_MPI_CHK( mbedtls_rsa_gen_key (&rsa_ctx, random_gen, &index, pubkey_len * 8,
			RSA_EXPONENT) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&rsa_ctx.P, p, pubkey_len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&rsa_ctx.Q, q, pubkey_len / 2) );
  MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary (&rsa_ctx.N, pubkey, pubkey_len) );

 cleanup:
  //chopstx_setcancelstate (cs);
  //chopstx_cleanup_pop (1);
  rsa_cleanup(NULL);
  if (ret != 0)
    return -1;
  else
    return 0;
}
