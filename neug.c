/*
 * neug.c - true random number generation
 *
 * Copyright (C) 2011, 2012, 2013, 2016, 2017, 2018
 *               Free Software Initiative of Japan
 * Author: NIIBE Yutaka <gniibe@fsij.org>
 *
 * This file is a part of NeuG, a True Random Number Generator
 * implementation based on quantization error of ADC (for STM32F103).
 *
 * NeuG is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NeuG is distributed in the hope that it will be useful, but WITHOUT
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
#include <stdio.h>
#include "pico/stdlib.h"
//#include <chopstx.h>

#include "sys.h"
#include "neug.h"
//#include "adc.h"
#include "sha256.h"
#include "gnuk.h"
#include "hardware/structs/rosc.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "bsp/board.h"

void adc_start () 
{
    adc_init();
    adc_gpio_init(27);
    adc_select_input(1);
}

void
adc_stop (void)
{
}

static uint64_t random_word = 0xcbf29ce484222325;
static uint8_t ep_round = 0;

static void ep_init (int mode)
{
  random_word = 0xcbf29ce484222325;
  ep_round = 0;
}

/* Here, we assume a little endian architecture.  */
static int ep_process (int mode)
{
  
    if (ep_round == 0)
    {
        ep_init(mode);
    }
    uint64_t word = 0x0;
    for (int n = 0; n < 64; n++) {
        uint8_t bit1, bit2;
        do
        {
            bit1 = rosc_hw->randombit&0xff;
            //sleep_ms(1);
            bit2 = rosc_hw->randombit&0xff;
        } while(bit1 == bit2);
        word = (word << 1) | bit1;
    }
    random_word ^= word^board_millis()^adc_read();
    random_word *= 0x00000100000001B3;
    if (++ep_round == 8)
    {
        ep_round = 0;
        return 2; //2 words 
    }
    return 0;
}


static const uint32_t *ep_output (int mode)
{
    (void) mode;
    return (uint32_t *)&random_word;
}

/*
 * Ring buffer, filled by generator, consumed by neug_get routine.
 */
struct rng_rb {
  uint32_t *buf;
  //chopstx_mutex_t m;
  //chopstx_cond_t data_available;
  //chopstx_cond_t space_available;
  uint8_t head, tail;
  uint8_t size;
  unsigned int full :1;
  unsigned int empty :1;
};

static void rb_init (struct rng_rb *rb, uint32_t *p, uint8_t size)
{
  rb->buf = p;
  rb->size = size;
  //chopstx_mutex_init (&rb->m);
  //chopstx_cond_init (&rb->data_available);
  //chopstx_cond_init (&rb->space_available);
  rb->head = rb->tail = 0;
  rb->full = 0;
  rb->empty = 1;
}

static void rb_add (struct rng_rb *rb, uint32_t v)
{
  rb->buf[rb->tail++] = v;
  if (rb->tail == rb->size)
    rb->tail = 0;
  if (rb->tail == rb->head)
    rb->full = 1;
  rb->empty = 0;
}

static uint32_t rb_del (struct rng_rb *rb)
{
  uint32_t v = rb->buf[rb->head++];

  if (rb->head == rb->size)
    rb->head = 0;
  if (rb->head == rb->tail)
    rb->empty = 1;
  rb->full = 0;

  return v;
}

uint8_t neug_mode;
static int rng_should_terminate;

static struct rng_rb the_ring_buffer;
//static chopstx_t rng_thread;


/**
 * @brief Random number generation thread.
 */
void *
neug_task ()
{
  struct rng_rb *rb = &the_ring_buffer;
  int mode = neug_mode;

  rng_should_terminate = 0;
  //chopstx_mutex_init (&mode_mtx);
  //chopstx_cond_init (&mode_cond);

  //while (!rng_should_terminate)
    {
        int n;

        if ((n = ep_process (mode)))
    	{
    	  int i;
    	  const uint32_t *vp;
    
    	  vp = ep_output (mode);
    
    	  //chopstx_mutex_lock (&rb->m);
    	  //while (rb->full)
    	    //chopstx_cond_wait (&rb->space_available, &rb->m);
    
    	  for (i = 0; i < n; i++)
    	    {
    	      rb_add (rb, *vp++);
    	      if (rb->full)
    		break;
    	    }
    
    	  //chopstx_cond_signal (&rb->data_available);
    	  //chopstx_mutex_unlock (&rb->m);
    	}
    }

  //adc_stop ();

  return NULL;
}

/**
 * @brief Initialize NeuG.
 */
void
neug_init (uint32_t *buf, uint8_t size)
{
  const uint32_t *u = (const uint32_t *)unique_device_id ();
  struct rng_rb *rb = &the_ring_buffer;
  int i;


  /*
   * This initialization ensures that it generates different sequence
   * even if all physical conditions are same.
   */

  neug_mode = NEUG_MODE_CONDITIONED;
  rb_init (rb, buf, size);
  
  /* Enable ADCs */
  adc_start ();

  ep_init (neug_mode);

  //rng_thread = chopstx_create (PRIO_RNG, STACK_ADDR_RNG, STACK_SIZE_RNG,
	//		       rng, rb);
}

/**
 * @breif Flush random bytes.
 */
void
neug_flush (void)
{
  struct rng_rb *rb = &the_ring_buffer;

  //chopstx_mutex_lock (&rb->m);
  while (!rb->empty)
    (void)rb_del (rb);
  //chopstx_cond_signal (&rb->space_available);
  //chopstx_mutex_unlock (&rb->m);
}



/**
 * @brief  Get random word (32-bit) from NeuG.
 * @detail With NEUG_KICK_FILLING, it wakes up RNG thread.
 *         With NEUG_NO_KICK, it doesn't wake up RNG thread automatically,
 *         it is needed to call neug_kick_filling later.
 */
uint32_t
neug_get (int kick)
{
  struct rng_rb *rb = &the_ring_buffer;
  uint32_t v;

  //chopstx_mutex_lock (&rb->m);
  while (rb->empty)
    neug_task(); //chopstx_cond_wait (&rb->data_available, &rb->m);
  v = rb_del (rb);
  //if (kick)
    //chopstx_cond_signal (&rb->space_available);
  //chopstx_mutex_unlock (&rb->m);

  return v;
}

int
neug_get_nonblock (uint32_t *p)
{
  struct rng_rb *rb = &the_ring_buffer;
  int r = 0;

  //chopstx_mutex_lock (&rb->m);
  if (rb->empty)
    {
      r = -1;
      //chopstx_cond_signal (&rb->space_available);
    }
  else
    *p = rb_del (rb);
  //chopstx_mutex_unlock (&rb->m);

  return r;
}

int neug_consume_random (void (*proc) (uint32_t, int))
{
  int i = 0;
  struct rng_rb *rb = &the_ring_buffer;

  //chopstx_mutex_lock (&rb->m);
  while (!rb->empty)
    {
      uint32_t v;

      v = rb_del (rb);
      proc (v, i);
      i++;
    }
  //chopstx_cond_signal (&rb->space_available);
  //chopstx_mutex_unlock (&rb->m);

  return i;
}

void
neug_wait_full (void)
{
  struct rng_rb *rb = &the_ring_buffer;

  //chopstx_mutex_lock (&rb->m);
  while (!rb->full)
    neug_task(); //chopstx_cond_wait (&rb->data_available, &rb->m);
  //chopstx_mutex_unlock (&rb->m);
}

void
neug_fini (void)
{
  rng_should_terminate = 1;
  neug_get (1);
  //chopstx_join (rng_thread, NULL);
}

void
neug_mode_select (uint8_t mode)
{
  if (neug_mode == mode)
    return;

  neug_wait_full ();

  //chopstx_mutex_lock (&mode_mtx);
  neug_mode = mode;
  neug_flush ();
  //chopstx_cond_wait (&mode_cond, &mode_mtx);
  //chopstx_mutex_unlock (&mode_mtx);

  neug_wait_full ();
  neug_flush ();
}
