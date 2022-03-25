/* 
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
//Part of the code is taken from GnuK (GPLv3)


#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"

#include "neug.h"
#include "hardware/structs/rosc.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "bsp/board.h"
#include "pico/unique_id.h"

void adc_start() {
    adc_init();
    adc_gpio_init(27);
    adc_select_input(1);
}

void adc_stop() {
}

static uint64_t random_word = 0xcbf29ce484222325;
static uint8_t ep_round = 0;

static void ep_init() {
    random_word = 0xcbf29ce484222325;
    ep_round = 0;
}

/* Here, we assume a little endian architecture.  */
static int ep_process () {
    if (ep_round == 0) {
        ep_init();
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
    if (++ep_round == 8) {
        ep_round = 0;
        return 2; //2 words 
    }
    return 0;
}

static const uint32_t *ep_output() {
    return (uint32_t *)&random_word;
}

struct rng_rb {
    uint32_t *buf;
    uint8_t head, tail;
    uint8_t size;
    unsigned int full :1;
    unsigned int empty :1;
};

static void rb_init(struct rng_rb *rb, uint32_t *p, uint8_t size) {
    rb->buf = p;
    rb->size = size;
    rb->head = rb->tail = 0;
    rb->full = 0;
    rb->empty = 1;
}

static void rb_add(struct rng_rb *rb, uint32_t v) {
    rb->buf[rb->tail++] = v;
    if (rb->tail == rb->size)
        rb->tail = 0;
    if (rb->tail == rb->head)
        rb->full = 1;
    rb->empty = 0;
}

static uint32_t rb_del(struct rng_rb *rb) {
    uint32_t v = rb->buf[rb->head++];

    if (rb->head == rb->size)
        rb->head = 0;
    if (rb->head == rb->tail)
        rb->empty = 1;
    rb->full = 0;

    return v;
}

static struct rng_rb the_ring_buffer;

void *neug_task() {
    struct rng_rb *rb = &the_ring_buffer;
 
    int n;

    if ((n = ep_process())) {
	    int i;
	    const uint32_t *vp;

	    vp = ep_output();

	    for (i = 0; i < n; i++) {
	        rb_add (rb, *vp++);
	        if (rb->full)
		        break;
	    }
	}

    return NULL;
}

void neug_init(uint32_t *buf, uint8_t size) {
    pico_unique_board_id_t unique_id;
    pico_get_unique_board_id(&unique_id);
    const uint32_t *u = (const uint32_t *)unique_id.id;
    struct rng_rb *rb = &the_ring_buffer;
    int i;

    rb_init(rb, buf, size);
    
    adc_start();
    
    ep_init();
}

void neug_flush(void) {
    struct rng_rb *rb = &the_ring_buffer;
    
    while (!rb->empty)
        rb_del (rb);
}

uint32_t neug_get(int kick) {
    struct rng_rb *rb = &the_ring_buffer;
    uint32_t v;

    while (rb->empty)
        neug_task();
    v = rb_del(rb);

    return v;
}

void neug_wait_full(void) { //should be called only on core1
    struct rng_rb *rb = &the_ring_buffer;

    while (!rb->full) {
        sleep_ms(1);
    }
}

void neug_fini(void) {
    neug_get(1);
}

