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


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/mutex.h"
#include "pico/sem.h"
#include "pico/multicore.h"
#include "hsm2040.h"
#include "sc_hsm.h"
#include <string.h>

#define TOTAL_FLASH_PAGES 4

typedef struct page_flash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
    size_t page_size; //this param is for easy erase. It allows to erase with a single call. IT DOES NOT APPLY TO WRITE
} page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;
static semaphore_t sem_wait;

static uint8_t ready_pages = 0;

bool flash_available = false;
static bool locked_out = false;


//this function has to be called from the core 0
void do_flash()
{
    if (mutex_try_enter(&mtx_flash, NULL) == true) {
        if (locked_out == true && flash_available == true && ready_pages > 0) {
            //printf(" DO_FLASH AVAILABLE\r\n");
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
                if (flash_pages[r].ready == true) {
                    //printf("WRITTING %X\r\n",flash_pages[r].address-XIP_BASE);
                    while (multicore_lockout_start_timeout_us(1000) == false);
                    //printf("WRITTING %X\r\n",flash_pages[r].address-XIP_BASE);
                    uint32_t ints = save_and_disable_interrupts();
                    flash_range_erase(flash_pages[r].address-XIP_BASE, FLASH_SECTOR_SIZE);
                    flash_range_program(flash_pages[r].address-XIP_BASE, flash_pages[r].page, FLASH_SECTOR_SIZE);
                    restore_interrupts (ints);
                    while (multicore_lockout_end_timeout_us(1000) == false);
                    //printf("WRITEN %X !\r\n",flash_pages[r].address);                    
                    
                    flash_pages[r].ready = false;
                    ready_pages--;
                }
                else if (flash_pages[r].erase == true) {
                    while (multicore_lockout_start_timeout_us(1000) == false);
                    //printf("WRITTING\r\n");
                    flash_range_erase(flash_pages[r].address-XIP_BASE, flash_pages[r].page_size ? ((int)(flash_pages[r].page_size/FLASH_SECTOR_SIZE))*FLASH_SECTOR_SIZE : FLASH_SECTOR_SIZE);
                    while (multicore_lockout_end_timeout_us(1000) == false);
                    flash_pages[r].erase = false;
                    ready_pages--;
                }
            }
            flash_available = false;
            if (ready_pages != 0) {
                DEBUG_INFO("ERROR: DO FLASH DOES NOT HAVE ZERO PAGES");
            }
        }
        mutex_exit(&mtx_flash);
    }
    sem_release(&sem_wait);
}

//this function has to be called from the core 0
void low_flash_init() {
    mutex_init(&mtx_flash);
    sem_init(&sem_wait, 0, 1);
    memset(flash_pages, 0, sizeof(page_flash_t)*TOTAL_FLASH_PAGES);
}

void low_flash_init_core1() {
    mutex_enter_blocking(&mtx_flash);
    multicore_lockout_victim_init();
    locked_out = true;
    mutex_exit(&mtx_flash);
}

void wait_flash_finish() {
    sem_acquire_blocking(&sem_wait); //blocks until released
    //wake up
    sem_acquire_blocking(&sem_wait); //decrease permits
}

void low_flash_available() {
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    page_flash_t *p = NULL;
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++)
    {
        if ((!flash_pages[r].ready && !flash_pages[r].erase) || flash_pages[r].address == addr_alg) //first available
        {
            p = &flash_pages[r];
            if (!flash_pages[r].ready && !flash_pages[r].erase)
            {
                memcpy(p->page, (uint8_t *)addr_alg, FLASH_SECTOR_SIZE);
                ready_pages++;
                p->address = addr_alg;
                p->ready = true;
            }
            return p;
        }
    }
    return NULL;
}

int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    page_flash_t *p = NULL;
    
    if (!data || len == 0)
        return HSM_ERR_NULL_PARAM;
    
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages == TOTAL_FLASH_PAGES) {
        mutex_exit(&mtx_flash);
        DEBUG_INFO("ERROR: ALL FLASH PAGES CACHED\r\n");
        return HSM_ERR_NO_MEMORY;
    }
    if (!(p = find_free_page(addr)))
    {
        mutex_exit(&mtx_flash);
        DEBUG_INFO("ERROR: FLASH CANNOT FIND A PAGE (rare error)\r\n");
        return HSM_ERR_MEMORY_FATAL;
    }
    memcpy(&p->page[addr&(FLASH_SECTOR_SIZE-1)], data, len);
    //printf("Flash: modified page %X with data %x at [%x] (top page %X)\r\n",addr_alg,data,addr&(FLASH_SECTOR_SIZE-1),addr);
    mutex_exit(&mtx_flash);
    return HSM_OK;
}

int flash_program_halfword (uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, (const uint8_t *)&data, sizeof(uint16_t));
}

int flash_program_word (uintptr_t addr, uint32_t data) {
    return flash_program_block(addr,  (const uint8_t *)&data, sizeof(uint32_t));
}

int flash_program_uintptr (uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr,  (const uint8_t *)&data, sizeof(uintptr_t));
}

uint8_t *flash_read(uintptr_t addr) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;   
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++)
        {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr&(FLASH_SECTOR_SIZE-1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    uint8_t *v = (uint8_t *)addr;
    mutex_exit(&mtx_flash);
    return v;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uintptr_t v = 0x0;
    for (int i = 0; i < sizeof(uintptr_t); i++) {
        v |= (uintptr_t)p[i]<<(8*i);
    }
    return v;
}
uint16_t flash_read_uint16(uintptr_t addr) {
    uint8_t *p = flash_read(addr);
    uint16_t v = 0x0;
    for (int i = 0; i < sizeof(uint16_t); i++) {
        v |= p[i]<<(8*i);
    }
    return v;
}
uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page (uintptr_t addr, size_t page_size) {
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    page_flash_t *p = NULL;
    
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages == TOTAL_FLASH_PAGES) {
        mutex_exit(&mtx_flash);
        DEBUG_INFO("ERROR: ALL FLASH PAGES CACHED\r\n");
        return HSM_ERR_NO_MEMORY;
    }
    if (!(p = find_free_page(addr))) {
        DEBUG_INFO("ERROR: FLASH CANNOT FIND A PAGE (rare error)\r\n");
        mutex_exit(&mtx_flash);
        return HSM_ERR_MEMORY_FATAL;
    }
    p->erase = true;
    p->ready = false;
    p->page_size = page_size;
    mutex_exit(&mtx_flash);
    
    return HSM_OK;
}

bool flash_check_blank(const uint8_t *p_start, size_t size)
{
    const uint8_t *p;

    for (p = p_start; p < p_start + size; p++) {
        if (*p != 0xff)
            return false;
    }
    return true;
}
