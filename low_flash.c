#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/mutex.h"
#include "pico/multicore.h"
#include "gnuk.h"
#include <string.h>

#define TOTAL_FLASH_PAGES 4

typedef struct PageFlash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
} PageFlash_t;

static PageFlash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;

static uint8_t ready_pages = 0;

bool flash_available = false;


//this function has to be called from the core 0
void do_flash()
{
    if (mutex_try_enter(&mtx_flash, NULL) == true)
    {
        if (flash_available == true && ready_pages > 0)
        {
            //printf(" DO_FLASH AVAILABLE\r\n");
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++)
            {
                if (flash_pages[r].ready == true)
                {
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
                else if (flash_pages[r].erase == true) 
                {
                    while (multicore_lockout_start_timeout_us(1000) == false);
                    printf("WRITTING\r\n");
                    flash_range_erase(flash_pages[r].address-XIP_BASE, FLASH_SECTOR_SIZE);
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
}

//this function has to be called from the core 0
void low_flash_init()
{
    mutex_init(&mtx_flash);
    memset(flash_pages, 0, sizeof(PageFlash_t)*TOTAL_FLASH_PAGES);
}

void low_flash_available()
{
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

int
flash_program_halfword (uintptr_t addr, uint16_t data)
{
    off_t offset;
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    PageFlash_t *p = NULL;
    if (ready_pages == TOTAL_FLASH_PAGES) {
        DEBUG_INFO("ERROR: ALL FLASH PAGES CACHED\r\n");
        return 1;
    }
    mutex_enter_blocking(&mtx_flash);

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
            break;
        }
    }

    if (!p)
    {
        DEBUG_INFO("ERROR: FLASH CANNOT FIND A PAGE (rare error)\r\n");
        mutex_exit(&mtx_flash);
        return 1;
    }
    
    p->page[addr&(FLASH_SECTOR_SIZE-1)] = (data & 0xff);
    p->page[(addr&(FLASH_SECTOR_SIZE-1))+1] = (data >> 8);
    //printf("Flash: modified page %X with data %x %x at [%x-%x] (top page %X)\r\n",addr_alg,(data & 0xff),data>>8,addr&(FLASH_SECTOR_SIZE-1),(addr&(FLASH_SECTOR_SIZE-1))+1,addr);
    mutex_exit(&mtx_flash);
    return 0;
}

int
flash_erase_page (uintptr_t addr)
{
    /*
    uintptr_t addr_alg = addr & -FLASH_SECTOR_SIZE;
    PageFlash_t *p = NULL;
    if (ready_pages == TOTAL_FLASH_PAGES) {
        DEBUG_INFO("ERROR: ALL FLASH PAGES CACHED\r\n");
        return 1;
    }
    mutex_enter_blocking(&mtx_flash);

    for (int r = 0; r < TOTAL_FLASH_PAGES; r++)
    {
        if ((!flash_pages[r].ready && !flash_pages[r].erase) || flash_pages[r].address == addr_alg) //first available
        {
            p = &flash_pages[r];
            if (!flash_pages[r].ready && !flash_pages[r].erase)
            {
                ready_pages++;
                p->address = addr_alg;
            }
            p->erase = true;
            break;
        }
    }

    if (!p)
    {
        DEBUG_INFO("ERROR: FLASH CANNOT FIND A PAGE (rare error)\r\n");
        mutex_exit(&mtx_flash);
        return 1;
    }
    mutex_exit(&mtx_flash);
    */
    return 0;
}

int
flash_check_blank (const uint8_t *p_start, size_t size)
{
  const uint8_t *p;

  for (p = p_start; p < p_start + size; p++)
    if (*p != 0xff)
      return 0;

  return 1;
}

int
flash_write (uintptr_t dst_addr, const uint8_t *src, size_t len)
{
    size_t len_alg = (len + (FLASH_SECTOR_SIZE - 1)) & -FLASH_SECTOR_SIZE;
    uintptr_t add_alg = dst_addr & -FLASH_SECTOR_SIZE;
    printf("WRITE ATTEMPT %X (%d) %X (%d)\r\n",dst_addr,len,add_alg,len_alg);
  uint32_t ints = save_and_disable_interrupts();
  flash_range_program(add_alg-XIP_BASE, src, len_alg);
  restore_interrupts (ints);
}
