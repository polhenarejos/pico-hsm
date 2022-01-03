#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include <string.h>

int
flash_program_halfword (uintptr_t addr, uint16_t data)
{
  off_t offset;
  uint8_t buf[FLASH_PAGE_SIZE];
  memset(buf, 0, sizeof(uint8_t)*FLASH_PAGE_SIZE);

  buf[0] = (data & 0xff);
  buf[1] = (data >> 8);
  uint32_t ints = save_and_disable_interrupts();
  flash_range_program(addr-XIP_BASE, buf, FLASH_PAGE_SIZE);
  restore_interrupts (ints);
  return 0;
}

static const uint8_t erased[] = { [0 ... 1023 ] = 0xff };

int
flash_erase_page (uintptr_t addr)
{
  uint32_t ints = save_and_disable_interrupts();
  flash_range_erase(addr-XIP_BASE, FLASH_SECTOR_SIZE);
  restore_interrupts (ints);
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
  uint32_t ints = save_and_disable_interrupts();
  flash_range_program(dst_addr-XIP_BASE, src, (len%FLASH_PAGE_SIZE == 0 ? len : ((size_t)(len/FLASH_PAGE_SIZE)+1)*FLASH_PAGE_SIZE));
  restore_interrupts (ints);
}
