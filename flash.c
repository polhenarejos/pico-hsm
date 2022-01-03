/*
 * flash.c -- Data Objects (DO) and GPG Key handling on Flash ROM
 *
 * Copyright (C) 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018
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

/*
 * We assume single DO size is less than 256.
 *
 * NOTE: "Card holder certificate" (which size is larger than 256) is
 *       not put into data pool, but is implemented by its own flash
 *       page(s).
 */

#include <stdint.h>
#include <string.h>

#include "config.h"

#include "sys.h"
#include "gnuk.h"

#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "tusb.h"

/*
 * Flash memory map
 *
 * _text
 *         .text
 *         .ctors
 *         .dtors
 * _etext
 *         .data
 * _bss_start
 *         .bss
 * _end
 *         <alignment to page>
 * ch_certificate_startp
 *         <2048 bytes>
 * _keystore_pool
 *         Three flash pages for keystore
 *         a page contains a key data of:
 *              For RSA-2048: 512-byte (p, q and N)
 *              For RSA-4096: 1024-byte (p, q and N)
 *              For ECDSA/ECDH and EdDSA, there are padding after public key
 * _data_pool
 *	   <two pages>
 */

#define FLASH_DATA_POOL_HEADER_SIZE	2
#define FLASH_DATA_POOL_SIZE		(2048*1024)

static uint16_t flash_page_size;
static const uint8_t *data_pool;
static uint8_t *last_p;

/* The first halfword is generation for the data page (little endian) */
const uint8_t flash_data[4] __attribute__ ((section (".gnuk_data"))) = {
  0x00, 0x00, 0xff, 0xff
};

#define FLASH_TARGET_OFFSET (4096 * 1024) // DATA starts at the mid of flash


const uint8_t *flash_addr_key_storage_start = (const uint8_t *) (XIP_BASE + FLASH_TARGET_OFFSET);
const uint8_t *flash_addr_data_storage_start = (const uint8_t *) (XIP_BASE + FLASH_TARGET_OFFSET + 2048 * 1024); // 2 MB 
const uint8_t *ch_certificate_start = (const uint8_t *) (XIP_BASE + FLASH_TARGET_OFFSET - FLASH_SECTOR_SIZE);
#define FLASH_ADDR_KEY_STORAGE_START  flash_addr_key_storage_start
#define FLASH_ADDR_DATA_STORAGE_START flash_addr_data_storage_start

extern int flash_erase_page (uintptr_t addr);
extern int flash_program_halfword (uintptr_t addr, uint16_t data);
extern int flash_check_blank (const uint8_t *p_start, size_t size);
extern int flash_write (uintptr_t dst_addr, const uint8_t *src, size_t len);

static int key_available_at (const uint8_t *k, int key_size)
{
  int i;

  for (i = 0; i < key_size; i++)
    if (k[i])
      break;
  if (i == key_size)	/* It's ZERO.  Released key.  */
    return 0;

  for (i = 0; i < key_size; i++)
    if (k[i] != 0xff)
      break;
  if (i == key_size)	/* It's FULL.  Unused key.  */
    return 0;

  return 1;
}

void
flash_do_storage_init (const uint8_t **p_do_start, const uint8_t **p_do_end)
{
  uint16_t gen0, gen1;
  uint16_t *gen0_p = (uint16_t *)FLASH_ADDR_DATA_STORAGE_START;
  uint16_t *gen1_p;

  flash_page_size = FLASH_SECTOR_SIZE;

  gen1_p = (uint16_t *)(FLASH_ADDR_DATA_STORAGE_START + flash_page_size);
  data_pool = FLASH_ADDR_DATA_STORAGE_START;

  /* Check data pool generation and choose the page */
  gen0 = *gen0_p;
  gen1 = *gen1_p;

  if (gen0 == 0xffff && gen1 == 0xffff)
    {
      /* It's terminated.  */
      *p_do_start = *p_do_end = NULL;
      return;
    }

  if (gen0 == 0xffff)
    /* Use another page if a page is erased.  */
    data_pool = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
  else if (gen1 == 0xffff)
    /* Or use different page if another page is erased.  */
    data_pool = FLASH_ADDR_DATA_STORAGE_START;
  else if ((gen0 == 0xfffe && gen1 == 0) || gen1 > gen0)
    /* When both pages have valid header, use newer page.   */
    data_pool = FLASH_ADDR_DATA_STORAGE_START + flash_page_size;

  *p_do_start = data_pool + FLASH_DATA_POOL_HEADER_SIZE;
  *p_do_end = data_pool + flash_page_size;
}

static uint8_t *flash_key_getpage (enum kind_of_key kk);

void
flash_terminate (void)
{
  int i;

  for (i = 0; i < 3; i++)
    flash_erase_page ((uintptr_t)flash_key_getpage (i));
  flash_erase_page ((uintptr_t)FLASH_ADDR_DATA_STORAGE_START);
  flash_erase_page ((uintptr_t)(FLASH_ADDR_DATA_STORAGE_START + flash_page_size));
  data_pool = FLASH_ADDR_DATA_STORAGE_START;
  last_p = (uint8_t *)FLASH_ADDR_DATA_STORAGE_START + FLASH_DATA_POOL_HEADER_SIZE;
#if defined(CERTDO_SUPPORT)
  flash_erase_page ((uintptr_t)ch_certificate_start);
  if (FLASH_CH_CERTIFICATE_SIZE > flash_page_size)
    flash_erase_page ((uintptr_t)(ch_certificate_start + flash_page_size));
#endif
}

void
flash_activate (void)
{
  flash_program_halfword ((uintptr_t)FLASH_ADDR_DATA_STORAGE_START, 0);
}


void
flash_key_storage_init (void)
{
  const uint8_t *p;
  int i;

  /* For each key, find its address.  */
  p = FLASH_ADDR_KEY_STORAGE_START;
  for (i = 0; i < 3; i++)
    {
      const uint8_t *k;
      int key_size = gpg_get_algo_attr_key_size (i, GPG_KEY_STORAGE);

      kd[i].pubkey = NULL;
      for (k = p; k < p + flash_page_size; k += key_size)
	if (key_available_at (k, key_size))
	  {
	    int prv_len = gpg_get_algo_attr_key_size (i, GPG_KEY_PRIVATE);

	    kd[i].pubkey = k + prv_len;
	    break;
	  }

      p += flash_page_size;
    }
}

/*
 * Flash data pool managenent
 *
 * Flash data pool consists of two parts:
 *   2-byte header
 *   contents
 *
 * Flash data pool objects:
 *   Data Object (DO) (of smart card)
 *   Internal objects:
 *     NONE (0x0000)
 *     123-counter
 *     14-bit counter
 *     bool object
 *     small enum
 *
 * Format of a Data Object:
 *    NR:   8-bit tag_number
 *    LEN:  8-bit length
 *    DATA: data * LEN
 *    PAD:  optional byte for 16-bit alignment
 */

void
flash_set_data_pool_last (const uint8_t *p)
{
  last_p = (uint8_t *)p;
}

/*
 * We use two pages
 */
static int
flash_copying_gc (void)
{
  uint8_t *src, *dst;
  uint16_t generation;

  if (data_pool == FLASH_ADDR_DATA_STORAGE_START)
    {
      src = (uint8_t *)FLASH_ADDR_DATA_STORAGE_START;
      dst = (uint8_t *)FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
    }
  else
    {
      src = (uint8_t *)FLASH_ADDR_DATA_STORAGE_START + flash_page_size;
      dst = (uint8_t *)FLASH_ADDR_DATA_STORAGE_START;
    }

  generation = *(uint16_t *)src;
  data_pool = dst;
  gpg_data_copy (data_pool + FLASH_DATA_POOL_HEADER_SIZE);
  if (generation == 0xfffe)
    generation = 0;
  else
    generation++;
  flash_program_halfword ((uintptr_t)dst, generation);
  flash_erase_page ((uintptr_t)src);
  return 0;
}

static int
is_data_pool_full (size_t size)
{
  return last_p + size > data_pool + flash_page_size;
}

static uint8_t *
flash_data_pool_allocate (size_t size)
{
  uint8_t *p;

  size = (size + 1) & ~1;	/* allocation unit is 1-halfword (2-byte) */

  if (is_data_pool_full (size))
    if (flash_copying_gc () < 0 || /*still*/ is_data_pool_full (size))
      TU_LOG1 ("!!!! FATAL: %d\r\n",FATAL_FLASH);

  p = last_p;
  last_p += size;
  return p;
}

void
flash_do_write_internal (const uint8_t *p, int nr, const uint8_t *data, int len)
{
  uint16_t hw;
  uintptr_t addr;
  int i;

  addr = (uintptr_t)p;
  hw = nr | (len << 8);
  if (flash_program_halfword (addr, hw) != 0)
    flash_warning ("DO WRITE ERROR");
  addr += 2;

  for (i = 0; i < len/2; i++)
    {
      hw = data[i*2] | (data[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	flash_warning ("DO WRITE ERROR");
      addr += 2;
    }

  if ((len & 1))
    {
      hw = data[i*2] | 0xff00;
      if (flash_program_halfword (addr, hw) != 0)
	flash_warning ("DO WRITE ERROR");
    }
}

const uint8_t *
flash_do_write (uint8_t nr, const uint8_t *data, int len)
{
  const uint8_t *p;

  DEBUG_INFO ("flash DO\r\n");

  p = flash_data_pool_allocate (2 + len);
  if (p == NULL)
    {
      DEBUG_INFO ("flash data pool allocation failure.\r\n");
      return NULL;
    }

  flash_do_write_internal (p, nr, data, len);
  DEBUG_INFO ("flash DO...done\r\n");
  return p + 1;
}

void
flash_warning (const char *msg)
{
  (void)msg;
  DEBUG_INFO ("FLASH: ");
  DEBUG_INFO (msg);
  DEBUG_INFO ("\r\n");
}

void
flash_do_release (const uint8_t *do_data)
{
  uintptr_t addr = (uintptr_t)do_data - 1;
  uintptr_t addr_tag = addr;
  int i;
  int len = do_data[0];

  /* Don't filling zero for data in code (such as ds_count_initial_value) */
  if (do_data < FLASH_ADDR_DATA_STORAGE_START
      || do_data > FLASH_ADDR_DATA_STORAGE_START + FLASH_DATA_POOL_SIZE)
    return;

  addr += 2;

  /* Fill zero for content and pad */
  for (i = 0; i < len/2; i ++)
    {
      if (flash_program_halfword (addr, 0) != 0)
	flash_warning ("fill-zero failure");
      addr += 2;
    }

  if ((len & 1))
    {
      if (flash_program_halfword (addr, 0) != 0)
	flash_warning ("fill-zero pad failure");
    }

  /* Fill 0x0000 for "tag_number and length" word */
  if (flash_program_halfword (addr_tag, 0) != 0)
    flash_warning ("fill-zero tag_nr failure");
}


static uint8_t *
flash_key_getpage (enum kind_of_key kk)
{
  /* There is a page for each KK.  */
  return (uint8_t *)FLASH_ADDR_KEY_STORAGE_START + (flash_page_size * kk);
}

uint8_t *
flash_key_alloc (enum kind_of_key kk)
{
  uint8_t *k, *k0 = flash_key_getpage (kk);
  int i;
  int key_size = gpg_get_algo_attr_key_size (kk, GPG_KEY_STORAGE);

  /* Seek free space in the page.  */
  for (k = k0; k < k0 + flash_page_size; k += key_size)
    {
      const uint32_t *p = (const uint32_t *)k;

      for (i = 0; i < key_size/4; i++)
	if (p[i] != 0xffffffff)
	  break;

      if (i == key_size/4)	/* Yes, it's empty.  */
	return k;
    }

  /* Should not happen as we have enough free space all time, but just
     in case.  */
  return NULL;
}

int
flash_key_write (uint8_t *key_addr,
		 const uint8_t *key_data, int key_data_len,
		 const uint8_t *pubkey, int pubkey_len)
{
  uint16_t hw;
  uintptr_t addr;
  int i;

  addr = (uintptr_t)key_addr;
  for (i = 0; i < key_data_len/2; i ++)
    {
      hw = key_data[i*2] | (key_data[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  for (i = 0; i < pubkey_len/2; i ++)
    {
      hw = pubkey[i*2] | (pubkey[i*2+1]<<8);
      if (flash_program_halfword (addr, hw) != 0)
	return -1;
      addr += 2;
    }

  return 0;
}

static int
flash_check_all_other_keys_released (const uint8_t *key_addr, int key_size)
{
  uintptr_t start = (uintptr_t)key_addr & ~(flash_page_size - 1);
  const uint32_t *p = (const uint32_t *)start;

  while (p < (const uint32_t *)(start + flash_page_size))
    if (p == (const uint32_t *)key_addr)
      p += key_size/4;
    else
      if (*p)
	return 0;
      else
	p++;

  return 1;
}

static void
flash_key_fill_zero_as_released (uint8_t *key_addr, int key_size)
{
  int i;
  uintptr_t addr = (uintptr_t)key_addr;

  for (i = 0; i < key_size/2; i++)
    flash_program_halfword (addr + i*2, 0);
}

void
flash_key_release (uint8_t *key_addr, int key_size)
{
  if (flash_check_all_other_keys_released (key_addr, key_size))
    flash_erase_page (((uintptr_t)key_addr & ~(flash_page_size - 1)));
  else
    flash_key_fill_zero_as_released (key_addr, key_size);
}

void
flash_key_release_page (enum kind_of_key kk)
{
  flash_erase_page ((uintptr_t)flash_key_getpage (kk));
}


void
flash_clear_halfword (uintptr_t addr)
{
  flash_program_halfword (addr, 0);
}


void
flash_put_data_internal (const uint8_t *p, uint16_t hw)
{
  flash_program_halfword ((uintptr_t)p, hw);
}

void
flash_put_data (uint16_t hw)
{
  uint8_t *p;

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("data allocation failure.\r\n");
    }

  flash_program_halfword ((uintptr_t)p, hw);
}


void
flash_bool_clear (const uint8_t **addr_p)
{
  const uint8_t *p;

  if ((p = *addr_p) == NULL)
    return;

  flash_program_halfword ((uintptr_t)p, 0);
  *addr_p = NULL;
}

void
flash_bool_write_internal (const uint8_t *p, int nr)
{
  flash_program_halfword ((uintptr_t)p, nr);
}

const uint8_t *
flash_bool_write (uint8_t nr)
{
  uint8_t *p;
  uint16_t hw = nr;

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("bool allocation failure.\r\n");
      return NULL;
    }

  flash_program_halfword ((uintptr_t)p, hw);
  return p;
}


void
flash_enum_clear (const uint8_t **addr_p)
{
  flash_bool_clear (addr_p);
}

void
flash_enum_write_internal (const uint8_t *p, int nr, uint8_t v)
{
  uint16_t hw = nr | (v << 8);

  flash_program_halfword ((uintptr_t)p, hw);
}

const uint8_t *
flash_enum_write (uint8_t nr, uint8_t v)
{
  uint8_t *p;
  uint16_t hw = nr | (v << 8);

  p = flash_data_pool_allocate (2);
  if (p == NULL)
    {
      DEBUG_INFO ("enum allocation failure.\r\n");
      return NULL;
    }

  flash_program_halfword ((uintptr_t)p, hw);
  return p;
}


int
flash_cnt123_get_value (const uint8_t *p)
{
  if (p == NULL)
    return 0;
  else
    {
      uint8_t v = *p;

      /*
       * After erase, a halfword in flash memory becomes 0xffff.
       * The halfword can be programmed to any value.
       * Then, the halfword can be programmed to zero.
       *
       * Thus, we can represent value 1, 2, and 3.
       */
      if (v == 0xff)
	return 1;
      else if (v == 0x00)
	return 3;
      else
	return 2;
    }
}

void
flash_cnt123_write_internal (const uint8_t *p, int which, int v)
{
  uint16_t hw;

  hw = NR_COUNTER_123 | (which << 8);
  flash_program_halfword ((uintptr_t)p, hw);

  if (v == 1)
    return;
  else if (v == 2)
    flash_program_halfword ((uintptr_t)p+2, 0xc3c3);
  else				/* v == 3 */
    flash_program_halfword ((uintptr_t)p+2, 0);
}

void
flash_cnt123_increment (uint8_t which, const uint8_t **addr_p)
{
  const uint8_t *p;
  uint16_t hw;

  if ((p = *addr_p) == NULL)
    {
      p = flash_data_pool_allocate (4);
      if (p == NULL)
	{
	  DEBUG_INFO ("cnt123 allocation failure.\r\n");
	  return;
	}
      hw = NR_COUNTER_123 | (which << 8);
      flash_program_halfword ((uintptr_t)p, hw);
      *addr_p = p + 2;
    }
  else
    {
      uint8_t v = *p;

      if (v == 0)
	return;

      if (v == 0xff)
	hw = 0xc3c3;
      else
	hw = 0;

      flash_program_halfword ((uintptr_t)p, hw);
    }
}

void
flash_cnt123_clear (const uint8_t **addr_p)
{
  const uint8_t *p;

  if ((p = *addr_p) == NULL)
    return;

  flash_program_halfword ((uintptr_t)p, 0);
  p -= 2;
  flash_program_halfword ((uintptr_t)p, 0);
  *addr_p = NULL;
}


#if defined(CERTDO_SUPPORT)
int
flash_erase_binary (uint8_t file_id)
{
  if (file_id == FILEID_CH_CERTIFICATE)
    {
      const uint8_t *p = ch_certificate_start;
      if (flash_check_blank (p, FLASH_CH_CERTIFICATE_SIZE) == 0)
	{
	  flash_erase_page ((uintptr_t)p);
	  if (FLASH_CH_CERTIFICATE_SIZE > flash_page_size)
	    flash_erase_page ((uintptr_t)p + flash_page_size);
	}

      return 0;
    }

  return -1;
}
#endif


int
flash_write_binary (uint8_t file_id, const uint8_t *data,
		    uint16_t len, uint16_t offset)
{
  uint16_t maxsize;
  const uint8_t *p;

  if (file_id == FILEID_SERIAL_NO)
    {
      maxsize = 6;
      p = &openpgpcard_aid[8];
    }
#if defined(CERTDO_SUPPORT)
  else if (file_id == FILEID_CH_CERTIFICATE)
    {
      maxsize = FLASH_CH_CERTIFICATE_SIZE;
      p = ch_certificate_start;
    }
#endif
  else
    return -1;

  if (offset + len > maxsize || (offset&1) || (len&1))
    return -1;
  else
    {
      uint16_t hw;
      uintptr_t addr;
      int i;

      if (flash_check_blank (p + offset, len)  == 0)
	return -1;

      addr = (uintptr_t)p + offset;
      for (i = 0; i < len/2; i++)
	{
	  hw = data[i*2] | (data[i*2+1]<<8);
	  if (flash_program_halfword (addr, hw) != 0)
	    flash_warning ("DO WRITE ERROR");
	  addr += 2;
	}

      return 0;
    }
}
