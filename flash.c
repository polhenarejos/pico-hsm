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
#include "hsm2040.h"
#include "tusb.h"
#include "file.h"

#define FLASH_TARGET_OFFSET (PICO_FLASH_SIZE_BYTES >> 1) // DATA starts at the mid of flash
#define FLASH_DATA_HEADER_SIZE (sizeof(uintptr_t)+sizeof(uint32_t))

//To avoid possible future allocations, data region starts at the begining of flash and goes upwards to the center region

const uintptr_t start_data_pool = (XIP_BASE + FLASH_TARGET_OFFSET);
const uintptr_t end_data_pool = (XIP_BASE + PICO_FLASH_SIZE_BYTES)-FLASH_DATA_HEADER_SIZE; //This is a fixed value. DO NOT CHANGE
#define FLASH_ADDR_DATA_STORAGE_START start_data_pool

extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern int flash_program_halfword (uintptr_t addr, uint16_t data);
extern int flash_program_uintptr(uintptr_t, uintptr_t);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);

extern void low_flash_available();

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
 
uintptr_t allocate_free_addr(uint16_t size) {
    if (size > FLASH_SECTOR_SIZE)
        return 0x0; //ERROR
    size_t real_size = size+sizeof(uint16_t)+sizeof(uintptr_t)+sizeof(uint16_t); //len+len size+next address+fid
    uintptr_t next_base = 0x0;
    for (uintptr_t base = end_data_pool; base >= start_data_pool; base = next_base) {
        uintptr_t addr_alg = base & -FLASH_SECTOR_SIZE; //start address of sector
        uintptr_t potential_addr = base-real_size;
        next_base = flash_read_uintptr(base);
        if (next_base == 0x0) { //we are at the end
            //now we check if we fit in the current sector
            if (addr_alg <= potential_addr) //it fits in the current sector
            {
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(base, potential_addr);
                return potential_addr;
            }
            else if (addr_alg-FLASH_SECTOR_SIZE >= start_data_pool) { //check whether it fits in the next sector, so we take addr_aligned as the base
                potential_addr = addr_alg-real_size;
                flash_program_uintptr(potential_addr, 0x0);
                flash_program_uintptr(base, potential_addr);
                return potential_addr;
            }
            return 0x0;
        }
        //we check if |base-(next_addr+size_next_addr)| > |base-potential_addr| only if fid != 1xxx (not size blocked)
        else if (addr_alg <= potential_addr && base-(next_base+flash_read_uint16(next_base+sizeof(uintptr_t)+sizeof(uint16_t))) > base-potential_addr && flash_read_uint16(next_base+sizeof(uintptr_t)+sizeof(uint16_t)) & 0x1000 != 0x1000) {
            flash_program_uintptr(potential_addr, next_base);
            flash_program_uintptr(base, potential_addr);
            return potential_addr;
        }
    }
    return 0x0; //probably never reached
}

int flash_clear_file(file_t *file) {
    uintptr_t prev_addr = (uintptr_t)(file->data+flash_read_uint16((uintptr_t)file->data)+sizeof(uint16_t));
    uintptr_t base_addr = (uintptr_t)file->data-sizeof(uintptr_t);
    uintptr_t next_addr = flash_read_uintptr(base_addr);
    flash_program_uintptr(prev_addr, next_addr);
    flash_program_halfword((uintptr_t)file->data, 0);
    return 0;
}

int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len) {
    if (len > FLASH_SECTOR_SIZE)
        return 1;
    if (file->data) { //already in flash
        uint16_t size_file_flash = flash_read_uint16((uintptr_t)file->data);
        if (len <= size_file_flash) { //it fits, no need to move it
            flash_program_halfword((uintptr_t)file->data, len);
            flash_program_block((uintptr_t)file->data+sizeof(uint16_t), data, len);
            return 0;
        }
        else { //we clear the old file
            flash_clear_file(file);
        }
    }
    uintptr_t new_addr = allocate_free_addr(len);
    if (new_addr == 0x0) 
        return 2;
    file->data = (uint8_t *)new_addr+sizeof(uintptr_t)+sizeof(uint16_t); //next addr+fid
    flash_program_halfword(new_addr+sizeof(uintptr_t), file->fid);
    flash_program_halfword((uintptr_t)file->data, len);
    flash_program_block((uintptr_t)file->data+sizeof(uint16_t), data, len);
    return 0;
}
