/*
 * debug.c -- Debuging with virtual COM port
 *
 * Copyright (C) 2010 Free Software Initiative of Japan
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
#include "tusb.h"
#include "config.h"

void my_write (const char *s, int len)
{
  if (len == 0)
    return;

  TU_LOG1(s);
}


static void
put_hex (uint8_t nibble)
{
  uint8_t c;

  if (nibble < 0x0a)
    c = '0' + nibble;
  else
    c = 'a' + nibble - 0x0a;

  //my_write ((const char *)&c, 1);
  printf("%X",nibble);
}

void
put_byte (uint8_t b)
{
  put_hex (b >> 4);
  put_hex (b &0x0f);
  my_write ("\r\n", 2);
}

void
put_byte_with_no_nl (uint8_t b)
{
  my_write (" ", 1);
  put_hex (b >> 4);
  put_hex (b &0x0f);
}

void
put_short (uint16_t x)
{
  put_hex (x >> 12);
  put_hex ((x >> 8)&0x0f);
  put_hex ((x >> 4)&0x0f);
  put_hex (x & 0x0f);
  my_write ("\r\n", 2);
}

void
put_word (uint32_t x)
{
  put_hex (x >> 28);
  put_hex ((x >> 24)&0x0f);
  put_hex ((x >> 20)&0x0f);
  put_hex ((x >> 16)&0x0f);
  put_hex ((x >> 12)&0x0f);
  put_hex ((x >> 8)&0x0f);
  put_hex ((x >> 4)&0x0f);
  put_hex (x & 0x0f);
  my_write ("\r\n", 2);
}

void
put_int (uint32_t x)
{
  char s[10];
  int i;

  for (i = 0; i < 10; i++)
    {
      s[i] = '0' + (x % 10);
      x /= 10;
      if (x == 0)
	break;
    }

  while (i)
    {
      my_write (s+i, 1);
      i--;
    }

  my_write (s, 1);
  my_write ("\r\n", 2);
}

void
put_binary (const char *s, int len)
{
  int i;

  for (i = 0; i < len; i++)
    {
      put_byte_with_no_nl (s[i]);
      if ((i & 0x0f) == 0x0f)
	my_write ("\r\n", 2);
      }
  my_write ("\r\n", 2);
}

void
put_string (const char *s)
{
  my_write (s, strlen (s));
}


