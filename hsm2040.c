/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

// Pico
#include "pico/stdlib.h"

// For memcpy
#include <string.h>

#include "bsp/board.h"
#include "tusb.h"
#include "usb_descriptors.h"

// Device descriptors
#include "hsm2040.h"

enum  {
  BLINK_NOT_MOUNTED = 250,
  BLINK_MOUNTED     = 1000,
  BLINK_SUSPENDED   = 2500,

  BLINK_RED =   18,
  BLINK_GREEN = 19,
  BLINK_BLUE =  20,

  BLINK_ALWAYS_ON   = UINT32_MAX,
  BLINK_ALWAYS_OFF  = 0
};

static uint32_t blink_interval_ms = BLINK_NOT_MOUNTED;


//--------------------------------------------------------------------+
// USB CDC
//--------------------------------------------------------------------+
void vendor_task(void)
{
  if ( tud_vendor_mounted() )
  {
    // connected and there are data available
    if ( tud_vendor_available() )
    {
      uint8_t buf[64];

      uint32_t count = tud_vendor_read(buf, sizeof(buf));

      // echo back to both web serial and cdc
      //echo_all(buf, count);
    }
  }
}

// Invoked when cdc when line state changed e.g connected/disconnected
void tud_vendor_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
  (void) itf;

  // connected
  if ( dtr && rts )
  {
    // print initial message when connected
    tud_vendor_write_str("\r\nTinyUSB WebUSB device example\r\n");
  }
}

// Invoked when CDC interface received data from host
void tud_vendor_rx_cb(uint8_t itf)
{
  (void) itf;
}

void tud_mount_cb()
{
    TU_LOG3("!!!!!!!  MOUNTED\r\n");
}

void led_blinking_task(void)
{
  static uint32_t start_ms = 0;
  static uint8_t led_state = false;
  static uint8_t led_color = BLINK_RED;

  // Blink every interval ms
  if ( board_millis() - start_ms < blink_interval_ms) return; // not enough time
  start_ms += blink_interval_ms;

  gpio_put(led_color, led_state);
  led_state ^= 1; // toggle
}

void led_off_all() 
{
  gpio_put(18, 1);  
  gpio_put(19, 1);  
  gpio_put(20, 1);
}

int main(void)
{
  printf("BOARD INIT\r\n");
  board_init();
  
  gpio_init(18);
  gpio_set_dir(18, GPIO_OUT);
  gpio_init(19);
  gpio_set_dir(19, GPIO_OUT);
  gpio_init(20);
  gpio_set_dir(20, GPIO_OUT);
  
  led_off_all();

  tusb_init();

  while (1)
  {
    tud_task(); // tinyusb device task
    vendor_task();
    led_blinking_task();
  }

  return 0;
}