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
#include "device/usbd_pvt.h"

// Device descriptors
#include "hsm2040.h"

static uint8_t itf_num;

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE+5)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE+5)
#endif

struct apdu apdu;
static struct ccid ccid;

static uint8_t ccid_buffer[USB_BUF_SIZE];

#define CCID_SET_PARAMS		0x61 /* non-ICCD command  */
#define CCID_POWER_ON		0x62
#define CCID_POWER_OFF		0x63
#define CCID_SLOT_STATUS	0x65 /* non-ICCD command */
#define CCID_SECURE		0x69 /* non-ICCD command */
#define CCID_GET_PARAMS		0x6C /* non-ICCD command */
#define CCID_RESET_PARAMS	0x6D /* non-ICCD command */
#define CCID_XFR_BLOCK		0x6F
#define CCID_DATA_BLOCK_RET	0x80
#define CCID_SLOT_STATUS_RET	0x81 /* non-ICCD result */
#define CCID_PARAMS_RET		0x82 /* non-ICCD result */

#define CCID_MSG_SEQ_OFFSET	6
#define CCID_MSG_STATUS_OFFSET	7
#define CCID_MSG_ERROR_OFFSET	8
#define CCID_MSG_CHAIN_OFFSET	9
#define CCID_MSG_DATA_OFFSET	10	/* == CCID_MSG_HEADER_SIZE */
#define CCID_MAX_MSG_DATA_SIZE	USB_BUF_SIZE

#define CCID_STATUS_RUN		0x00
#define CCID_STATUS_PRESENT	0x01
#define CCID_STATUS_NOTPRESENT	0x02
#define CCID_CMD_STATUS_OK	0x00
#define CCID_CMD_STATUS_ERROR	0x40
#define CCID_CMD_STATUS_TIMEEXT	0x80

#define CCID_ERROR_XFR_OVERRUN	0xFC

/*
 * Since command-byte is at offset 0,
 * error with offset 0 means "command not supported".
 */
#define CCID_OFFSET_CMD_NOT_SUPPORTED 0
#define CCID_OFFSET_DATA_LEN 1
#define CCID_OFFSET_PARAM 8


struct ccid_header {
  uint8_t msg_type;
  uint32_t data_len;
  uint8_t slot;
  uint8_t seq;
  uint8_t rsvd;
  uint16_t param;
} __attribute__((packed));


/* Data structure handled by CCID layer */
struct ccid {
  uint32_t ccid_state : 4;
  uint32_t state      : 4;
  uint32_t err        : 1;
  uint32_t tx_busy    : 1;
  uint32_t timeout_cnt: 3;

  uint8_t *p;
  size_t len;

  struct ccid_header ccid_header;

  uint8_t sw1sw2[2];
  uint8_t chained_cls_ins_p1_p2[4];

  struct apdu *a;
};

static void ccid_init(struct ccid *c, struct apdu *a)
{
  c->ccid_state = CCID_STATE_START;
  c->err = 0;
  c->tx_busy = 0;
  c->state = APDU_STATE_WAIT_COMMAND;
  c->p = a->cmd_apdu_data;
  c->len = MAX_CMD_APDU_DATA_SIZE;
  memset (&c->ccid_header, 0, sizeof (struct ccid_header));
  c->sw1sw2[0] = 0x90;
  c->sw1sw2[1] = 0x00;
  c->a = a;
}

static void apdu_init (struct apdu *a)
{
  a->seq = 0;			/* will be set by lower layer */
  a->cmd_apdu_head = &ccid_buffer[0];
  a->cmd_apdu_data = &ccid_buffer[5];
  a->cmd_apdu_data_len = 0;	/* will be set by lower layer */
  a->expected_res_size = 0;	/* will be set by lower layer */

  a->sw = 0x9000;		     /* will be set by upper layer */
  a->res_apdu_data = &ccid_buffer[5]; /* will be set by upper layer */
  a->res_apdu_data_len = 0;	     /* will be set by upper layer */
}

static void ccid_init_cb(void) {
    TU_LOG2("-------- CCID INIT\r\n");
    vendord_init();
}

static void ccid_reset(uint8_t rhport) {
    TU_LOG2("-------- CCID RESET\r\n");
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    
    TU_LOG2("-------- CCID OPEN\r\n");
    TU_VERIFY(itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);
    
    vendord_open(rhport, itf_desc, max_len);

    uint16_t const drv_len = sizeof(tusb_desc_interface_t) + sizeof(class_desc_ccid_t) + 2*sizeof(tusb_desc_endpoint_t);
    TU_VERIFY(max_len >= drv_len, 0);

    itf_num = itf_desc->bInterfaceNumber;
    return drv_len;
}

// Support for parameterized reset via vendor interface control request
static bool ccid_control_xfer_cb(uint8_t __unused rhport, uint8_t stage, tusb_control_request_t const * request) {
    // nothing to do with DATA & ACK stage
    TU_LOG2("-------- CCID CTRL XFER\r\n");
    if (stage != CONTROL_STAGE_SETUP) return true;

    if (request->wIndex == itf_num) 
    {
        TU_LOG2("-------- bmRequestType %x, bRequest %x, wValue %x, wLength %x\r\n",request->bmRequestType,request->bRequest, request->wValue, request->wLength);
/*
#if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_BOOTSEL
        if (request->bRequest == RESET_REQUEST_BOOTSEL) {
#ifdef PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED
            uint gpio_mask = 1u << PICO_STDIO_USB_RESET_BOOTSEL_ACTIVITY_LED;
#else
            uint gpio_mask = 0u;
#endif
#if !PICO_STDIO_USB_RESET_BOOTSEL_FIXED_ACTIVITY_LED
            if (request->wValue & 0x100) {
                gpio_mask = 1u << (request->wValue >> 9u);
            }
#endif
            reset_usb_boot(gpio_mask, (request->wValue & 0x7f) | PICO_STDIO_USB_RESET_BOOTSEL_INTERFACE_DISABLE_MASK);
            // does not return, otherwise we'd return true
        }
#endif

#if PICO_STDIO_USB_RESET_INTERFACE_SUPPORT_RESET_TO_FLASH_BOOT
        if (request->bRequest == RESET_REQUEST_FLASH) {
            watchdog_reboot(0, 0, PICO_STDIO_USB_RESET_RESET_TO_FLASH_DELAY_MS);
            return true;
        }
#endif
*/
        return true;
    }
    return false;
}

static bool ccid_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes) {
    TU_LOG2("------ CALLED XFER_CB\r\n");
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    //return true;
}


static usbd_class_driver_t const ccid_driver =
{
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset,
    .open             = ccid_open,
    .control_xfer_cb  = ccid_control_xfer_cb,
    .xfer_cb          = ccid_xfer_cb,
    .sof              = NULL
};

// Implement callback to add our custom driver
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count) {
    *driver_count = 1;
    return &ccid_driver;
}

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
    TU_LOG2("---- TASK VENDR AVAILABLE\r\n");
      uint8_t buf[64];

      uint32_t count = tud_vendor_read(buf, sizeof(buf));
      TU_LOG2("-------- RECEIVED %d, %x %x %x",count,buf[0],buf[1],buf[2]);
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
    TU_LOG3("!!!!!!!  RX_CB\r\n");
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
    struct apdu *a = &apdu;
    struct ccid *c = &ccid;
    
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

    apdu_init(a);
    ccid_init(c, a);

    while (1)
    {
        vendor_task();
        tud_task(); // tinyusb device task
        led_blinking_task();
    }

    return 0;
}