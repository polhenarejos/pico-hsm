/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

// Pico
#include "pico/stdlib.h"
#include <stdlib.h>

// For memcpy
#include <string.h>

#include "bsp/board.h"
#include "tusb.h"
#include "usb_descriptors.h"
#include "device/usbd_pvt.h"
#include "pico/util/queue.h"
#include "pico/multicore.h"
#include "gnuk.h"
#include "config.h"
#include "random.h"

// Device descriptors
#include "hsm2040.h"

extern void do_flash();
extern void low_flash_init();

static uint8_t itf_num;

#if MAX_RES_APDU_DATA_SIZE > MAX_CMD_APDU_DATA_SIZE
#define USB_BUF_SIZE (MAX_RES_APDU_DATA_SIZE+20+9)
#else
#define USB_BUF_SIZE (MAX_CMD_APDU_DATA_SIZE+20+9)
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

static app_t apps[4];
static uint8_t num_apps = 0;

app_t *current_app = NULL;

extern void card_thread();

static queue_t *card_comm;
extern void low_flash_init_core1();

int register_app(app_t * (*select_aid)()) {
    if (num_apps < sizeof(apps)/sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        num_apps++;
        return 1;
    }
    return 0;
}

struct ep_in {
    uint8_t ep_num;
    uint8_t tx_done;
    const uint8_t *buf;
    size_t cnt;
    size_t buf_len;
    void *priv;
    void (*next_buf) (struct ep_in *epi, size_t len);
};

static void epi_init (struct ep_in *epi, int ep_num, void *priv)
{
    epi->ep_num = ep_num;
    epi->tx_done = 0;
    epi->buf = NULL;
    epi->cnt = 0;
    epi->buf_len = 0;
    epi->priv = priv;
    epi->next_buf = NULL;
}

struct ep_out {
    uint8_t ep_num;
    uint8_t err;
    uint8_t *buf;
    size_t cnt;
    size_t buf_len;
    void *priv;
    void (*next_buf) (struct ep_out *epo, size_t len);
    int  (*end_rx) (struct ep_out *epo, size_t orig_len);
    uint8_t ready;
};

static struct ep_out endpoint_out;
static struct ep_in endpoint_in;

static void epo_init (struct ep_out *epo, int ep_num, void *priv)
{
    epo->ep_num = ep_num;
    epo->err = 0;
    epo->buf = NULL;
    epo->cnt = 0;
    epo->buf_len = 0;
    epo->priv = priv;
    epo->next_buf = NULL;
    epo->end_rx = NULL;
    epo->ready = 0;
}

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

    struct ep_out *epo;
    struct ep_in *epi;

    queue_t ccid_comm;
    queue_t card_comm;

    uint8_t application;

    struct apdu *a;
};

static uint8_t endp1_rx_buf[64];
static uint8_t endp1_tx_buf[64];

#define APDU_STATE_WAIT_COMMAND        0
#define APDU_STATE_COMMAND_CHAINING    1
#define APDU_STATE_COMMAND_RECEIVED    2
#define APDU_STATE_RESULT              3
#define APDU_STATE_RESULT_GET_RESPONSE 4

static void ccid_prepare_receive (struct ccid *c);
static void apdu_init (struct apdu *a);

static void ccid_reset (struct ccid *c)
{
    apdu_init(c->a);
    c->err = 0;
    c->tx_busy = 0;
    c->state = APDU_STATE_WAIT_COMMAND;
    c->p = c->a->cmd_apdu_data;
    c->len = MAX_CMD_APDU_DATA_SIZE;
    c->a->cmd_apdu_data_len = 0;
    c->a->expected_res_size = 0;
}

static void ccid_init(struct ccid *c, struct ep_in *epi, struct ep_out *epo, struct apdu *a)
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
    c->application = 0;
    c->epi = epi;
    c->epo = epo;
    c->a = a;

    queue_init(&c->card_comm, sizeof(uint32_t), 64);
    queue_init(&c->ccid_comm, sizeof(uint32_t), 64);
}

#define CMD_APDU_HEAD_SIZE 5

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

/*
!!!! IT USES ENDP2, Interruption

#define NOTIFY_SLOT_CHANGE 0x50
static void ccid_notify_slot_change(struct ccid *c)
{
    uint8_t msg;
    uint8_t notification[2];

    if (c->ccid_state == CCID_STATE_NOCARD)
        msg = 0x02;
    else
        msg = 0x03;

    notification[0] = NOTIFY_SLOT_CHANGE;
    notification[1] = msg;

    tud_vendor_write(notification, sizeof(notification));
}
*/

#define USB_CCID_TIMEOUT (50)

#define GPG_THREAD_TERMINATED 0xffff
#define GPG_ACK_TIMEOUT 0x6600

static void ccid_init_cb(void) {
    struct ccid *c = &ccid;
    TU_LOG1("-------- CCID INIT\r\n");
    vendord_init();

    //ccid_notify_slot_change(c);
}

static void ccid_reset_cb(uint8_t rhport) {
    TU_LOG1("-------- CCID RESET\r\n");
    itf_num = 0;
    vendord_reset(rhport);
}

static uint16_t ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len) {
    uint8_t *itf_vendor = (uint8_t *)malloc(sizeof(uint8_t)*max_len);
    TU_LOG1("-------- CCID OPEN\r\n");
    TU_VERIFY(itf_desc->bInterfaceClass == TUSB_CLASS_SMART_CARD && itf_desc->bInterfaceSubClass == 0 && itf_desc->bInterfaceProtocol == 0, 0);

    //vendord_open expects a CLASS_VENDOR interface class
    memcpy(itf_vendor, itf_desc, sizeof(uint8_t)*max_len);
    ((tusb_desc_interface_t *)itf_vendor)->bInterfaceClass = TUSB_CLASS_VENDOR_SPECIFIC;
    vendord_open(rhport, (tusb_desc_interface_t *)itf_vendor, max_len);
    free(itf_vendor);

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
    //TU_LOG2("------ CALLED XFER_CB\r\n");
    return vendord_xfer_cb(rhport, ep_addr, result, xferred_bytes);
    //return true;
}


static usbd_class_driver_t const ccid_driver =
{
#if CFG_TUSB_DEBUG >= 2
    .name = "CCID",
#endif
    .init             = ccid_init_cb,
    .reset            = ccid_reset_cb,
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
    BLINK_NOT_MOUNTED = (250 << 16) | 250,
    BLINK_MOUNTED     = (250 << 16) | 250,
    BLINK_SUSPENDED   = (500 << 16) | 1000,
    BLINK_PROCESSING  = (50 << 16) | 50,

    BLINK_RED =   18,
    BLINK_GREEN = 19,
    BLINK_BLUE =  20,

    BLINK_ALWAYS_ON   = UINT32_MAX,
    BLINK_ALWAYS_OFF  = 0
};

static uint32_t blink_interval_ms = BLINK_NOT_MOUNTED;

void usb_tx_enable(const uint8_t *buf, uint32_t len) 
{
    if (len > 0) {
        if (buf[0] != 0x81)
            DEBUG_PAYLOAD(buf,len);
        //DEBUG_PAYLOAD(buf,len);
        tud_vendor_write(buf, len);
    }
}

/*
 * ATR (Answer To Reset) string
 *
 * TS = 0x3b: Direct conversion
 * T0 = 0xda: TA1, TC1 and TD1 follow, 10 historical bytes
 * TA1 = 0x11: FI=1, DI=1
 * TC1 = 0xff
 * TD1 = 0x81: TD2 follows, T=1
 * TD2 = 0xb1: TA3, TB3 and TD3 follow, T=1
 * TA3 = 0xFE: IFSC = 254 bytes
 * TB3 = 0x55: BWI = 5, CWI = 5   (BWT timeout 3.2 sec)
 * TD3 = 0x1f: TA4 follows, T=15
 * TA4 = 0x03: 5V or 3.3V
 *
 * Minimum: 0x3b, 0x8a, 0x80, 0x01
 *
 */
static const uint8_t ATR_head[] = {
    0x3b, 0xda, 0x11, 0xff, 0x81, 0xb1, 0xfe, 0x55, 0x1f, 0x03,
    //0x3B,0xFE,0x18,0x00,0x00,0x81,0x31,0xFE,0x45,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0xFA
};

/* Send back ATR (Answer To Reset) */
static enum ccid_state ccid_power_on(struct ccid *c)
{
    TU_LOG1("!!! CCID POWER ON %d\r\n",c->application);
    uint8_t p[CCID_MSG_HEADER_SIZE+1]; /* >= size of historical_bytes -1 */
    int hist_len = historical_bytes[0];
    
    //char atr_sc_hsm[] = { 0x3B,0x8E,0x80,0x01,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x18 };
    char atr_sc_hsm[] = { 0x3B, 0xDE, 0x18, 0xFF, 0x81, 0x91, 0xFE, 0x1F, 0xC3, 0x80, 0x31, 0x81, 0x54, 0x48, 0x53, 0x4D, 0x31, 0x73, 0x80, 0x21, 0x40, 0x81, 0x07, 0x1C };
    uint8_t mode = 1; //1 sc-hsm, 0 openpgp
    size_t size_atr;
    if (mode == 1)
        size_atr = sizeof(atr_sc_hsm);
    else
        size_atr = sizeof (ATR_head) + hist_len + 1;
    uint8_t xor_check = 0;
    int i;
    if (c->application == 0)
    {
        multicore_reset_core1();
        multicore_launch_core1(card_thread);
        multicore_fifo_push_blocking((uint32_t)&c->ccid_comm);
        multicore_fifo_push_blocking((uint32_t)&c->card_comm);
        c->application = 1;
    }
    p[0] = CCID_DATA_BLOCK_RET;
    p[1] = size_atr;
    p[2] = 0x00;
    p[3] = 0x00;
    p[4] = 0x00;
    p[5] = 0x00;	/* Slot */
    p[CCID_MSG_SEQ_OFFSET] = c->ccid_header.seq;
    p[CCID_MSG_STATUS_OFFSET] = 0x00;
    p[CCID_MSG_ERROR_OFFSET] = 0x00;
    p[CCID_MSG_CHAIN_OFFSET] = 0x00;

    memcpy(endp1_tx_buf, p, CCID_MSG_HEADER_SIZE);
    if (mode == 1)
    {
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, atr_sc_hsm, sizeof(atr_sc_hsm));
    }
    else
    {
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, ATR_head, sizeof (ATR_head));

        for (i = 1; i < (int)sizeof (ATR_head); i++)
            xor_check ^= ATR_head[i];
        memcpy (p, historical_bytes + 1, hist_len);
#ifdef LIFE_CYCLE_MANAGEMENT_SUPPORT
        if (file_selection == 255)
            p[7] = 0x03;
#endif
        for (i = 0; i < hist_len; i++)
            xor_check ^= p[i];
        p[i] = xor_check;
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE+sizeof (ATR_head), p, hist_len+1);
    }

  /* This is a single packet Bulk-IN transaction */
    c->epi->buf = NULL;
    c->epi->tx_done = 1;
    
    usb_tx_enable(endp1_tx_buf, CCID_MSG_HEADER_SIZE + size_atr);

    DEBUG_INFO("ON\r\n");
    c->tx_busy = 1;
    blink_interval_ms = BLINK_MOUNTED;
    return CCID_STATE_WAIT;
}

static void ccid_send_status(struct ccid *c)
{
    uint8_t ccid_reply[CCID_MSG_HEADER_SIZE];

    ccid_reply[0] = CCID_SLOT_STATUS_RET;
    ccid_reply[1] = 0x00;
    ccid_reply[2] = 0x00;
    ccid_reply[3] = 0x00;
    ccid_reply[4] = 0x00;
    ccid_reply[5] = 0x00;	/* Slot */
    ccid_reply[CCID_MSG_SEQ_OFFSET] = c->ccid_header.seq;
    if (c->ccid_state == CCID_STATE_NOCARD)
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 2; /* 2: No ICC present */
    else if (c->ccid_state == CCID_STATE_START)
        /* 1: ICC present but not activated */
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 1;
    else
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 0; /* An ICC is present and active */
    ccid_reply[CCID_MSG_ERROR_OFFSET] = 0x00;
    ccid_reply[CCID_MSG_CHAIN_OFFSET] = 0x00;

    /* This is a single packet Bulk-IN transaction */
    c->epi->buf = NULL;
    c->epi->tx_done = 1;

    memcpy(endp1_tx_buf, ccid_reply, CCID_MSG_HEADER_SIZE);
    usb_tx_enable(endp1_tx_buf, CCID_MSG_HEADER_SIZE);
    c->tx_busy = 1;
}

static enum ccid_state ccid_power_off(struct ccid *c)
{
    if (c->application)
    {
        uint32_t flag = EV_EXIT;
        queue_try_add(&c->card_comm, &flag);
        c->application = 0;
    }

    c->ccid_state = CCID_STATE_START; /* This status change should be here */
    ccid_send_status (c);
    DEBUG_INFO ("OFF\r\n");
    c->tx_busy = 1;
    blink_interval_ms = BLINK_SUSPENDED;
    return CCID_STATE_START;
}

static void no_buf (struct ep_in *epi, size_t len)
{
    (void)len;
    epi->buf = NULL;
    epi->cnt = 0;
    epi->buf_len = 0;
}

static void set_sw1sw2(struct ccid *c, size_t chunk_len)
{
    if (c->a->expected_res_size >= c->len)
    {
        c->sw1sw2[0] = 0x90;
        c->sw1sw2[1] = 0x00;
    }
    else
    {
        c->sw1sw2[0] = 0x61;
        if (c->len - chunk_len >= 256)
	        c->sw1sw2[1] = 0;
        else
	        c->sw1sw2[1] = (uint8_t)(c->len - chunk_len);
    }
}

static void get_sw1sw2(struct ep_in *epi, size_t len)
{
    struct ccid *c = (struct ccid *)epi->priv;

    (void)len;
    epi->buf = c->sw1sw2;
    epi->cnt = 0;
    epi->buf_len = 2;
    epi->next_buf = no_buf;
}

static void ccid_send_data_block_internal(struct ccid *c, uint8_t status, uint8_t error)
{
    int tx_size = USB_LL_BUF_SIZE;
    uint8_t p[CCID_MSG_HEADER_SIZE];
    size_t len;

    if (status == 0)
        len = c->a->res_apdu_data_len + 2;
    else
        len = 0;

    p[0] = CCID_DATA_BLOCK_RET;
    p[1] = len & 0xFF;
    p[2] = (len >> 8)& 0xFF;
    p[3] = (len >> 16)& 0xFF;
    p[4] = (len >> 24)& 0xFF;
    p[5] = 0x00;	/* Slot */
    p[CCID_MSG_SEQ_OFFSET] = c->a->seq;
    p[CCID_MSG_STATUS_OFFSET] = status;
    p[CCID_MSG_ERROR_OFFSET] = error;
    p[CCID_MSG_CHAIN_OFFSET] = 0;

    memcpy(endp1_tx_buf, p, CCID_MSG_HEADER_SIZE);

    if (len == 0)
    {
        c->epi->buf = NULL;
        c->epi->tx_done = 1;
        usb_tx_enable(endp1_tx_buf, CCID_MSG_HEADER_SIZE);
        c->tx_busy = 1;
      return;
    }

    if (CCID_MSG_HEADER_SIZE + len <= USB_LL_BUF_SIZE)
    {
      memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->a->res_apdu_data, c->a->res_apdu_data_len);
      memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE+c->a->res_apdu_data_len, c->sw1sw2, 2);

      c->epi->buf = NULL;
      if (CCID_MSG_HEADER_SIZE + len < USB_LL_BUF_SIZE)
	    c->epi->tx_done = 1;
      tx_size = CCID_MSG_HEADER_SIZE + len;
    }
    else if (CCID_MSG_HEADER_SIZE + len - 1 == USB_LL_BUF_SIZE)
    {
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->a->res_apdu_data, c->a->res_apdu_data_len);
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE+c->a->res_apdu_data_len, c->sw1sw2, 1);

        c->epi->buf = &c->sw1sw2[1];
        c->epi->cnt = 1;
        c->epi->buf_len = 1;
        c->epi->next_buf = no_buf;
    }
    else if (CCID_MSG_HEADER_SIZE + len - 2 == USB_LL_BUF_SIZE)
    {
      memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->a->res_apdu_data, c->a->res_apdu_data_len);

      c->epi->buf = &c->sw1sw2[0];
      c->epi->cnt = 0;
      c->epi->buf_len = 2;
      c->epi->next_buf = no_buf;
    }
    else
    {
        memcpy(endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->a->res_apdu_data, USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE);

        c->epi->buf = c->a->res_apdu_data + USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE;
        c->epi->cnt = USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE;
        c->epi->buf_len = c->a->res_apdu_data_len - (USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE);
        c->epi->next_buf = get_sw1sw2;
    }
    usb_tx_enable(endp1_tx_buf, tx_size);
    c->tx_busy = 1;
}

static void ccid_send_data_block(struct ccid *c)
{
    ccid_send_data_block_internal (c, 0, 0);
}

static void ccid_send_data_block_time_extension(struct ccid *c)
{
    ccid_send_data_block_internal (c, CCID_CMD_STATUS_TIMEEXT, c->ccid_state == CCID_STATE_EXECUTE? 1: 0xff);
}

static void ccid_send_data_block_0x9000(struct ccid *c)
{
    uint8_t p[CCID_MSG_HEADER_SIZE+2];
    size_t len = 2;

    p[0] = CCID_DATA_BLOCK_RET;
    p[1] = len & 0xFF;
    p[2] = (len >> 8)& 0xFF;
    p[3] = (len >> 16)& 0xFF;
    p[4] = (len >> 24)& 0xFF;
    p[5] = 0x00;	/* Slot */
    p[CCID_MSG_SEQ_OFFSET] = c->a->seq;
    p[CCID_MSG_STATUS_OFFSET] = 0;
    p[CCID_MSG_ERROR_OFFSET] = 0;
    p[CCID_MSG_CHAIN_OFFSET] = 0;
    p[CCID_MSG_CHAIN_OFFSET+1] = 0x90;
    p[CCID_MSG_CHAIN_OFFSET+2] = 0x00;

    memcpy (endp1_tx_buf, p, CCID_MSG_HEADER_SIZE + len);

    c->epi->buf = NULL;
    c->epi->tx_done = 1;
    usb_tx_enable (endp1_tx_buf, CCID_MSG_HEADER_SIZE + len);
    c->tx_busy = 1;
}

static void ccid_send_data_block_gr(struct ccid *c, size_t chunk_len)
{
    int tx_size = USB_LL_BUF_SIZE;
    uint8_t p[CCID_MSG_HEADER_SIZE];
    size_t len = chunk_len + 2;

    p[0] = CCID_DATA_BLOCK_RET;
    p[1] = len & 0xFF;
    p[2] = (len >> 8)& 0xFF;
    p[3] = (len >> 16)& 0xFF;
    p[4] = (len >> 24)& 0xFF;
    p[5] = 0x00;	/* Slot */
    p[CCID_MSG_SEQ_OFFSET] = c->a->seq;
    p[CCID_MSG_STATUS_OFFSET] = 0;
    p[CCID_MSG_ERROR_OFFSET] = 0;
    p[CCID_MSG_CHAIN_OFFSET] = 0;

    memcpy (endp1_tx_buf, p, CCID_MSG_HEADER_SIZE);

    set_sw1sw2 (c, chunk_len);

    if (chunk_len <= USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE)
    {
        int size_for_sw;

        if (chunk_len <= USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE - 2)
            size_for_sw = 2;
        else if (chunk_len == USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE - 1)
            size_for_sw = 1;
        else
            size_for_sw = 0;

        memcpy (endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->p, chunk_len);

        if (size_for_sw)
            memcpy (endp1_tx_buf+CCID_MSG_HEADER_SIZE+chunk_len, c->sw1sw2, size_for_sw);

        tx_size = CCID_MSG_HEADER_SIZE + chunk_len + size_for_sw;
        if (size_for_sw == 2)
        {
            c->epi->buf = NULL;
            if (tx_size < USB_LL_BUF_SIZE)
                c->epi->tx_done = 1;
                /* Don't set epi->tx_done = 1, when it requires ZLP */
        }
        else
        {
            c->epi->buf = c->sw1sw2 + size_for_sw;
            c->epi->cnt = size_for_sw;
            c->epi->buf_len = 2 - size_for_sw;
            c->epi->next_buf = no_buf;
        }
    }
    else
    {
      memcpy (endp1_tx_buf+CCID_MSG_HEADER_SIZE, c->p, USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE);

      c->epi->buf = c->p + USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE;
      c->epi->cnt = 0;
      c->epi->buf_len = chunk_len - (USB_LL_BUF_SIZE - CCID_MSG_HEADER_SIZE);
      c->epi->next_buf = get_sw1sw2;
    }

    c->p += chunk_len;
    c->len -= chunk_len;
    usb_tx_enable (endp1_tx_buf, tx_size);
    c->tx_busy = 1;
}

static void ccid_send_params(struct ccid *c)
{
    uint8_t p[CCID_MSG_HEADER_SIZE];
    const uint8_t params[] =  {
        0x11,   /* bmFindexDindex */
        0x11, /* bmTCCKST1 */
        0xFE, /* bGuardTimeT1 */
        0x55, /* bmWaitingIntegersT1 */
        0x03, /* bClockStop */
        0xFE, /* bIFSC */
        0    /* bNadValue */
    };

    p[0] = CCID_PARAMS_RET;
    p[1] = 0x07;	/* Length = 0x00000007 */
    p[2] = 0;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0x00;	/* Slot */
    p[CCID_MSG_SEQ_OFFSET] = c->ccid_header.seq;
    p[CCID_MSG_STATUS_OFFSET] = 0;
    p[CCID_MSG_ERROR_OFFSET] = 0;
    p[CCID_MSG_CHAIN_OFFSET] = 0x01;  /* ProtocolNum: T=1 */

    memcpy (endp1_tx_buf, p, CCID_MSG_HEADER_SIZE);
    memcpy (endp1_tx_buf+CCID_MSG_HEADER_SIZE, params, sizeof params);

    /* This is a single packet Bulk-IN transaction */
    c->epi->buf = NULL;
    c->epi->tx_done = 1;
    usb_tx_enable (endp1_tx_buf, CCID_MSG_HEADER_SIZE + sizeof params);
    c->tx_busy = 1;
}

static void ccid_error(struct ccid *c, int offset)
{
    uint8_t ccid_reply[CCID_MSG_HEADER_SIZE];

    ccid_reply[0] = CCID_SLOT_STATUS_RET; /* Any value should be OK */
    ccid_reply[1] = 0x00;
    ccid_reply[2] = 0x00;
    ccid_reply[3] = 0x00;
    ccid_reply[4] = 0x00;
    ccid_reply[5] = 0x00;	/* Slot */
    ccid_reply[CCID_MSG_SEQ_OFFSET] = c->ccid_header.seq;
    if (c->ccid_state == CCID_STATE_NOCARD)
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 2; /* 2: No ICC present */
    else if (c->ccid_state == CCID_STATE_START)
        /* 1: ICC present but not activated */
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 1;
    else
        ccid_reply[CCID_MSG_STATUS_OFFSET] = 0; /* An ICC is present and active */
    ccid_reply[CCID_MSG_STATUS_OFFSET] |= CCID_CMD_STATUS_ERROR; /* Failed */
    ccid_reply[CCID_MSG_ERROR_OFFSET] = offset;
    ccid_reply[CCID_MSG_CHAIN_OFFSET] = 0x00;

    /* This is a single packet Bulk-IN transaction */
    c->epi->buf = NULL;
    c->epi->tx_done = 1;
    memcpy (endp1_tx_buf, ccid_reply, CCID_MSG_HEADER_SIZE);
    usb_tx_enable (endp1_tx_buf, CCID_MSG_HEADER_SIZE);
    c->tx_busy = 1;
}

#define INS_GET_RESPONSE 0xc0

static enum ccid_state ccid_handle_data(struct ccid *c)
{
    enum ccid_state next_state = c->ccid_state;

    TU_LOG3("---- CCID STATE %d,msg_type %x,start %d\r\n",c->ccid_state,c->ccid_header.msg_type,CCID_STATE_START);
    if (c->err != 0)
    {
        ccid_reset(c);
        ccid_error(c, CCID_OFFSET_DATA_LEN);
        return next_state;
    }
    switch (c->ccid_state)
    {
        case CCID_STATE_NOCARD:
            if (c->ccid_header.msg_type == CCID_SLOT_STATUS)
	            ccid_send_status(c);
            else
        	{
        	  DEBUG_INFO ("ERR00\r\n");
        	  ccid_error(c, CCID_OFFSET_CMD_NOT_SUPPORTED);
        	}
            break;
        case CCID_STATE_START:
            if (c->ccid_header.msg_type == CCID_POWER_ON)
        	{
        	    ccid_reset(c);
        	    next_state = ccid_power_on(c);
        	}
            else if (c->ccid_header.msg_type == CCID_POWER_OFF)
        	{
        	    ccid_reset(c);
        	    next_state = ccid_power_off(c);
        	}
            else if (c->ccid_header.msg_type == CCID_SLOT_STATUS)
    	        ccid_send_status (c);
            else
        	{
        	    DEBUG_INFO("ERR01\r\n");
        	    ccid_error(c, CCID_OFFSET_CMD_NOT_SUPPORTED);
        	}
            break;
        case CCID_STATE_WAIT:
            if (c->ccid_header.msg_type == CCID_POWER_ON)
        	{
        	    /* Not in the spec., but pcscd/libccid */
        	    ccid_reset(c);
        	    next_state = ccid_power_on(c);
        	}
            else if (c->ccid_header.msg_type == CCID_POWER_OFF)
        	{
        	    ccid_reset(c);
        	    next_state = ccid_power_off(c);
        	}
            else if (c->ccid_header.msg_type == CCID_SLOT_STATUS)
    	        ccid_send_status(c);
            else if (c->ccid_header.msg_type == CCID_XFR_BLOCK)
    	    {
    	        if (c->ccid_header.param == 0)
    	        {
    	            if ((c->a->cmd_apdu_head[0] & 0x10) == 0)
    		        {
    		            if (c->state == APDU_STATE_COMMAND_CHAINING)
            		    {		/* command chaining finished */
            		        c->p += c->a->cmd_apdu_head[4];
            		        c->a->cmd_apdu_head[4] = 0;
            		        DEBUG_INFO ("CMD chaning finished.\r\n");
            		    }

    		            if (c->a->cmd_apdu_head[1] == INS_GET_RESPONSE && c->state == APDU_STATE_RESULT_GET_RESPONSE)
            		    {
            		        size_t len = c->a->expected_res_size;

            		        if (c->len <= c->a->expected_res_size)
            			        len = c->len;

            		        ccid_send_data_block_gr (c, len);
            		        if (c->len == 0)
            			        c->state = APDU_STATE_RESULT;
            		        c->ccid_state = CCID_STATE_WAIT;
            		        DEBUG_INFO ("GET Response.\r\n");
            		    }
        		        else
            		    {		  /* Give this message to GPG thread */
            		        c->state = APDU_STATE_COMMAND_RECEIVED;

            		        c->a->sw = 0x9000;
            		        c->a->res_apdu_data_len = 0;
            		        c->a->res_apdu_data = &ccid_buffer[5];
            		        
            		        uint32_t flag = EV_CMD_AVAILABLE;
            		        queue_try_add(&c->card_comm, &flag);

            		        next_state = CCID_STATE_EXECUTE;
            		    }
    		        }
    	            else
    		        {
    		            if (c->state == APDU_STATE_WAIT_COMMAND)
    		            {		/* command chaining is started */
            		        c->a->cmd_apdu_head[0] &= ~0x10;
            		        memcpy (c->chained_cls_ins_p1_p2, c->a->cmd_apdu_head, 4);
            		        c->state = APDU_STATE_COMMAND_CHAINING;
            		    }

                        c->p += c->a->cmd_apdu_head[4];
                        c->len -= c->a->cmd_apdu_head[4];
                        ccid_send_data_block_0x9000 (c);
                        DEBUG_INFO ("CMD chaning...\r\n");
    		        }
    	        }
    	        else
    	        {		     /* ICC block chaining is not supported. */
                    DEBUG_INFO ("ERR02\r\n");
                    ccid_error (c, CCID_OFFSET_PARAM);
    	        }
    	    }
            else if (c->ccid_header.msg_type == CCID_SET_PARAMS || c->ccid_header.msg_type == CCID_GET_PARAMS || c->ccid_header.msg_type == CCID_RESET_PARAMS)
    	        ccid_send_params(c);
            else
    	    {
                DEBUG_INFO ("ERR03\r\n");
                DEBUG_BYTE (c->ccid_header.msg_type);
                ccid_error (c, CCID_OFFSET_CMD_NOT_SUPPORTED);
    	    }
            break;
        case CCID_STATE_EXECUTE:
        case CCID_STATE_ACK_REQUIRED_0:
        case CCID_STATE_ACK_REQUIRED_1:
            if (c->ccid_header.msg_type == CCID_POWER_OFF)
    	        next_state = ccid_power_off (c);
            else if (c->ccid_header.msg_type == CCID_SLOT_STATUS)
    	        ccid_send_status (c);
            else
        	{
        	    DEBUG_INFO ("ERR04\r\n");
        	    DEBUG_BYTE (c->ccid_header.msg_type);
        	    ccid_error (c, CCID_OFFSET_CMD_NOT_SUPPORTED);
        	}
            break;
        default:
            next_state = CCID_STATE_START;
            DEBUG_INFO ("ERR10\r\n");
            break;
    }

    return next_state;
}

static enum ccid_state ccid_handle_timeout(struct ccid *c)
{
    enum ccid_state next_state = c->ccid_state;
    switch (c->ccid_state)
    {
        case CCID_STATE_EXECUTE:
        case CCID_STATE_ACK_REQUIRED_0:
        case CCID_STATE_ACK_REQUIRED_1:
            ccid_send_data_block_time_extension(c);
            break;
        default:
        break;
    }

    return next_state;
}


static void notify_icc (struct ep_out *epo)
{
    struct ccid *c = (struct ccid *)epo->priv;
    c->err = epo->err;
    uint32_t val = EV_RX_DATA_READY;
    queue_try_add(&c->ccid_comm, &val);
}

static int end_ccid_rx (struct ep_out *epo, size_t orig_len)
{
    (void)orig_len;
    if (epo->cnt < sizeof (struct ccid_header))
        /* short packet, just ignore */
        return 1;

    /* icc message with no abdata */
    return 0;
}

static int end_abdata (struct ep_out *epo, size_t orig_len)
{
    struct ccid *c = (struct ccid *)epo->priv;
    size_t len = epo->cnt;

    if (orig_len == USB_LL_BUF_SIZE && len < c->ccid_header.data_len)
        /* more packet comes */
        return 1;

    if (len != c->ccid_header.data_len)
        epo->err = 1;

    return 0;
}

static int end_cmd_apdu_head (struct ep_out *epo, size_t orig_len)
{
    struct ccid *c = (struct ccid *)epo->priv;

    (void)orig_len;

    if (epo->cnt < 4 || epo->cnt != c->ccid_header.data_len)
    {
        epo->err = 1;
        return 0;
    }

    if ((c->state == APDU_STATE_COMMAND_CHAINING)
        && (c->chained_cls_ins_p1_p2[0] != (c->a->cmd_apdu_head[0] & ~0x10)
        || c->chained_cls_ins_p1_p2[1] != c->a->cmd_apdu_head[1]
        || c->chained_cls_ins_p1_p2[2] != c->a->cmd_apdu_head[2]
        || c->chained_cls_ins_p1_p2[3] != c->a->cmd_apdu_head[3]))
    /*
     * Handling exceptional request.
     *
     * Host stops sending command APDU using command chaining,
     * and start another command APDU.
     *
     * Discard old one, and start handling new one.
     */
    {
        c->state = APDU_STATE_WAIT_COMMAND;
        c->p = c->a->cmd_apdu_data;
        c->len = MAX_CMD_APDU_DATA_SIZE;
    }

    if (epo->cnt == 4)
        /* No Lc and Le */
        c->a->expected_res_size = 0;
    else if (epo->cnt == 5)
    {
        /* No Lc but Le */
        c->a->expected_res_size = c->a->cmd_apdu_head[4];
        if (c->a->expected_res_size == 0)
	        c->a->expected_res_size = 256;
        c->a->cmd_apdu_head[4] = 0;
    }
    else if (epo->cnt == 9) { //extended
        c->a->expected_res_size = (c->a->cmd_apdu_head[7] << 8) | c->a->cmd_apdu_head[8];
        if (c->a->expected_res_size == 0)
	        c->a->expected_res_size = 65536;
    }

    c->a->cmd_apdu_data_len = 0;
    return 0;
}

static int end_nomore_data (struct ep_out *epo, size_t orig_len)
{
    (void)epo;
    if (orig_len == USB_LL_BUF_SIZE)
        return 1;
    else
        return 0;
}

static int end_cmd_apdu_data (struct ep_out *epo, size_t orig_len)
{
    struct ccid *c = (struct ccid *)epo->priv;
    size_t len = epo->cnt;

    if (orig_len == USB_LL_BUF_SIZE && CMD_APDU_HEAD_SIZE + len < c->ccid_header.data_len)
        /* more packet comes */
        return 1;

    if (CMD_APDU_HEAD_SIZE + len != c->ccid_header.data_len)
        goto error;
    //len is the length after lc (whole APDU = len+5)
    if (c->a->cmd_apdu_head[4] == 0 && len >= 2) { //extended
        if (len == 2) {
            c->a->expected_res_size = (c->a->cmd_apdu_head[5] << 8) | c->a->cmd_apdu_head[6];
            if (c->a->expected_res_size == 0)
                c->a->expected_res_size = 0xffff+1;
        }
        else {
            c->a->cmd_apdu_data_len = (c->a->cmd_apdu_data[0] << 8) | c->a->cmd_apdu_data[1];
            len -= 2;
            if (len < c->a->cmd_apdu_data_len)
                goto error;
            c->a->cmd_apdu_data += 2;
            if (len == c->a->cmd_apdu_data_len) //no LE
                c->a->expected_res_size = 0;
            else {
                if (len - c->a->cmd_apdu_data_len < 2)
                    goto error;
                c->a->expected_res_size = (c->a->cmd_apdu_data[c->a->cmd_apdu_data_len] << 8) | c->a->cmd_apdu_data[c->a->cmd_apdu_data_len+1];
                if (c->a->expected_res_size == 0)
                    c->a->expected_res_size = 0xffff+1;
            }
        }
    }
    else {

        if (len == c->a->cmd_apdu_head[4])
            /* No Le field*/
            c->a->expected_res_size = 0;
        else if (len == (size_t)c->a->cmd_apdu_head[4] + 1)
        {
            /* it has Le field*/
            c->a->expected_res_size = epo->buf[-1];
            if (c->a->expected_res_size == 0)
    	        c->a->expected_res_size = 256;
            len--;
        }
        else
        {
            error:
                DEBUG_INFO("APDU header size error");
                epo->err = 1;
                return 0;
        }
    
        c->a->cmd_apdu_data_len += len;
    }
    return 0;
}

static void nomore_data (struct ep_out *epo, size_t len)
{
    (void)len;
    epo->err = 1;
    epo->end_rx = end_nomore_data;
    epo->buf = NULL;
    epo->buf_len = 0;
    epo->cnt = 0;
    epo->next_buf = nomore_data;
    epo->ready = 0;
}

static void ccid_cmd_apdu_data (struct ep_out *epo, size_t len)
{
    struct ccid *c = (struct ccid *)epo->priv;

    (void)len;
    if (c->state == APDU_STATE_RESULT_GET_RESPONSE && c->a->cmd_apdu_head[1] != INS_GET_RESPONSE)
    {
        /*
        * Handling exceptional request.
        *
        * Host didn't finish receiving the whole response APDU by GET RESPONSE,
        * but initiates another command.
        */

        c->state = APDU_STATE_WAIT_COMMAND;
        c->p = c->a->cmd_apdu_data;
        c->len = MAX_CMD_APDU_DATA_SIZE;
    }
    else if (c->state == APDU_STATE_COMMAND_CHAINING)
    {
        if (c->chained_cls_ins_p1_p2[0] != (c->a->cmd_apdu_head[0] & ~0x10)
	        || c->chained_cls_ins_p1_p2[1] != c->a->cmd_apdu_head[1]
	        || c->chained_cls_ins_p1_p2[2] != c->a->cmd_apdu_head[2]
	        || c->chained_cls_ins_p1_p2[3] != c->a->cmd_apdu_head[3])
    	/*
    	 * Handling exceptional request.
    	 *
    	 * Host stops sending command APDU using command chaining,
    	 * and start another command APDU.
    	 *
    	 * Discard old one, and start handling new one.
    	 */
    	{
            c->state = APDU_STATE_WAIT_COMMAND;
            c->p = c->a->cmd_apdu_data;
            c->len = MAX_CMD_APDU_DATA_SIZE;
            c->a->cmd_apdu_data_len = 0;
        }
    }

    epo->end_rx = end_cmd_apdu_data;
    epo->buf = c->p;
    epo->buf_len = c->len;
    epo->cnt = 0;
    epo->next_buf = nomore_data;
}

static void ccid_abdata (struct ep_out *epo, size_t len)
{
    struct ccid *c = (struct ccid *)epo->priv;

    (void)len;
    c->a->seq = c->ccid_header.seq;
    if (c->ccid_header.msg_type == CCID_XFR_BLOCK)
    {
        c->a->seq = c->ccid_header.seq;
        epo->end_rx = end_cmd_apdu_head;
        epo->buf = c->a->cmd_apdu_head;
        epo->buf_len = 5;
        epo->cnt = 0;
        epo->next_buf = ccid_cmd_apdu_data;
    }
    else
    {
        epo->end_rx = end_abdata;
        epo->buf = c->p;
        epo->buf_len = c->len;
        epo->cnt = 0;
        epo->next_buf = nomore_data;
    }
}

static void ccid_prepare_receive (struct ccid *c)
{
    c->epo->err = 0;
    c->epo->buf = (uint8_t *)&c->ccid_header;
    c->epo->buf_len = sizeof (struct ccid_header);
    c->epo->cnt = 0;
    c->epo->next_buf = ccid_abdata;
    c->epo->end_rx = end_ccid_rx;
    c->epo->ready = 1;
}

static void ccid_rx_ready (uint16_t len)
{
    /*
    * If we support multiple CCID interfaces, we select endpoint object
    * by EP_NUM.  Because it has only single CCID interface now, it's
    * hard-coded, here.
    */
    struct ep_out *epo = &endpoint_out;
    int offset = 0;
    int cont;
    size_t orig_len = len;
    while (epo->err == 0)
    {
        if (len == 0)
            break;
        else if (len <= epo->buf_len)
        {
	        memcpy (epo->buf, endp1_rx_buf + offset, len);
        	epo->buf += len;
        	epo->cnt += len;
        	epo->buf_len -= len;
	        break;
        }
        else /* len > buf_len */
        {
	        memcpy (epo->buf, endp1_rx_buf + offset, epo->buf_len);
    	    len -= epo->buf_len;
        	offset += epo->buf_len;
        	epo->next_buf (epo, len); /* Update epo->buf, cnt, buf_len */
        }
    }

    /*
    * ORIG_LEN to distingush ZLP and the end of transaction
    *  (ORIG_LEN != USB_LL_BUF_SIZE)
    */
    cont = epo->end_rx (epo, orig_len);

    if (cont == 0)
        notify_icc (epo);
    else
        epo->ready = 1;
}

static void notify_tx (struct ep_in *epi)
{
    struct ccid *c = (struct ccid *)epi->priv;

    /* The sequence of Bulk-IN transactions finished */
    uint32_t flag = EV_TX_FINISHED;
    queue_try_add(&c->ccid_comm, &flag);
    c->tx_busy = 0;
}

static void ccid_tx_done ()
{
  /*
   * If we support multiple CCID interfaces, we select endpoint object
   * by EP_NUM.  Because it has only single CCID interface now, it's
   * hard-coded, here.
   */
    struct ep_in *epi = &endpoint_in;
    if (epi->buf == NULL)
    {
        if (epi->tx_done)
            notify_tx (epi);
        else
        {
	        epi->tx_done = 1;
	        usb_tx_enable (endp1_tx_buf, 0);
        }
    }
    else
    {
        int tx_size = 0;
        size_t remain = USB_LL_BUF_SIZE;
        int offset = 0;

        while (epi->buf)
        {
    	    if (epi->buf_len < remain)
    	    {
        	    memcpy (endp1_tx_buf+offset, epi->buf, epi->buf_len);
        	    offset += epi->buf_len;
        	    remain -= epi->buf_len;
        	    tx_size += epi->buf_len;
        	    epi->next_buf (epi, remain); /* Update epi->buf, cnt, buf_len */
    	    }
    	    else
    	    {
    	        memcpy (endp1_tx_buf+offset, epi->buf, remain);
        	    epi->buf += remain;
        	    epi->cnt += remain;
        	    epi->buf_len -= remain;
        	    tx_size += remain;
        	    break;
    	    }
    	}
        if (tx_size < USB_LL_BUF_SIZE)
	        epi->tx_done = 1;
	    
	    usb_tx_enable (endp1_tx_buf, tx_size);
    }
}

static int usb_event_handle(struct ccid *c)
{
    TU_LOG3("!!! tx %d, vendor %d, cfg %d, rx %d\r\n",c->tx_busy,tud_vendor_n_write_available(0),CFG_TUD_VENDOR_TX_BUFSIZE,tud_vendor_available());
    if (c->tx_busy == 1 && tud_vendor_n_write_available(0) == CFG_TUD_VENDOR_TX_BUFSIZE)
    {
        ccid_tx_done ();
    }
    if (tud_vendor_available() && c->epo->ready)
    {
        uint32_t count = tud_vendor_read(endp1_rx_buf, sizeof(endp1_rx_buf));
        if (endp1_rx_buf[0] != 0x65)
            DEBUG_PAYLOAD(endp1_rx_buf, count);
        //DEBUG_PAYLOAD(endp1_rx_buf, count);
        ccid_rx_ready(count);
    }
    return 0;
}

uint32_t timeout = USB_CCID_TIMEOUT;
static uint32_t prev_millis = 0;

void prepare_ccid()
{
    struct ep_in *epi = &endpoint_in;
    struct ep_out *epo = &endpoint_out;
    struct ccid *c = &ccid;
    struct apdu *a = &apdu;

    epi_init (epi, 1, c);
    epo_init (epo, 2, c);

    apdu_init(a);
    ccid_init (c, epi, epo, a);
}

int process_apdu() {
    blink_interval_ms = BLINK_PROCESSING;
    if (!current_app) {
        if (INS(apdu) == 0xA4 && P1(apdu) == 0x04 && (P2(apdu) == 0x00 || P2(apdu) == 0x4)) { //select by AID
            for (int a = 0; a < num_apps; a++) {
                if ((current_app = apps[a].select_aid(&apps[a]))) {
                    return set_res_sw(0x90,0x00);
                }
            }
        }
        return set_res_sw(0x6a, 0x82);
    }
    if (current_app->process_apdu)
        return current_app->process_apdu();
    return set_res_sw (0x6D, 0x00);
}

uint16_t set_res_sw (uint8_t sw1, uint8_t sw2)
{
    apdu.sw = (sw1 << 8) | sw2;
    return make_uint16_t(sw1, sw2);
}

static void card_init (void)
{
    //gpg_data_scan (flash_do_start, flash_do_end);
    low_flash_init_core1();
}

void card_thread()
{
    queue_t *ccid_comm = (queue_t *)multicore_fifo_pop_blocking();
    card_comm = (queue_t *)multicore_fifo_pop_blocking();

    card_init ();

    while (1)
    {    
        uint32_t m;
        queue_remove_blocking(card_comm, &m);
        
        if (m == EV_VERIFY_CMD_AVAILABLE || m == EV_MODIFY_CMD_AVAILABLE)
	    {
	        set_res_sw (0x6f, 0x00);
	        goto done;
	    }
        else if (m == EV_EXIT) {
            if (current_app && current_app->unload)
                current_app->unload();
	        break;
	    }

        process_apdu();
        
        done:;
        uint32_t flag = EV_EXEC_FINISHED;
        queue_add_blocking(ccid_comm, &flag);
    }
    
    if (current_app && current_app->unload)
        current_app->unload();
}


void ccid_task(void)
{
    struct ccid *c = &ccid;
    if (tud_vendor_mounted())
    {
        // connected and there are data available
        if ((c->epo->ready && tud_vendor_available()) || (tud_vendor_n_write_available(0) == CFG_TUD_VENDOR_TX_BUFSIZE && c->tx_busy == 1))
        {
            if (usb_event_handle (c) != 0)
        	{
                if (c->application)
                {
                    uint32_t flag = EV_EXIT;
                    queue_try_add(&c->ccid_comm, &flag);
                    c->application = 0;
                }
                prepare_ccid();
                return;
            }
        }
        if (timeout == 0) 
        {
    	    timeout = USB_CCID_TIMEOUT;
    	    c->timeout_cnt++;
        }
        uint32_t m = 0x0;
        bool has_m = queue_try_remove(&c->ccid_comm, &m);
        if (m != 0)
            TU_LOG3("\r\n ------ M = %d\r\n",m);
        if (has_m)
        {
            if (m == EV_CARD_CHANGE)
	        {
	            if (c->ccid_state == CCID_STATE_NOCARD)
	                /* Inserted!  */
	                c->ccid_state = CCID_STATE_START;
	            else
	            { /* Removed!  */
	                if (c->application)
		            {
		                uint32_t flag = EV_EXIT;
		                queue_try_add(&c->card_comm, &flag);
		                c->application = 0;
		            }
                    c->ccid_state = CCID_STATE_NOCARD;
	            }
                //ccid_notify_slot_change (c);
	        }
            else if (m == EV_RX_DATA_READY)
        	{
        	    c->ccid_state = ccid_handle_data(c);
        	    timeout = 0;
        	    c->timeout_cnt = 0;
        	}
            else if (m == EV_EXEC_FINISHED)
            {
	            if (c->ccid_state == CCID_STATE_EXECUTE)
	            {
	                exec_done:
            	    if (c->a->sw == GPG_THREAD_TERMINATED)
            	    {
                		c->sw1sw2[0] = 0x90;
                		c->sw1sw2[1] = 0x00;
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_EXITED;
                		c->application = 0;
                		return;
            	    }

            	    c->a->cmd_apdu_data_len = 0;
            	    c->sw1sw2[0] = c->a->sw >> 8;
            	    c->sw1sw2[1] = c->a->sw & 0xff;
            	    if (c->a->res_apdu_data_len <= c->a->expected_res_size)
            	    {
                		c->state = APDU_STATE_RESULT;
                		ccid_send_data_block(c);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	    else
            	    {
                		c->state = APDU_STATE_RESULT_GET_RESPONSE;
                		c->p = c->a->res_apdu_data;
                		c->len = c->a->res_apdu_data_len;
                		ccid_send_data_block_gr(c, c->a->expected_res_size);
                		c->ccid_state = CCID_STATE_WAIT;
            	    }
            	}
            	else
        	    {
        	        DEBUG_INFO ("ERR05\r\n");
        	    }
        	    blink_interval_ms = BLINK_MOUNTED;
            }
            else if (m == EV_TX_FINISHED)
        	{
        	    if (c->state == APDU_STATE_RESULT)
        	        ccid_reset(c);
        	    else
        	        c->tx_busy = 0;
        	    if (c->state == APDU_STATE_WAIT_COMMAND || c->state == APDU_STATE_COMMAND_CHAINING || c->state == APDU_STATE_RESULT_GET_RESPONSE)
        	        ccid_prepare_receive(c);
        	}
        }
        else			/* Timeout */
        {            
            timeout -= MIN(board_millis()-prev_millis,timeout);
            if (timeout == 0)
        	{
                if (c->timeout_cnt == 7 && c->ccid_state == CCID_STATE_ACK_REQUIRED_1)
                {
                    c->a->sw = GPG_ACK_TIMEOUT;
                    c->a->res_apdu_data_len = 0;
                    c->a->sw = GPG_ACK_TIMEOUT;
                    c->a->res_apdu_data_len = 0;
    
                    goto exec_done;
                }
                else
                    c->ccid_state = ccid_handle_timeout(c);
            }
        }
    }
}

void tud_mount_cb()
{
    ccid_prepare_receive (&ccid);
}

void led_blinking_task()
{
    static uint32_t start_ms = 0;
    static uint8_t led_state = false;
    static uint8_t led_color = BLINK_RED;
    uint32_t interval = !led_state ? blink_interval_ms & 0xffff : blink_interval_ms >> 16;
    

    // Blink every interval ms
    if (board_millis() - start_ms < interval)
        return; // not enough time
    start_ms += interval;

    gpio_put(led_color, led_state);
    led_state ^= 1; // toggle
}

void led_off_all()
{
    gpio_put(18, 1);
    gpio_put(19, 1);
    gpio_put(20, 1);
}

extern void neug_task();

pico_unique_board_id_t unique_id;

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

    prepare_ccid();
    
    random_init();
    
    low_flash_init();
      
    while (1)
    {
        prev_millis = board_millis();
        ccid_task();
        tud_task(); // tinyusb device task
        led_blinking_task();
        neug_task();
        do_flash();
    }

    return 0;
}