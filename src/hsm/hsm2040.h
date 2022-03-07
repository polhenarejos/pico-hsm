/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _HSM2040_H_
#define _HSM2040_H_

#include "ccid.h"
#include "tusb.h"
#include "file.h"
#include "pico/unique_id.h"

#define USB_REQ_CCID        0xA1

typedef struct app {
    const uint8_t *aid;
    int (*process_apdu)();
    struct app* (*select_aid)();
    int (*unload)();
} app_t;

extern int register_app(app_t * (*)());

extern const uint8_t historical_bytes[];

#define DEBUG_PAYLOAD(p,s) { \
    printf("Payload %s (%d bytes):\r\n", #p,s);\
    for (int i = 0; i < s; i += 16) {\
        printf("%07Xh : ",i+p);\
        for (int j = 0; j < 16; j++) {\
            if (j < s-i) printf("%02X ",(p)[i+j]);\
            else printf("   ");\
            if (j == 7) printf(" ");\
            } printf(":  "); \
        for (int j = 0; j < MIN(16,s-i); j++) {\
            printf("%c",(p)[i+j] == 0x0a || (p)[i+j] == 0x0d ? '\\' : (p)[i+j]);\
            if (j == 7) printf(" ");\
            }\
            printf("\r\n");\
        } printf("\r\n"); \
    }
    
struct apdu {
  uint8_t seq;

  /* command APDU */
  uint8_t *cmd_apdu_head;	/* CLS INS P1 P2 [ internal Lc ] */
  uint8_t *cmd_apdu_data;
  size_t cmd_apdu_data_len;	/* Nc, calculated by Lc field */
  size_t expected_res_size;	/* Ne, calculated by Le field */

  /* response APDU */
  uint16_t sw;
  uint16_t res_apdu_data_len;
  uint8_t *res_apdu_data;
};

#define MAX_CMD_APDU_DATA_SIZE (24+4+256+256)
#define MAX_RES_APDU_DATA_SIZE (5+9+512)
#define CCID_MSG_HEADER_SIZE    10
#define USB_LL_BUF_SIZE         64

/* CCID thread */
#define EV_CARD_CHANGE        1
#define EV_TX_FINISHED        2 /* CCID Tx finished  */
#define EV_EXEC_ACK_REQUIRED  4 /* OpenPGPcard Execution ACK required */
#define EV_EXEC_FINISHED      8 /* OpenPGPcard Execution finished */
#define EV_RX_DATA_READY     16 /* USB Rx data available  */

/* OpenPGPcard thread */
#define EV_MODIFY_CMD_AVAILABLE   1
#define EV_VERIFY_CMD_AVAILABLE   2
#define EV_CMD_AVAILABLE          4
#define EV_EXIT                   8
#define EV_PINPAD_INPUT_DONE     16

enum ccid_state {
    CCID_STATE_NOCARD,		/* No card available */
    CCID_STATE_START,		/* Initial */
    CCID_STATE_WAIT,		/* Waiting APDU */
    
    CCID_STATE_EXECUTE,		/* Executing command */
    CCID_STATE_ACK_REQUIRED_0,	/* Ack required (executing)*/
    CCID_STATE_ACK_REQUIRED_1,	/* Waiting user's ACK (execution finished) */
    
    CCID_STATE_EXITED,		/* CCID Thread Terminated */
    CCID_STATE_EXEC_REQUESTED,	/* Exec requested */
};

#define CLS(a) a.cmd_apdu_head[0]
#define INS(a) a.cmd_apdu_head[1]
#define P1(a) a.cmd_apdu_head[2]
#define P2(a) a.cmd_apdu_head[3]

#define res_APDU apdu.res_apdu_data
#define res_APDU_size apdu.res_apdu_data_len

extern struct apdu apdu;

uint16_t set_res_sw (uint8_t sw1, uint8_t sw2);


static inline const uint16_t make_uint16_t(uint8_t b1, uint8_t b2) {
    return (b1 << 8) | b2;
}
static inline const uint16_t get_uint16_t(const uint8_t *b, uint16_t offset) {
    return make_uint16_t(b[offset], b[offset+1]);
}
static inline const void put_uint16_t(uint16_t n, uint8_t *b) {
    *b++ = (n >> 8) & 0xff;
    *b = n & 0xff;
}


#ifdef DEBUG
void stdout_init (void);
#define DEBUG_MORE 1
/*
 * Debug functions in debug.c
 */
void put_byte (uint8_t b);
void put_byte_with_no_nl (uint8_t b);
void put_short (uint16_t x);
void put_word (uint32_t x);
void put_int (uint32_t x);
void put_string (const char *s);
void put_binary (const char *s, int len);

#define DEBUG_INFO(msg)	    put_string (msg)
#define DEBUG_WORD(w)	    put_word (w)
#define DEBUG_SHORT(h)	    put_short (h)
#define DEBUG_BYTE(b)       put_byte (b)
#define DEBUG_BINARY(s,len) put_binary ((const char *)s,len)
#else
#define DEBUG_INFO(msg)
#define DEBUG_WORD(w)
#define DEBUG_SHORT(h)
#define DEBUG_BYTE(b)
#define DEBUG_BINARY(s,len)
#endif

extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern void low_flash_available();
extern int flash_clear_file(file_t *file);

extern pico_unique_board_id_t unique_id;
#endif