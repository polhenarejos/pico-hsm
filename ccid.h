#ifndef _CCID_H_
#define _CCID_H_

#include "ccid-types.h"

struct apdu {
  uint8_t seq;

  /* command APDU */
  uint8_t *cmd_apdu_head;	/* CLS INS P1 P2 [ internal Lc ] */
  uint8_t *cmd_apdu_data;
  uint16_t cmd_apdu_data_len;	/* Nc, calculated by Lc field */
  uint16_t expected_res_size;	/* Ne, calculated by Le field */

  /* response APDU */
  uint16_t sw;
  uint16_t res_apdu_data_len;
  uint8_t *res_apdu_data;
};

extern struct apdu apdu;

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

#define APDU_STATE_WAIT_COMMAND        0
#define APDU_STATE_COMMAND_CHAINING    1
#define APDU_STATE_COMMAND_RECEIVED    2
#define APDU_STATE_RESULT              3
#define APDU_STATE_RESULT_GET_RESPONSE 4

/* Maximum cmd apdu data is key import 24+4+256+256 (proc_key_import) */
#define MAX_CMD_APDU_DATA_SIZE (24+4+256+256) /* without header */
/* Maximum res apdu data is public key 5+9+512 (gpg_do_public_key) */
#define MAX_RES_APDU_DATA_SIZE (5+9+512) /* without trailer */

#define CCID_MSG_HEADER_SIZE	10


static const class_desc_ccid_t desc_ccid = {
    .bLength                = sizeof (class_desc_ccid_t),
    .bDescriptorType        = 0x21,
    .bcdCCID                = (0x0110),
    .bMaxSlotIndex          = 0,
    .bVoltageSupport        = 0x01,  // 5.0V
    .dwProtocols            = (
                              0x01|  // T=0
                              0x02), // T=1
    .dwDefaultClock         = (0xDFC),
    .dwMaximumClock         = (0xDFC),
    .bNumClockSupport       = 1,
    .dwDataRate             = (0x2580),
    .dwMaxDataRate          = (0x2580),
    .bNumDataRatesSupported = 1,
    .dwMaxIFSD              = (0xFF), // IFSD is handled by the real reader driver
    .dwSynchProtocols       = (0),
    .dwMechanical           = (0),
    .dwFeatures             = (
                              0x00000002|  // Automatic parameter configuration based on ATR data
                              0x00000004|  // Automatic activation of ICC on inserting
                              0x00000008|  // Automatic ICC voltage selection
                              0x00000010|  // Automatic ICC clock frequency change
                              0x00000020|  // Automatic baud rate change
                              0x00000040|  // Automatic parameters negotiation
                              0x00000080|  // Automatic PPS   
                              0x00000400|  // Automatic IFSD exchange as first exchange
                              0x00040000|  // Short and Extended APDU level exchange with CCID
                              0x00100000), // USB Wake up signaling supported
    .dwMaxCCIDMessageLength = (CCID_EXT_APDU_MAX),
    .bClassGetResponse      = 0xFF,
    .bclassEnvelope         = 0xFF,
    .wLcdLayout             = (
                              0xFF00|   // Number of lines for the LCD display
                              0x00FF),  // Number of characters per line
    .bPINSupport            = 0x1|      // PIN Verification supported
                              0x2|      // PIN Modification supported
                              0x10|     // PIN PACE Capabilities supported
                              0x20,     // PIN PACE Verification supported
    .bMaxCCIDBusySlots      = 0x01,
};

#endif