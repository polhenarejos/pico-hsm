#ifndef _CCID_H_
#define _CCID_H_

#include "ccid-types.h"

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
    .bPINSupport            = 0x0,
                              /*
                              0x1|      // PIN Verification supported
                              0x2|      // PIN Modification supported
                              0x10|     // PIN PACE Capabilities supported
                              0x20,     // PIN PACE Verification supported
                              */
    .bMaxCCIDBusySlots      = 0x01,
};

#endif