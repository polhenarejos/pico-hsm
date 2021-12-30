/* 
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Ha Thach (tinyusb.org)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "tusb.h"
#include "usb_descriptors.h"
#include "ccid.h"

/* A combination of interfaces must have a unique product id, since PC will save device driver after the first plug.
 * Same VID/PID with different interface e.g MSC (first), then CDC (later) will possibly cause system error on PC.
 *
 * Auto ProductID layout's Bitmap:
 *   [MSB]       MIDI | HID | MSC | CDC          [LSB]
 */
#define _PID_MAP(itf, n)  ( (CFG_TUD_##itf) << (n) )
#define USB_PID           (0x4000 | _PID_MAP(CDC, 0) | _PID_MAP(MSC, 1) | _PID_MAP(HID, 2) | \
                           _PID_MAP(MIDI, 3) | _PID_MAP(VENDOR, 4) )
                           
#define USB_VID   0xCafe
#define USB_BCD   0x0200

#define USB_CONFIG_ATT_ONE TU_BIT(7)

#define	MAX_USB_POWER		1


//--------------------------------------------------------------------+
// Device Descriptors
//--------------------------------------------------------------------+
tusb_desc_device_t const desc_device =
{
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = (USB_BCD),

    // Use Interface Association Descriptor (IAD) for CDC
    // As required by USB Specs IAD's subclass must be common class (2) and protocol must be IAD (1)
    .bDeviceClass       = 0x00,
    .bDeviceSubClass    = 0,
    .bDeviceProtocol    = 0,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor           = (USB_VID),
    .idProduct          = (USB_PID),
    .bcdDevice          = (0x0100),

    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,

    .bNumConfigurations = 0x01
};

// Invoked when received GET DEVICE DESCRIPTOR
// Application return pointer to descriptor
uint8_t const * tud_descriptor_device_cb(void)
{
  return (uint8_t const *) &desc_device;
}

tusb_desc_interface_t const desc_interface = 
{
    .bLength            = sizeof(tusb_desc_interface_t),
    .bDescriptorType    = TUSB_DESC_INTERFACE,
    .bInterfaceNumber   = 0,
    .bAlternateSetting  = 0,
    .bNumEndpoints      = 2,
    .bInterfaceClass    = TUSB_CLASS_SMART_CARD,
    .bInterfaceSubClass = 0,
    .bInterfaceProtocol = 0,
    .iInterface         = 5,
};

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+

tusb_desc_configuration_t const desc_config  = 
{
    .bLength             = sizeof(tusb_desc_configuration_t),
  	.bDescriptorType     = TUSB_DESC_CONFIGURATION,
    .wTotalLength        = U16_TO_U8S_LE(sizeof(tusb_desc_configuration_t) + sizeof(tusb_desc_interface_t) + sizeof(class_desc_ccid_t) + 2*sizeof(tusb_desc_endpoint_t)),
  	.bNumInterfaces      = 1,
  	.bConfigurationValue = 3,
  	.iConfiguration      = 4,
  	.bmAttributes        = USB_CONFIG_ATT_ONE | TUSB_DESC_CONFIG_ATT_SELF_POWERED,
  	.bMaxPower           = TUSB_DESC_CONFIG_POWER_MA(MAX_USB_POWER+1),
};

tusb_desc_endpoint_t const desc_ep1 = 
{
    .bLength             = sizeof(tusb_desc_endpoint_t),
	.bDescriptorType     = TUSB_DESC_ENDPOINT,
	.bEndpointAddress    = TUSB_DIR_IN_MASK | 1,
	.bmAttributes.xfer   = TUSB_XFER_BULK,
	.wMaxPacketSize.size = U16_TO_U8S_LE(64),
	.bInterval           = 0
};

tusb_desc_endpoint_t const desc_ep2 = 
{
    .bLength             = sizeof(tusb_desc_endpoint_t),
	.bDescriptorType     = TUSB_DESC_ENDPOINT,
	.bEndpointAddress    = 2,
	.bmAttributes.xfer   = TUSB_XFER_BULK,
	.wMaxPacketSize.size = U16_TO_U8S_LE(64),
	.bInterval           = 1
};


// Invoked when received GET CONFIGURATION DESCRIPTOR
// Application return pointer to descriptor
// Descriptor contents must exist long enough for transfer to complete


static uint8_t desc_config_extended[sizeof(tusb_desc_configuration_t) + sizeof(tusb_desc_interface_t) + sizeof(class_desc_ccid_t) + 2*sizeof(tusb_desc_endpoint_t)];

uint8_t const * tud_descriptor_configuration_cb(uint8_t index)
{
  (void) index; // for multiple configurations
  
  static uint8_t initd = 0;
  if (initd == 0)
  {
      uint8_t *p = desc_config_extended;
      memcpy(p, &desc_config, sizeof(tusb_desc_configuration_t)); p += sizeof(tusb_desc_configuration_t);
      memcpy(p, &desc_interface, sizeof(tusb_desc_interface_t)); p += sizeof(tusb_desc_interface_t);
      memcpy(p, &desc_ccid, sizeof(class_desc_ccid_t)); p += sizeof(class_desc_ccid_t);
      memcpy(p, &desc_ep1, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
      memcpy(p, &desc_ep2, sizeof(tusb_desc_endpoint_t)); p += sizeof(tusb_desc_endpoint_t);
      initd = 1;
  }
  return (const uint8_t *)desc_config_extended;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+

// array of pointer to string descriptors
char const* string_desc_arr [] =
{
  (const char[]) { 0x09, 0x04 }, // 0: is supported language is English (0x0409)
  "TinyUSB",                     // 1: Manufacturer
  "TinyUSB Device",              // 2: Product
  "11223344",                      // 3: Serials, should use chip ID
  "TinyUSB Config",               // 4: Vendor Interface
  "TinyUSB Interface"
};

static uint16_t _desc_str[32];

// Invoked when received GET STRING DESCRIPTOR request
// Application return pointer to descriptor, whose contents must exist long enough for transfer to complete
uint16_t const* tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
  (void) langid;

  uint8_t chr_count;

  if ( index == 0)
  {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  }else
  {
    // Note: the 0xEE index string is a Microsoft OS 1.0 Descriptors.
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-defined-usb-descriptors

    if ( !(index < sizeof(string_desc_arr)/sizeof(string_desc_arr[0])) ) return NULL;

    const char* str = string_desc_arr[index];

    // Cap at max char
    chr_count = strlen(str);
    if ( chr_count > 31 ) chr_count = 31;

    // Convert ASCII string into UTF-16
    for(uint8_t i=0; i<chr_count; i++)
    {
      _desc_str[1+i] = str[i];
    }
  }

  // first byte is length (including header), second byte is string type
  _desc_str[0] = (TUSB_DESC_STRING << 8 ) | (2*chr_count + 2);

  return _desc_str;
}
