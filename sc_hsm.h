#ifndef _SC_HSM_H_
#define _SC_HSM_H_

#include <stdlib.h>
#include "pico/stdlib.h"
#include "hsm2040.h"

extern const uint8_t sc_hsm_aid[];

#define SW_BYTES_REMAINING_00()             set_res_sw (0x61, 0x00)
#define SW_WARNING_STATE_UNCHANGED()        set_res_sw (0x62, 0x00)
#define SW_PIN_BLOCKED()                    set_res_sw (0x63, 0x00)
#define SW_MEMORY_FAILURE()                 set_res_sw (0x65, 0x81)
#define SW_WRONG_LENGTH()                   set_res_sw (0x67, 0x00)
#define SW_WRONG_DATA()                     set_res_sw (0x67, 0x00)
#define SW_LOGICAL_CHANNEL_NOT_SUPPORTED()  set_res_sw (0x68, 0x81)
#define SW_SECURE_MESSAGING_NOT_SUPPORTED() set_res_sw (0x68, 0x82)
#define SW_SECURITY_STATUS_NOT_SATISFIED()  set_res_sw (0x69, 0x82)
#define SW_FILE_INVALID()                   set_res_sw (0x69, 0x83)
#define SW_DATA_INVALID()                   set_res_sw (0x69, 0x84)
#define SW_CONDITIONS_NOT_SATISFIED()       set_res_sw (0x69, 0x85)
#define SW_COMMAND_NOT_ALLOWED()            set_res_sw (0x69, 0x86)
#define SW_APPLET_SELECT_FAILED()           set_res_sw (0x69, 0x99)
#define SW_FUNC_NOT_SUPPORTED()             set_res_sw (0x6A, 0x81)
#define SW_FILE_NOT_FOUND()                 set_res_sw (0x6A, 0x82)
#define SW_RECORD_NOT_FOUND()               set_res_sw (0x6A, 0x83)
#define SW_FILE_FULL()                      set_res_sw (0x6A, 0x84)
#define SW_INCORRECT_P1P2()                 set_res_sw (0x6A, 0x86)
#define SW_REFERENCE_NOT_FOUND()            set_res_sw (0x6A, 0x88)
#define SW_WRONG_P1P2()                     set_res_sw (0x6B, 0x00)
#define SW_CORRECT_LENGTH_00()              set_res_sw (0x6C, 0x00)
#define SW_INS_NOT_SUPPORTED()              set_res_sw (0x6D, 0x00)
#define SW_CLA_NOT_SUPPORTED()              set_res_sw (0x6E, 0x00)
#define SW_UNKNOWN()                        set_res_sw (0x6F, 0x00)
#define SW_OK()                             set_res_sw (0x90, 0x00)

#define HSM_OK                              0
#define HSM_ERR_NO_MEMORY                   -1000
#define HSM_ERR_MEMORY_FATAL                -1001
#define HSM_ERR_NULL_PARAM                  -1002
#define HSM_ERR_FILE_NOT_FOUND              -1003
#define HSM_ERR_BLOCKED                     -1004

extern int pin_reset_retries(const file_t *pin);
extern int pin_wrong_retry(const file_t *pin);

extern void hash(const uint8_t *input, size_t len, uint8_t output[32]);
extern void hash_multi(const uint8_t *input, size_t len, uint8_t output[32]);
extern void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]);

extern uint8_t session_pin[32], session_sopin[32];

#define IV_SIZE 16

#endif