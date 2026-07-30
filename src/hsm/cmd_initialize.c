/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "sc_hsm.h"
#include "crypto_utils.h"
#include "files.h"
#include "random.h"
#include "kek.h"
#include "version.h"
#include "tlv.h"
#include "cvc.h"
#include "otp.h"
#include "object_authorization.h"
#include "usb.h"
#include <stdio.h>
#ifdef PICO_PLATFORM
#include "hardware/watchdog.h"
#endif

/* Upper bound on waiting for the re-personalisation write to become durable before the reset
 * below. Generous on purpose: a full-region erase is many sectors, and overshooting merely
 * costs a few idle milliseconds, whereas undershooting falls back to the async commit and
 * reintroduces the race the synchronous wait exists to remove. */
#define FLASH_COMMIT_SYNC_TIMEOUT_MS 10000

/* Grace period between arming the reset and it firing, so core 0 can transmit the APDU response
 * first. Without it the host reports "Card removed" for a command that actually succeeded. */
#define INITIALIZE_REBOOT_DELAY_MS 500

extern char __StackLimit;
static int heapLeft(void) {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

int cmd_initialize(void) {
    if (apdu.nc > 0) {
        uint8_t mkek[MKEK_SIZE];
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_SECURE_LOCK && !has_mkek_mask) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        int ret_mkek = load_mkek(mkek); //Try loading MKEK with previous session
        file_initialize_flash(true);
        scan_all();
        hsm_object_authorization_session_invalidate();
        has_session_pin = has_session_sopin = has_mkek_mask = false;
        uint8_t *p = NULL, *kds = NULL, *dkeks = NULL;
        tlv_item_t item;
        tlv_ctx_t ctxi;
        tlv_ctx_init(BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc), &ctxi);
        while (tlv_walk(&ctxi, &p, &item)) {
            uint16_t tag = item.tag;
            uint16_t tag_len = (uint16_t)item.value.len;
            uint8_t *tag_data = (uint8_t *)item.value.data;
            if (tag == 0x80) { //options
                file_t *tf = file_search(EF_DEVOPS);
                file_put_data(tf, CONST_BYTE_ARRAY(tag_data, tag_len));
            }
            else if (tag == 0x81) {   //user pin
                if (file_pin1 && file_pin1->data) {
                    uint8_t pin_data[34];
                    pin_data[0] = (uint8_t)tag_len;
                    pin_data[1] = 1; // Format
                    pin_derive_verifier(CONST_BYTE_ARRAY(tag_data, tag_len), pin_data + 2);
                    file_put_data(file_pin1, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));
                    pin_derive_session(CONST_BYTE_ARRAY(tag_data, tag_len), session_pin);
                    has_session_pin = true;
                }
            }
            else if (tag == 0x82) {   //sopin pin
                if (file_sopin && file_sopin->data) {
                    uint8_t pin_data[34];
                    pin_data[0] = (uint8_t)tag_len;
                    pin_data[1] = 1; // Format
                    pin_derive_verifier(CONST_BYTE_ARRAY(tag_data, tag_len), pin_data + 2);
                    file_put_data(file_sopin, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));
                    pin_derive_session(CONST_BYTE_ARRAY(tag_data, tag_len), session_sopin);
                    has_session_sopin = true;
                }
            }
            else if (tag == 0x91) {   //retries user pin
                file_t *tf = file_search(EF_PIN1_MAX_RETRIES);
                if (tf && tf->data) {
                    file_put_data(tf, CONST_BYTE_ARRAY(tag_data, tag_len));
                }
                if (file_retries_pin1 && file_retries_pin1->data) {
                    file_put_data(file_retries_pin1, CONST_BYTE_ARRAY(tag_data, tag_len));
                }
            }
            else if (tag == 0x92) {
                dkeks = tag_data;
                file_t *tf = file_new(EF_DKEK);
                if (!tf) {
                    release_mkek(mkek);
                    return SW_MEMORY_FAILURE();
                }
                file_put_data(tf, CONST_BYTE_ARRAY(NULL, 0));
            }
            else if (tag == 0x93) {
                file_t *ef_puk = file_search(EF_PUKAUT);
                if (!ef_puk) {
                    release_mkek(mkek);
                    return SW_MEMORY_FAILURE();
                }
                uint8_t pk_status[4], puks = MIN(tag_data[0], MAX_PUK);
                memset(pk_status, 0, sizeof(pk_status));
                pk_status[0] = puks;
                pk_status[1] = puks;
                pk_status[2] = tag_data[1];
                file_put_data(ef_puk, CONST_BYTE_ARRAY(pk_status, sizeof(pk_status)));
                for (uint8_t i = 0; i < puks; i++) {
                    file_t *tf = file_new(EF_PUK + i);
                    if (!tf) {
                        release_mkek(mkek);
                        return SW_MEMORY_FAILURE();
                    }
                    file_put_data(tf, CONST_BYTE_ARRAY(NULL, 0));
                }
            }
            else if (tag == 0x97) {
                kds = tag_data;
                /*
                   for (int i = 0; i < MIN(*kds,MAX_KEY_DOMAINS); i++) {
                    file_t *tf = file_new(EF_DKEK+i);
                    if (!tf)
                        return SW_MEMORY_FAILURE();
                    file_put_data(tf, CONST_BYTE_ARRAY(NULL, 0));
                   }
                 */
            }
        }
        file_t *tf_kd = file_search(EF_KEY_DOMAIN);
        if (!tf_kd) {
            release_mkek(mkek);
            return SW_EXEC_ERROR();
        }
        if (ret_mkek != PICOKEYS_OK) {
            ret_mkek = load_mkek(mkek); //Try again with new PIN/SO-PIN just in case some is the same
        }
        if (store_mkek(ret_mkek == PICOKEYS_OK ? mkek : NULL) != PICOKEYS_OK) {
            release_mkek(mkek);
            return SW_EXEC_ERROR();
        }
        release_mkek(mkek);
        if (dkeks) {
            if (*dkeks > 0) {
                uint16_t d = *dkeks;
                if (file_put_data(tf_kd, CONST_BYTE_ARRAY((const uint8_t *)&d, sizeof(d))) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
            }
            else {
                int r = save_dkek_key(0, random_bytes_get(32));
                if (r != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                uint16_t d = 0x0101;
                if (file_put_data(tf_kd, CONST_BYTE_ARRAY((const uint8_t *)&d, sizeof(d))) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
            }
        }
        else {
            uint16_t d = 0x0000;
            if (file_put_data(tf_kd, CONST_BYTE_ARRAY((const uint8_t *)&d, sizeof(d))) != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        if (kds) {
            uint8_t t[MAX_KEY_DOMAINS * 2], k = MIN(*kds, MAX_KEY_DOMAINS);
            memset(t, 0xff, 2 * k);
            if (file_put_data(tf_kd, CONST_BYTE_ARRAY(t, 2 * k)) != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        /* When initialized, it has all credentials */
        isUserAuthenticated = true;
        /* Create terminal private key */
        file_t *fdkey = hsm_key_search(0);
        if (!fdkey) {
            return SW_EXEC_ERROR();
        }
        int ret = 0;
        bool recreate_dev_key = ret_mkek != PICOKEYS_OK || !file_has_data(fdkey);
        if (!recreate_dev_key) {
            mbedtls_ecp_keypair existing_key;
            mbedtls_ecp_keypair_init(&existing_key);
            recreate_dev_key = load_private_key_ec(&existing_key, fdkey, FILE_OBJECT_OPERATION_USE, true) != PICOKEYS_OK;
            mbedtls_ecp_keypair_free(&existing_key);
        }
        if (recreate_dev_key) {
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_SECP256R1;
            uint8_t key_id = 0;
            if (otp_key_2) {
                ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256K1, &ecdsa, otp_key_2, 32);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
                ret = mbedtls_ecp_keypair_calc_public(&ecdsa, random_fill_iterator, NULL);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    return SW_EXEC_ERROR();
                }
            }
            else {
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_fill_iterator, NULL);
            }
            if (ret != 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            ret = store_keys(&ecdsa, PICOKEYS_KEY_EC, key_id);
            if (ret != PICOKEYS_OK) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            uint16_t ee_len = 0;
            mbedtls_pk_context subject_pk;
            byte_buffer_t certificates = BYTE_BUFFER(res_APDU, MAX_APDU_DATA);
            if (cvc_pk_wrap_ec(&subject_pk, &ecdsa) != LIBCVC_OK || asn1_cvc_aut(&subject_pk, &certificates, CONST_BYTE_ARRAY(NULL, 0)) == 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            ee_len = (uint16_t)certificates.len;

            file_t *fpk = file_search(EF_EE_DEV);
            ret = file_put_data(fpk, CONST_BYTE_ARRAY(res_APDU, ee_len));
            if (ret != PICOKEYS_OK) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }

            if (asn1_cvc_cert(&subject_pk, &certificates, CONST_BYTE_ARRAY(NULL, 0), true) == 0) {
                mbedtls_ecdsa_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdsa_free(&ecdsa);
            fpk = file_search(EF_TERMCA);
            ret = file_put_data(fpk, CONST_BYTE_ARRAY(res_APDU, certificates.len));
            if (ret != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }

            const uint8_t *keyid = (const uint8_t *) "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0",
                          *label = (const uint8_t *) "ESPICOHSMTR";
            byte_buffer_t prkd = BYTE_BUFFER(res_APDU, MAX_APDU_DATA);
            asn1_build_prkd_ecc(CONST_BYTE_ARRAY(label, (uint16_t)strlen((const char *)label)), CONST_BYTE_ARRAY(keyid, 20), 256, &prkd);
            fpk = file_search(EF_PRKD_DEV);
            ret = file_put_data(fpk, CONST_BYTE_ARRAY(res_APDU, prkd.len));
        }
        if (ret != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        /* Persist SYNCHRONOUSLY. flash_commit() only queues the write for low_flash_task() on
         * core 0; resetting straight after it would race the write and could leave a
         * half-written file system. APDU handlers run on core 1, which is exactly where
         * flash_commit_sync() is usable (it refuses on core 0, since core 0 owns the task it
         * would be waiting for). Fall back to the async commit if it reports failure so a
         * timeout can never leave the commit unqueued. */
        /* These printf()s go to the UART (PICO_STDIO_UART is on by default; PICO_STDIO_USB is
         * not), which is the ONLY channel that survives the failure being chased here: when the
         * reset below hangs, the device leaves the USB bus, so anything logging over USB goes
         * dark at exactly the moment it is needed. A serial adapter on GPIO0/GND at 115200
         * turns "it hung, unclear where" into a line number. */
        printf("INIT: wipe done, committing flash synchronously\n");
        bool committed = flash_commit_sync(FLASH_COMMIT_SYNC_TIMEOUT_MS);
        if (!committed) {
            printf("INIT: WARN sync commit reported failure, falling back to async\n");
            flash_commit();
        }
        printf("INIT: flash committed (sync=%d)\n", (int) committed);
        reset_puk_store();
        printf("INIT: puk store reset\n");
#if defined(PICO_PLATFORM)
        /* Re-personalising wipes the file system, and the card does NOT come back on its own
         * afterwards: the reader keeps reporting a card, but the card returns no ATR and
         * PKCS#11 sees no token, until the firmware rebuilds its state at boot. Before this
         * reset the only recovery was PHYSICALLY REPLUGGING the device, which is impossible in
         * a remote or datacenter deployment.
         *
         * Resetting after re-personalisation is also what a real smartcard does, so this makes
         * the Pico behave more like the SmartCard-HSM it stands in for, not less.
         *
         * Use watchdog_reboot() and NOT the EV_RESET path. EV_RESET routes to
         * usb_secure_reboot_now(), which zeroes heap and stack before resetting; that was tried
         * here first and MEASURED to hang the device outright on RP2350 — it left the bus and
         * never re-enumerated, recoverable only by physically replugging, i.e. strictly worse
         * than the bug being fixed. The flash and the wipe were both fine (the card came back
         * correctly re-personalised after a replug), so the fault is in that reboot path, not
         * in the commit above. rescue.c:490 already reboots with a plain watchdog_reset for
         * "reboot to normal mode", which is the proven path in this codebase.
         *
         * Not scrubbing RAM first is acceptable: a reset exposes memory to nobody without
         * physical access to the device, and the alternative here does not reboot at all.
         *
         * The delay lets core 0 finish transmitting the APDU response before the reset lands,
         * so the host sees this command SUCCEED rather than "Card removed".
         *
         * MEASURED RELIABILITY: 7/7 on a warm device, all recovering in ~3s. The single observed
         * failure was the FIRST initialize after a firmware flash, which hung and needed a
         * physical replug. One data point is a hypothesis, not a pattern — hsm-cycle-test.sh
         * exists to settle it. Until it is settled, provisioning should reboot the device (via
         * the rescue app: SELECT AID then 80 1F 00 00) after flashing and BEFORE the first
         * initialize, which avoids the cold path entirely. */
        printf("INIT: arming watchdog reset in %d ms\n", (int) INITIALIZE_REBOOT_DELAY_MS);
        watchdog_reboot(0, 0, INITIALIZE_REBOOT_DELAY_MS);
        /* If the UART shows this line and the device never comes back, the watchdog was armed
         * and the fault is in the reset/re-enumeration itself. If it never appears, the hang is
         * EARLIER — in the commit or the wipe — and the lines above localise it. That
         * distinction is the whole reason these logs exist. */
        printf("INIT: watchdog armed, returning SW_OK\n");
#endif
    }
    else {   //free memory bytes request
        int heap_left = heapLeft();
        res_APDU_size += put_uint32_be(heap_left, res_APDU);
        res_APDU[4] = 0;
        res_APDU[5] = HSM_VERSION_MAJOR;
        res_APDU[6] = HSM_VERSION_MINOR;
        res_APDU_size = 7;
    }
    return SW_OK();
}
