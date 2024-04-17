/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sc_hsm.h"
#include "files.h"
#include "common.h"
#include "version.h"
#include "crypto_utils.h"
#include "kek.h"
#include "eac.h"
#include "cvc.h"
#include "asn1.h"
#include "pico_keys.h"
#include "usb.h"
#include "random.h"

const uint8_t sc_hsm_aid[] = {
    11,
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01
};

const uint8_t atr_sc_hsm[] = {
    24,
    0x3B, 0xFE, 0x18, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x80, 0x31, 0x81, 0x54, 0x48, 0x53, 0x4D,
    0x31, 0x73, 0x80, 0x21, 0x40, 0x81, 0x07, 0xFA
};

uint8_t session_pin[32], session_sopin[32];
bool has_session_pin = false, has_session_sopin = false;
const uint8_t *dev_name = NULL;
uint16_t dev_name_len = 0;

static int sc_hsm_process_apdu();

static void init_sc_hsm();
static int sc_hsm_unload();

extern int cmd_select();
extern void select_file(file_t *pe);
extern int cmd_list_keys();

extern int cmd_read_binary();
extern int cmd_verify();
extern int cmd_reset_retry();
extern int cmd_challenge();
extern int cmd_external_authenticate();
extern int cmd_mse();
extern int cmd_initialize();
extern int cmd_key_domain();
extern int cmd_key_wrap();
extern int cmd_keypair_gen();
extern int cmd_update_ef();
extern int cmd_delete_file();
extern int cmd_change_pin();
extern int cmd_key_gen();
extern int cmd_signature();
extern int cmd_key_unwrap();
extern int cmd_decrypt_asym();
extern int cmd_cipher_sym();
extern int cmd_derive_asym();
extern int cmd_extras();
extern int cmd_general_authenticate();
extern int cmd_session_pin();
extern int cmd_puk_auth();
extern int cmd_pso();
extern int cmd_bip_slip();

extern const uint8_t *ccid_atr;

int sc_hsm_select_aid(app_t *a) {
    a->process_apdu = sc_hsm_process_apdu;
    a->unload = sc_hsm_unload;
    init_sc_hsm();
    return CCID_OK;
}

INITIALIZER( sc_hsm_ctor ) {
    ccid_atr = atr_sc_hsm;
    register_app(sc_hsm_select_aid, sc_hsm_aid);
}

void scan_files() {
    file_pin1 = search_file(EF_PIN1);
    if (file_pin1) {
        if (!file_pin1->data) {
            printf("PIN1 is empty. Initializing with default password\n");
            const uint8_t empty[33] = { 0 };
            file_put_data(file_pin1, empty, sizeof(empty));
        }
    }
    else {
        printf("FATAL ERROR: PIN1 not found in memory!\n");
    }
    file_sopin = search_file(EF_SOPIN);
    if (file_sopin) {
        if (!file_sopin->data) {
            printf("SOPIN is empty. Initializing with default password\n");
            const uint8_t empty[33] = { 0 };
            file_put_data(file_sopin, empty, sizeof(empty));
        }
    }
    else {
        printf("FATAL ERROR: SOPIN not found in memory!\n");
    }
    file_retries_pin1 = search_file(EF_PIN1_RETRIES);
    if (file_retries_pin1) {
        if (!file_retries_pin1->data) {
            printf("Retries PIN1 is empty. Initializing with default retriesr\n");
            const uint8_t retries = 3;
            file_put_data(file_retries_pin1, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries PIN1 not found in memory!\n");
    }
    file_retries_sopin = search_file(EF_SOPIN_RETRIES);
    if (file_retries_sopin) {
        if (!file_retries_sopin->data) {
            printf("Retries SOPIN is empty. Initializing with default retries\n");
            const uint8_t retries = 15;
            file_put_data(file_retries_sopin, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries SOPIN not found in memory!\n");
    }
    file_t *tf = NULL;

    tf = search_file(EF_PIN1_MAX_RETRIES);
    if (tf) {
        if (!tf->data) {
            printf("Max retries PIN1 is empty. Initializing with default max retriesr\n");
            const uint8_t retries = 3;
            file_put_data(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Max Retries PIN1 not found in memory!\n");
    }
    tf = search_file(EF_SOPIN_MAX_RETRIES);
    if (tf) {
        if (!tf->data) {
            printf("Max Retries SOPIN is empty. Initializing with default max retries\n");
            const uint8_t retries = 15;
            file_put_data(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries SOPIN not found in memory!\n");
    }
    low_flash_available();
}

void scan_all() {
    scan_flash();
    scan_files();
}

PUK puk_store[MAX_PUK_STORE_ENTRIES];
int puk_store_entries = 0;
PUK *current_puk = NULL;
uint8_t puk_status[MAX_PUK];

int add_cert_puk_store(const uint8_t *data, uint16_t data_len, bool copy) {
    if (data == NULL || data_len == 0) {
        return CCID_ERR_NULL_PARAM;
    }
    if (puk_store_entries == MAX_PUK_STORE_ENTRIES) {
        return CCID_ERR_MEMORY_FATAL;
    }

    puk_store[puk_store_entries].copied = copy;
    if (copy == true) {
        uint8_t *tmp = (uint8_t *) calloc(data_len, sizeof(uint8_t));
        memcpy(tmp, data, data_len);
        puk_store[puk_store_entries].cvcert = tmp;
    }
    else {
        puk_store[puk_store_entries].cvcert = data;
    }
    puk_store[puk_store_entries].cvcert_len = data_len;
    puk_store[puk_store_entries].chr = cvc_get_chr(puk_store[puk_store_entries].cvcert,
                                                   data_len,
                                                   &puk_store[puk_store_entries].chr_len);
    puk_store[puk_store_entries].car = cvc_get_car(puk_store[puk_store_entries].cvcert,
                                                   data_len,
                                                   &puk_store[puk_store_entries].car_len);
    puk_store[puk_store_entries].puk = cvc_get_pub(puk_store[puk_store_entries].cvcert,
                                                   data_len,
                                                   &puk_store[puk_store_entries].puk_len);

    puk_store_entries++;
    return CCID_OK;
}

int puk_store_select_chr(const uint8_t *chr) {
    for (int i = 0; i < puk_store_entries; i++) {
        if (memcmp(puk_store[i].chr, chr, puk_store[i].chr_len) == 0) {
            current_puk = &puk_store[i];
            return CCID_OK;
        }
    }
    return CCID_ERR_FILE_NOT_FOUND;
}

void reset_puk_store() {
    if (puk_store_entries > 0) { /* From previous session */
        for (int i = 0; i < puk_store_entries; i++) {
            if (puk_store[i].copied == true) {
                free((uint8_t *) puk_store[i].cvcert);
            }
        }
    }
    memset(puk_store, 0, sizeof(puk_store));
    puk_store_entries = 0;
    file_t *fterm = search_file(EF_TERMCA);
    if (fterm) {
        uint8_t *p = NULL, *fterm_data = file_get_data(fterm), *pq = fterm_data;
        uint16_t fterm_data_len = file_get_size(fterm);
        asn1_ctx_t ctxi;
        asn1_ctx_init(fterm_data, fterm_data_len, &ctxi);
        while (walk_tlv(&ctxi, &p, NULL, NULL, NULL)) {
            add_cert_puk_store(pq, (uint16_t)(p - pq), false);
            pq = p;
        }
    }
    for (int i = 0; i < 0xfe; i++) {
        file_t *ef = search_file((CA_CERTIFICATE_PREFIX << 8) | (uint8_t)i);
        if (ef && file_get_size(ef) > 0) {
            add_cert_puk_store(file_get_data(ef), file_get_size(ef), false);
        }
    }
    dev_name = cvc_get_chr(file_get_data(fterm), file_get_size(fterm), &dev_name_len);
    memset(puk_status, 0, sizeof(puk_status));
}

void init_sc_hsm() {
    scan_all();
    has_session_pin = has_session_sopin = false;
    isUserAuthenticated = false;
    cmd_select();
    reset_puk_store();
}

int sc_hsm_unload() {
    has_session_pin = has_session_sopin = false;
    isUserAuthenticated = false;
    sm_session_pin_len = 0;
    return CCID_OK;
}

uint16_t get_device_options() {
    file_t *ef = search_file(EF_DEVOPS);
    if (file_has_data(ef)) {
        return (file_read_uint8(ef) << 8) | file_read_uint8_offset(ef, 1);
    }
    return 0x0;
}

extern uint32_t board_button_read(void);

bool wait_button_pressed() {
    uint32_t val = EV_PRESS_BUTTON;
#ifndef ENABLE_EMULATION
    uint16_t opts = get_device_options();
    if (opts & HSM_OPT_BOOTSEL_BUTTON) {
        queue_try_add(&card_to_usb_q, &val);
        do{
            queue_remove_blocking(&usb_to_card_q, &val);
        } while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
    }
#endif
    return val == EV_BUTTON_TIMEOUT;
}

int parse_token_info(const file_t *f, int mode) {
    (void)f;
#ifdef __FOR_CI
    char *label = "SmartCard-HSM";
#else
    char *label = "Pico-HSM";
#endif
    char *manu = "Pol Henarejos";
    if (mode == 1) {
        uint8_t *p = res_APDU;
        *p++ = 0x30;
        *p++ = 0; //set later
        *p++ = 0x2; *p++ = 1; *p++ = HSM_VERSION_MAJOR;
#ifndef ENABLE_EMULATION
        *p++ = 0x4; *p++ = 8; memcpy(p, pico_serial.id, 8); p += 8;
#else
        *p++ = 0x4; *p++ = 8; memset(p, 0, 8); p += 8;
#endif
        *p++ = 0xC; *p++ = (uint8_t)strlen(manu); strcpy((char *) p, manu); p += strlen(manu);
        *p++ = 0x80; *p++ = (uint8_t)strlen(label); strcpy((char *) p, label); p += strlen(label);
        *p++ = 0x3; *p++ = 2; *p++ = 4; *p++ = 0x30;
        res_APDU_size = (uint16_t)(p - res_APDU);
        res_APDU[1] = (uint8_t)res_APDU_size - 2;
    }
    return (int)(2 + (2 + 1) + (2 + 8) + (2 + strlen(manu)) + (2 + strlen(label)) + (2 + 2));
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin) {
        return CCID_ERR_NULL_PARAM;
    }
    const file_t *max = search_file(pin->fid + 1);
    const file_t *act = search_file(pin->fid + 2);
    if (!max || !act) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    uint8_t retries = file_read_uint8(act);
    if (retries == 0 && force == false) { // blocked
        return CCID_ERR_BLOCKED;
    }
    retries = file_read_uint8(max);
    int r = file_put_data((file_t *) act, &retries, sizeof(retries));
    low_flash_available();
    return r;
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin) {
        return CCID_ERR_NULL_PARAM;
    }
    const file_t *act = search_file(pin->fid + 2);
    if (!act) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    uint8_t retries = file_read_uint8(act);
    if (retries > 0) {
        retries -= 1;
        int r = file_put_data((file_t *) act, &retries, sizeof(retries));
        if (r != CCID_OK) {
            return r;
        }
        low_flash_available();
        if (retries == 0) {
            return CCID_ERR_BLOCKED;
        }
        return retries;
    }
    return CCID_ERR_BLOCKED;
}

bool pka_enabled() {
    file_t *ef_puk = search_file(EF_PUKAUT);
    return file_has_data(ef_puk) && file_read_uint8(ef_puk) > 0;
}

uint16_t check_pin(const file_t *pin, const uint8_t *data, uint16_t len) {
    if (!file_has_data((file_t *) pin)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (pka_enabled() == false) {
        isUserAuthenticated = false;
    }
    has_session_pin = has_session_sopin = false;
    if (is_secured_apdu() && sm_session_pin_len > 0 && pin == file_pin1) {
        if (len == sm_session_pin_len && memcmp(data, sm_session_pin, len) != 0) {
            int retries;
            if ((retries = pin_wrong_retry(pin)) < CCID_OK) {
                return SW_PIN_BLOCKED();
            }
            return set_res_sw(0x63, 0xc0 | (uint8_t)retries);
        }
    }
    else {
        uint8_t dhash[32];
        double_hash_pin(data, len, dhash);
        if (sizeof(dhash) != file_get_size(pin) - 1) { // 1 byte for pin len
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        if (memcmp(file_get_data(pin) + 1, dhash, sizeof(dhash)) != 0) {
            int retries;
            if ((retries = pin_wrong_retry(pin)) < CCID_OK) {
                return SW_PIN_BLOCKED();
            }
            return set_res_sw(0x63, 0xc0 | (uint8_t)retries);
        }
    }
    int r = pin_reset_retries(pin, false);
    if (r == CCID_ERR_BLOCKED) {
        return SW_PIN_BLOCKED();
    }
    if (r != CCID_OK) {
        return SW_MEMORY_FAILURE();
    }
    if (pka_enabled() == false) {
        isUserAuthenticated = true;
    }
    if (pin == file_pin1) {
        hash_multi(data, len, session_pin);
        has_session_pin = true;
    }
    else if (pin == file_sopin) {
        hash_multi(data, len, session_sopin);
        has_session_sopin = true;
    }
    if (pending_save_dkek != 0xff) {
        save_dkek_key(pending_save_dkek, NULL);
        pending_save_dkek = 0xff;
    }
    return SW_OK();
}

const uint8_t *get_meta_tag(file_t *ef, uint16_t meta_tag, uint16_t *tag_len) {
    if (ef == NULL) {
        return NULL;
    }
    uint8_t *meta_data = NULL;
    uint16_t meta_size = meta_find(ef->fid, &meta_data);
    if (meta_size > 0 && meta_data != NULL) {
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL;
        asn1_ctx_t ctxi;
        asn1_ctx_init(meta_data, meta_size, &ctxi);
        while (walk_tlv(&ctxi, &p, &tag, tag_len, &tag_data)) {
            if (tag == meta_tag) {
                return tag_data;
            }
        }
    }
    return NULL;
}

uint32_t get_key_counter(file_t *fkey) {
    uint16_t tag_len = 0;
    const uint8_t *meta_tag = get_meta_tag(fkey, 0x90, &tag_len);
    if (meta_tag) {
        return (meta_tag[0] << 24) | (meta_tag[1] << 16) | (meta_tag[2] << 8) | meta_tag[3];
    }
    return 0xffffffff;
}

bool key_has_purpose(file_t *ef, uint8_t purpose) {
    uint16_t tag_len = 0;
    const uint8_t *meta_tag = get_meta_tag(ef, 0x91, &tag_len);
    if (meta_tag) {
        for (unsigned i = 0; i < tag_len; i++) {
            if (meta_tag[i] == purpose) {
                return true;
            }
        }
        return false;
    }
    return true;
}

uint32_t decrement_key_counter(file_t *fkey) {
    if (!fkey) {
        return 0xffffff;
    }
    uint8_t *meta_data = NULL;
    uint16_t meta_size = meta_find(fkey->fid, &meta_data);
    if (meta_size > 0 && meta_data != NULL) {
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL;
        uint16_t tag_len = 0;
        uint8_t *cmeta = (uint8_t *) calloc(1, meta_size);
        /* We cannot modify meta_data, as it comes from flash memory. It must be cpied to an aux buffer */
        memcpy(cmeta, meta_data, meta_size);
        asn1_ctx_t ctxi;
        asn1_ctx_init(meta_data, meta_size, &ctxi);
        while (walk_tlv(&ctxi, &p, &tag, &tag_len, &tag_data)) {
            if (tag == 0x90) { // ofset tag
                uint32_t val =
                    (tag_data[0] << 24) | (tag_data[1] << 16) | (tag_data[2] << 8) | tag_data[3];
                val--;
                tag_data[0] = (val >> 24) & 0xff;
                tag_data[1] = (val >> 16) & 0xff;
                tag_data[2] = (val >> 8) & 0xff;
                tag_data[3] = val & 0xff;

                int r = meta_add(fkey->fid, cmeta, (uint16_t)meta_size);
                free(cmeta);
                if (r != 0) {
                    return 0xffffffff;
                }
                low_flash_available();
                return val;
            }
        }
        free(cmeta);
    }
    return 0xffffffff;
}

// Stores the private and public keys in flash
int store_keys(void *key_ctx, int type, uint8_t key_id) {
    int r = 0;
    uint16_t key_size = 0;
    uint8_t kdata[4096 / 8]; // worst case
    if (type & PICO_KEYS_KEY_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        key_size = (uint16_t)mbedtls_mpi_size(&rsa->P) + (uint16_t)mbedtls_mpi_size(&rsa->Q);
        mbedtls_mpi_write_binary(&rsa->P, kdata, key_size / 2);
        mbedtls_mpi_write_binary(&rsa->Q, kdata + key_size / 2, key_size / 2);
    }
    else if (type & PICO_KEYS_KEY_EC) {
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *) key_ctx;
        key_size = (uint16_t)mbedtls_mpi_size(&ecdsa->d);
        kdata[0] = ecdsa->grp.id & 0xff;
        mbedtls_ecp_write_key(ecdsa, kdata + 1, key_size);
        key_size++;
    }
    else if (type & PICO_KEYS_KEY_AES) {
        if (type == PICO_KEYS_KEY_AES_128) {
            key_size = 16;
        }
        else if (type == PICO_KEYS_KEY_AES_192) {
            key_size = 24;
        }
        else if (type == PICO_KEYS_KEY_AES_256) {
            key_size = 32;
        }
        else if (type == PICO_KEYS_KEY_AES_512) {
            key_size = 64;
        }
        memcpy(kdata, key_ctx, key_size);
    }
    else {
        return CCID_WRONG_DATA;
    }
    file_t *fpk = file_new((KEY_PREFIX << 8) | key_id);
    if (!fpk) {
        return CCID_ERR_MEMORY_FATAL;
    }
    r = mkek_encrypt(kdata, key_size);
    if (r != CCID_OK) {
        return r;
    }
    r = file_put_data(fpk, kdata, (uint16_t)key_size);
    if (r != CCID_OK) {
        return r;
    }
    char key_id_str[4] = {0};
    sprintf(key_id_str, "%u", key_id);
    if (type & PICO_KEYS_KEY_EC) {
        key_size--;
    }
    uint16_t prkd_len = asn1_build_prkd_generic(NULL, 0, (uint8_t *)key_id_str, (uint16_t)strlen(key_id_str), key_size * 8, type, kdata, sizeof(kdata));
    if (prkd_len > 0) {
        fpk = file_new((PRKD_PREFIX << 8) | key_id);
        r = file_put_data(fpk, kdata, prkd_len);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    low_flash_available();
    return CCID_OK;
}

int find_and_store_meta_key(uint8_t key_id) {
    uint16_t meta_size = 0;
    uint8_t t90[4] = { 0xFF, 0xFF, 0xFF, 0xFE };
    asn1_ctx_t ctxi, ctxo[4] = { 0 };
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    for (uint16_t t = 0; t < 4; t++) {
        if (asn1_find_tag(&ctxi, 0x90 + t, &ctxo[t]) && asn1_len(&ctxo[t]) > 0) {
            meta_size += asn1_len_tag(0x90 + t, ctxo[t].len);
        }
    }
    if (asn1_len(&ctxo[0]) == 0) {
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_KEY_COUNTER_ALL) {
            ctxo[0].len = 4;
            ctxo[0].data = t90;
            meta_size += 6;
        }
    }
    if (meta_size) {
        uint8_t *meta = (uint8_t *) calloc(1, meta_size), *m = meta;
        for (uint8_t t = 0; t < 4; t++) {
            if (asn1_len(&ctxo[t]) > 0) {
                *m++ = 0x90 + t;
                m += format_tlv_len(ctxo[t].len, m);
                memcpy(m, ctxo[t].data, ctxo[t].len);
                m += ctxo[t].len;
            }
        }
        int r = meta_add((KEY_PREFIX << 8) | key_id, meta, (uint16_t)meta_size);
        free(meta);
        if (r != 0) {
            return CCID_EXEC_ERROR;
        }
    }
    return CCID_OK;
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey) {
    if (wait_button_pressed() == true) { // timeout
        return CCID_VERIFICATION_FAILED;
    }

    uint16_t key_size = file_get_size(fkey);
    uint8_t kdata[4096 / 8];
    memcpy(kdata, file_get_data(fkey), key_size);
    if (mkek_decrypt(kdata, key_size) != 0) {
        return CCID_EXEC_ERROR;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size / 2) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata + key_size / 2, key_size / 2) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    return CCID_OK;
}

int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey) {
    if (wait_button_pressed() == true) { // timeout
        return CCID_VERIFICATION_FAILED;
    }

    uint16_t key_size = file_get_size(fkey);
    uint8_t kdata[67]; // Worst case, 521 bit + 1byte
    memcpy(kdata, file_get_data(fkey), key_size);
    if (mkek_decrypt(kdata, key_size) != 0) {
        return CCID_EXEC_ERROR;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    int r = mbedtls_ecp_read_key(gid, ctx, kdata + 1, key_size - 1);
    if (r != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        mbedtls_ecdsa_free(ctx);
        return CCID_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    r = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, random_gen, NULL);
    if (r != 0) {
        mbedtls_ecdsa_free(ctx);
        return CCID_EXEC_ERROR;
    }
    return CCID_OK;
}

#define INS_VERIFY                  0x20
#define INS_MSE                     0x22
#define INS_CHANGE_PIN              0x24
#define INS_PSO                     0x2A
#define INS_RESET_RETRY             0x2C
#define INS_KEYPAIR_GEN             0x46
#define INS_KEY_GEN                 0x48
#define INS_BIP_SLIP                0x4A
#define INS_INITIALIZE              0x50
#define INS_KEY_DOMAIN              0x52
#define INS_PUK_AUTH                0x54
#define INS_LIST_KEYS               0x58
#define INS_SESSION_PIN             0x5A
#define INS_DECRYPT_ASYM            0x62
#define INS_EXTRAS                  0x64
#define INS_SIGNATURE               0x68
#define INS_WRAP                    0x72
#define INS_UNWRAP                  0x74
#define INS_DERIVE_ASYM             0x76
#define INS_CIPHER_SYM              0x78
#define INS_EXTERNAL_AUTHENTICATE   0x82
#define INS_CHALLENGE               0x84
#define INS_GENERAL_AUTHENTICATE    0x86
#define INS_SELECT_FILE             0xA4
#define INS_READ_BINARY             0xB0
#define INS_READ_BINARY_ODD         0xB1
#define INS_UPDATE_EF               0xD7
#define INS_DELETE_FILE             0xE4

static const cmd_t cmds[] = {
    { INS_SELECT_FILE, cmd_select },
    { INS_LIST_KEYS, cmd_list_keys },
    { INS_READ_BINARY, cmd_read_binary },
    { INS_READ_BINARY_ODD, cmd_read_binary },
    { INS_VERIFY, cmd_verify },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_CHALLENGE, cmd_challenge },
    { INS_INITIALIZE, cmd_initialize },
    { INS_KEY_DOMAIN, cmd_key_domain },
    { INS_KEYPAIR_GEN, cmd_keypair_gen },
    { INS_UPDATE_EF, cmd_update_ef },
    { INS_DELETE_FILE, cmd_delete_file },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_KEY_GEN, cmd_key_gen },
    { INS_SIGNATURE, cmd_signature },
    { INS_WRAP, cmd_key_wrap },
    { INS_UNWRAP, cmd_key_unwrap },
    { INS_DECRYPT_ASYM, cmd_decrypt_asym },
    { INS_CIPHER_SYM, cmd_cipher_sym },
    { INS_DERIVE_ASYM, cmd_derive_asym },
    { INS_EXTRAS, cmd_extras },
    { INS_MSE, cmd_mse },
    { INS_GENERAL_AUTHENTICATE, cmd_general_authenticate },
    { INS_SESSION_PIN, cmd_session_pin },
    { INS_PUK_AUTH, cmd_puk_auth },
    { INS_PSO, cmd_pso },
    { INS_EXTERNAL_AUTHENTICATE, cmd_external_authenticate },
    { INS_BIP_SLIP, cmd_bip_slip },
    { 0x00, 0x0 }
};

int sc_hsm_process_apdu() {
    int r = sm_unwrap();
    if (r != CCID_OK) {
        return SW_DATA_INVALID();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int res = cmd->cmd_handler();
            sm_wrap();
            return res;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
