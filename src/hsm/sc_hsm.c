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
#include "libopensc/card-sc-hsm.h"
#include "random.h"
#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/cmac.h"
#include "mbedtls/hkdf.h"
#include "version.h"
#include "cvcerts.h"
#include "crypto_utils.h"
#include "dkek.h"
#include "hardware/rtc.h"
#include "eac.h"

const uint8_t sc_hsm_aid[] = {
    11, 
    0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01
};

const uint8_t atr_sc_hsm[] = { 
    24,
    0x3B,0xFE,0x18,0x00,0x00,0x81,0x31,0xFE,0x45,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0xFA 
};

uint8_t session_pin[32], session_sopin[32];
bool has_session_pin = false, has_session_sopin = false;

static int sc_hsm_process_apdu();

static void init_sc_hsm();
static int sc_hsm_unload();
static int cmd_select();

app_t *sc_hsm_select_aid(app_t *a) {
    if (!memcmp(apdu.data, sc_hsm_aid+1, MIN(apdu.nc,sc_hsm_aid[0]))) {
        a->aid = sc_hsm_aid;
        a->process_apdu = sc_hsm_process_apdu;
        a->unload = sc_hsm_unload;
        init_sc_hsm();
        return a;
    }
    return NULL;
}

void __attribute__ ((constructor)) sc_hsm_ctor() { 
    ccid_atr = atr_sc_hsm;
    register_app(sc_hsm_select_aid);
}

void scan_files() {
    file_pin1 = search_by_fid(0x1081, NULL, SPECIFY_EF);
    if (file_pin1) {
        if (!file_pin1->data) {
            printf("PIN1 is empty. Initializing with default password\r\n");
            const uint8_t empty[33] = { 0 };
            flash_write_data_to_file(file_pin1, empty, sizeof(empty));
        }
    }
    else {
        printf("FATAL ERROR: PIN1 not found in memory!\r\n");
    }
    file_sopin = search_by_fid(0x1088, NULL, SPECIFY_EF);
    if (file_sopin) {
        if (!file_sopin->data) {
            printf("SOPIN is empty. Initializing with default password\r\n");
            const uint8_t empty[33] = { 0 };
            flash_write_data_to_file(file_sopin, empty, sizeof(empty));
        }
    }
    else {
        printf("FATAL ERROR: SOPIN not found in memory!\r\n");
    }
    file_retries_pin1 = search_by_fid(0x1083, NULL, SPECIFY_EF);
    if (file_retries_pin1) {
        if (!file_retries_pin1->data) {
            printf("Retries PIN1 is empty. Initializing with default retriesr\n");
            const uint8_t retries = 3;
            flash_write_data_to_file(file_retries_pin1, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries PIN1 not found in memory!\r\n");
    }
    file_retries_sopin = search_by_fid(0x108A, NULL, SPECIFY_EF);
    if (file_retries_sopin) {
        if (!file_retries_sopin->data) {
            printf("Retries SOPIN is empty. Initializing with default retries\r\n");
            const uint8_t retries = 15;
            flash_write_data_to_file(file_retries_sopin, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries SOPIN not found in memory!\r\n");
    }
    file_t *tf = NULL;
    
    tf = search_by_fid(0x1082, NULL, SPECIFY_EF);
    if (tf) {
        if (!tf->data) {
            printf("Max retries PIN1 is empty. Initializing with default max retriesr\n");
            const uint8_t retries = 3;
            flash_write_data_to_file(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Max Retries PIN1 not found in memory!\r\n");
    }
    tf = search_by_fid(0x1089, NULL, SPECIFY_EF);
    if (tf) {
        if (!tf->data) {
            printf("Max Retries SOPIN is empty. Initializing with default max retries\r\n");
            const uint8_t retries = 15;
            flash_write_data_to_file(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        printf("FATAL ERROR: Retries SOPIN not found in memory!\r\n");
    }
    low_flash_available();
}

void scan_all() {
    scan_flash();
    scan_files();
}

void init_sc_hsm() {
    scan_all();
    has_session_pin = has_session_sopin = false;
    isUserAuthenticated = false;
    cmd_select();
}

int sc_hsm_unload() {
    has_session_pin = has_session_sopin = false;
    isUserAuthenticated = false;
    sm_session_pin_len = 0;
    return CCID_OK;
}

void select_file(file_t *pe) {
    if (!pe)
    {
        currentDF = (file_t *)MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &file_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp || currentEF == file_sc_hsm) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

uint16_t get_device_options() {
    file_t *ef = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
    if (ef && ef->data)
        return (file_read_uint8(file_get_data(ef)) << 8) | file_read_uint8(file_get_data(ef)+1);
    return 0x0;
}

extern uint32_t board_button_read(void);

static bool wait_button() {
    uint16_t opts = get_device_options();
    uint32_t val = EV_PRESS_BUTTON;
    if (opts & HSM_OPT_BOOTSEL_BUTTON) {
        queue_try_add(&card_to_ccid_q, &val);
        do {
            queue_remove_blocking(&ccid_to_card_q, &val);
        }
        while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
    }
    return val == EV_BUTTON_TIMEOUT;
}

static int cmd_select() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    file_t *pe = NULL;
    uint16_t fid = 0x0;
    
    // Only "first or only occurence" supported 
    //if ((p2 & 0xF3) != 0x00) {
    //    return SW_INCORRECT_P1P2();
    //}
    
    if (apdu.nc >= 2)
        fid = get_uint16_t(apdu.data, 0);
        
    //if ((fid & 0xff00) == (KEY_PREFIX << 8))
    //    fid = (PRKD_PREFIX << 8) | (fid & 0xff);
    
    uint8_t pfx = fid >> 8;
    if (pfx == PRKD_PREFIX || 
        pfx == CD_PREFIX || 
        pfx == KEY_PREFIX || 
        pfx == EE_CERTIFICATE_PREFIX || 
        pfx == DCOD_PREFIX || 
        pfx == DATA_PREFIX || 
        pfx == PROT_DATA_PREFIX) {
        if (!(pe = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    if (!pe) {
        if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
            if (apdu.nc == 0) {
            	pe = (file_t *)MF;
            	//ac_fini();
            }
            else if (apdu.nc == 2) {
                if (!(pe = search_by_fid(fid, NULL, SPECIFY_ANY))) {
                    return SW_FILE_NOT_FOUND();
                }
            }
        }
        else if (p1 == 0x01) { //Select child DF - DF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_DF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x02) { //Select EF under the current DF - EF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_EF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x03) { //Select parent DF of the current DF - Absent
            if (apdu.nc != 0)
                return SW_FILE_NOT_FOUND();
        }
        else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
            if (!(pe = search_by_name(apdu.data, apdu.nc))) {
                return SW_FILE_NOT_FOUND();
            }
            if (card_terminated) {
                return set_res_sw (0x62, 0x85);
            }        
        }
        else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, MF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, currentDF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        process_fci(pe,0);
        if (pe == file_sc_hsm) {
            res_APDU[res_APDU_size++] = 0x85;
            res_APDU[res_APDU_size++] = 5;
            uint16_t opts = get_device_options();
            res_APDU[res_APDU_size++] = opts >> 8;
            res_APDU[res_APDU_size++] = opts & 0xff;
            res_APDU[res_APDU_size++] = 0xFF;
            res_APDU[res_APDU_size++] = HSM_VERSION_MAJOR;
            res_APDU[res_APDU_size++] = HSM_VERSION_MINOR;
            res_APDU[1] = res_APDU_size-2;
        }
    }
    else
        return SW_INCORRECT_P1P2();
    select_file(pe);
    return SW_OK ();
}

sc_context_t *create_context() {
    sc_context_t *ctx;
    sc_context_param_t ctx_opts;
    memset(&ctx_opts, 0, sizeof(sc_context_param_t));
    ctx_opts.ver      = 0;
	ctx_opts.app_name = "hsm2040";
    sc_context_create(&ctx, &ctx_opts);
    ctx->debug = 0;
    sc_ctx_log_to_file(ctx, "stdout");
    return ctx;
}

void cvc_init_common(sc_cvc_t *cvc) {
    memset(cvc, 0, sizeof(sc_cvc_t));

    size_t lencar = 0, lenchr = 0;
    uint8_t *car = NULL, *chr = NULL;
    
    if (asn1_find_tag(apdu.data, apdu.nc, 0x42, &lencar, &car) && lencar > 0 && car != NULL)
        strlcpy(cvc->car, (const char *)car, MIN(lencar,sizeof(cvc->car)));
    else
        strlcpy(cvc->car, "UTSRCACC100001", sizeof(cvc->car));
    if (asn1_find_tag(apdu.data, apdu.nc, 0x5f20, &lenchr, &chr) && lenchr > 0 && chr != NULL)
        strlcpy(cvc->chr, (const char *)chr, MIN(lenchr, sizeof(cvc->chr)));
    else
	    strlcpy(cvc->chr, "ESHSMCVCA00001", sizeof(cvc->chr));
	strlcpy(cvc->outer_car, "ESHSM00001", sizeof(cvc->outer_car));	
}

int cvc_prepare_signatures(sc_pkcs15_card_t *p15card, sc_cvc_t *cvc, size_t sig_len, uint8_t *hsh) {
    uint8_t *cvcbin;
    size_t cvclen;
    cvc->signatureLen = sig_len;
    cvc->signature = (uint8_t *)calloc(1, sig_len);
    cvc->outerSignatureLen = 4;
    cvc->outerSignature = (uint8_t *)calloc(1, sig_len);
    int r = sc_pkcs15emu_sc_hsm_encode_cvc(p15card, cvc, &cvcbin, &cvclen);
    if (r != SC_SUCCESS) {
        if (cvcbin)
            free(cvcbin);
        return r;
    }
    hash256(cvcbin, cvclen, hsh);
    free(cvcbin);
    return CCID_OK;
}

int parse_token_info(const file_t *f, int mode) {
    char *label = "SmartCard-HSM";
    char *manu = "Pol Henarejos";
    sc_pkcs15_tokeninfo_t *ti = (sc_pkcs15_tokeninfo_t *)calloc(1, sizeof(sc_pkcs15_tokeninfo_t));
    ti->version = HSM_VERSION_MAJOR;
    ti->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_EID_COMPLIANT;
    ti->label = (char *)calloc(strlen(label)+1, sizeof(char));
    strlcpy(ti->label, label, strlen(label)+1);
    ti->serial_number = (char *)calloc(2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1, sizeof(char));
    pico_get_unique_board_id_string(ti->serial_number, 2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1);
    ti->manufacturer_id = (char *)calloc(strlen(manu)+1, sizeof(char));
    strlcpy(ti->manufacturer_id, manu, strlen(manu)+1);

    uint8_t *b;
    size_t len;
    sc_pkcs15_encode_tokeninfo(NULL, ti, &b, &len);
    if (mode == 1) {
        memcpy(res_APDU, b, len);
        res_APDU_size = len;
    }
    free(b);
    sc_pkcs15_free_tokeninfo(ti);
    return len;
}

int parse_cvca(const file_t *f, int mode) {
    size_t termca_len = file_read_uint16(termca);
    size_t dica_len = file_read_uint16(dica);
    if (mode == 1) {
        memcpy(res_APDU, termca+2, termca_len);
        memcpy(res_APDU+termca_len, dica+2, dica_len);
        res_APDU_size = termca_len+dica_len;
    }
    return termca_len+dica_len;
}

static int cmd_list_keys()
{
    //first CC
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (PRKD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = PRKD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
            res_APDU[res_APDU_size++] = KEY_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    //second CD
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (CD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = CD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (DCOD_PREFIX << 8)) {
            res_APDU[res_APDU_size++] = DCOD_PREFIX;
            res_APDU[res_APDU_size++] = f->fid & 0xff;
        }
    }
    return SW_OK();
}

static int cmd_read_binary()
{
    uint16_t fid = 0x0;
    uint32_t offset = 0;
    uint8_t ins = INS(apdu), p1 = P1(apdu), p2 = P2(apdu);
    const file_t *ef = NULL;
    
    if ((ins & 0x1) == 0)
    {
        if ((p1 & 0x80) != 0) {
            if (!(ef = search_by_fid(p1&0x1f, NULL, SPECIFY_EF)))
                return SW_FILE_NOT_FOUND ();
            offset = p2;
        }
        else {
            offset = make_uint16_t(p1, p2) & 0x7fff;
            ef = currentEF;
        }
    }
    else {
        if (p1 == 0 && (p2 & 0xE0) == 0 && (p2 & 0x1f) != 0 && (p2 & 0x1f) != 0x1f) {
            if (!(ef = search_by_fid(p2&0x1f, NULL, SPECIFY_EF)))
                return SW_FILE_NOT_FOUND ();
        } 
        else {
            uint16_t file_id = make_uint16_t(p1, p2); // & 0x7fff;
            if (file_id == 0x0)
                ef = currentEF;
            else if (!(ef = search_by_fid(file_id, NULL, SPECIFY_EF)) && !(ef = search_dynamic_file(file_id)))
                return SW_FILE_NOT_FOUND ();
            
            if (apdu.data[0] != 0x54)
                return SW_WRONG_DATA();
                
            offset = 0;
            for (int d = 0; d < apdu.data[1]; d++)
                offset |= apdu.data[2+d]<<(apdu.data[1]-1-d)*8;
        }        
    }
    
    if ((fid >> 8) == KEY_PREFIX || !authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            uint16_t data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *)ef, 1); //already copies content to res_APDU
            if (offset > data_len)
                return SW_WRONG_P1P2();
            uint16_t maxle = data_len-offset;
            if (apdu.ne > maxle)
                apdu.ne = maxle;
            if (offset) {
                memmove(res_APDU, res_APDU+offset, res_APDU_size-offset);
                //res_APDU += offset;
                res_APDU_size -= offset;
            }
        }
        else {
            uint16_t data_len = file_get_size(ef);
            if (offset > data_len)
                return SW_WRONG_P1P2();
        
            uint16_t maxle = data_len-offset;
            if (apdu.ne > maxle)
                apdu.ne = maxle;
            memcpy(res_APDU, file_get_data(ef)+offset, data_len-offset);
            res_APDU_size = data_len-offset;
        }
    }

    return SW_OK();
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin)
        return CCID_ERR_NULL_PARAM; 
    const file_t *max = search_by_fid(pin->fid+1, NULL, SPECIFY_EF);
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!max || !act)
        return CCID_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(file_get_data(act));
    if (retries == 0 && force == false) //blocked
        return CCID_ERR_BLOCKED;
    retries = file_read_uint8(file_get_data(max));
    int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
    low_flash_available();
    return r;
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin)
        return CCID_ERR_NULL_PARAM; 
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!act)
        return CCID_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(file_get_data(act));
    if (retries > 0) {
        retries -= 1;
        int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
        if (r != CCID_OK)
            return r;
        low_flash_available();
        if (retries == 0)
            return CCID_ERR_BLOCKED;
        return retries;
    }
    return CCID_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!pin)
        return SW_REFERENCE_NOT_FOUND();
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    has_session_pin = has_session_sopin = false;
    if (is_secured_apdu() && sm_session_pin_len > 0 && pin == file_pin1) {
        if (len == sm_session_pin_len && memcmp(data, sm_session_pin, len) != 0) {
            int retries;
            if ((retries = pin_wrong_retry(pin)) < CCID_OK)
                return SW_PIN_BLOCKED();
            return set_res_sw(0x63, 0xc0 | retries);
        }
    }
    else {
        uint8_t dhash[32];
        double_hash_pin(data, len, dhash);
        if (sizeof(dhash) != file_get_size(pin)-1) //1 byte for pin len
            return SW_CONDITIONS_NOT_SATISFIED();
        if (memcmp(file_get_data(pin)+1, dhash, sizeof(dhash)) != 0) {
            int retries;
            if ((retries = pin_wrong_retry(pin)) < CCID_OK)
                return SW_PIN_BLOCKED();
            return set_res_sw(0x63, 0xc0 | retries);
        }
    }
    int r = pin_reset_retries(pin, false);
    if (r == CCID_ERR_BLOCKED)
        return SW_PIN_BLOCKED();
    if (r != CCID_OK)
        return SW_MEMORY_FAILURE();
    isUserAuthenticated = true;
    hash_multi(data, len, session_pin);
    if (pin == file_pin1)
        has_session_pin = true;
    else if (pin == file_sopin)
        has_session_sopin = true;
    return SW_OK();
}

static int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    
    if (p1 != 0x0 || (p2 & 0x60) != 0x0)
        return SW_WRONG_P1P2();

    if (p2 == 0x81) { //UserPin
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_TRANSPORT_PIN)
            return SW_DATA_INVALID();
        if (file_get_data(file_pin1) == 0) //not initialized
            return SW_REFERENCE_NOT_FOUND();
        if (apdu.nc > 0) {
            return check_pin(file_pin1, apdu.data, apdu.nc);
        }
        if (file_read_uint8(file_get_data(file_retries_pin1)) == 0)
            return SW_PIN_BLOCKED();
        if (has_session_pin)
            return SW_OK();
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_get_data(file_retries_pin1)));
    }
    else if (p2 == 0x88) { //SOPin
        if (file_read_uint8(file_get_data(file_sopin)) == 0) //not initialized
            return SW_REFERENCE_NOT_FOUND();
        if (apdu.nc > 0) {
            return check_pin(file_sopin, apdu.data, apdu.nc);
        }
        if (file_read_uint8(file_get_data(file_retries_sopin)) == 0)
            return SW_PIN_BLOCKED();
        if (has_session_sopin)
            return SW_OK();
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_get_data(file_retries_sopin)));
    }
    else if (p2 == 0x85) {
        return SW_OK();
    }
    return SW_REFERENCE_NOT_FOUND();
}

static int cmd_reset_retry() {
    if (P2(apdu) != 0x81)
        return SW_REFERENCE_NOT_FOUND();        
    if (!file_sopin || !file_pin1) {
        return SW_FILE_NOT_FOUND();
    }
    if (!file_sopin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint16_t opts = get_device_options();
    if (!(opts & HSM_OPT_RRC))
        return SW_COMMAND_NOT_ALLOWED();
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        if (P1(apdu) == 0x0) {
            if (apdu.nc <= 8)
                return SW_WRONG_LENGTH();
            uint16_t r = check_pin(file_sopin, apdu.data, 8);
            if (r != 0x9000)
                return r;
            newpin_len = apdu.nc-8;
        }
        else if (P1(apdu) == 0x2) {    
            if (!has_session_sopin)
                return SW_CONDITIONS_NOT_SATISFIED();
            if (apdu.nc > 16)
                return SW_WRONG_LENGTH();
            newpin_len = apdu.nc;
        }
        uint8_t dhash[33];
        dhash[0] = newpin_len;
        double_hash_pin(apdu.data+(apdu.nc-newpin_len), newpin_len, dhash+1);
        flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
        if (pin_reset_retries(file_pin1, true) != CCID_OK)
            return SW_MEMORY_FAILURE();
        low_flash_available();
        return SW_OK();
    }
    else if (P1(apdu) == 0x1 || P1(apdu) == 0x3) {        
        if (!(opts & HSM_OPT_RRC_RESET_ONLY))
            return SW_COMMAND_NOT_ALLOWED();
        if (P1(apdu) == 0x1) {
            if (apdu.nc != 8)
                return SW_WRONG_LENGTH();
            uint16_t r = check_pin(file_sopin, apdu.data, 8);
            if (r != 0x9000)
                return r;
        }
        else if (P1(apdu) == 0x3) {
            if (!has_session_sopin)
                return SW_CONDITIONS_NOT_SATISFIED();
            if (apdu.nc != 0)
                return SW_WRONG_LENGTH();
        }
        if (pin_reset_retries(file_pin1, true) != CCID_OK)
            return SW_MEMORY_FAILURE();
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}

static int cmd_challenge() {
    uint8_t *rb = (uint8_t *)random_bytes_get(apdu.ne);
    if (!rb)
        return SW_WRONG_LENGTH();
    memcpy(res_APDU, rb, apdu.ne);
    res_APDU_size = apdu.ne;
    return SW_OK();
}

extern char __StackLimit;
int heapLeft() {
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
    return left;
}

static int cmd_initialize() {
    if (apdu.nc > 0) {
        initialize_flash(true);
        scan_all();
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL, *kds = NULL, *dkeks = NULL;
        size_t tag_len = 0;    
        while (walk_tlv(apdu.data, apdu.nc, &p, &tag, &tag_len, &tag_data)) {
            if (tag == 0x80) { //options
                file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
                flash_write_data_to_file(tf, tag_data, tag_len);
            }
            else if (tag == 0x81) { //user pin
                if (file_pin1 && file_pin1->data) {
                    uint8_t dhash[33];
                    dhash[0] = tag_len;
                    double_hash_pin(tag_data, tag_len, dhash+1);
                    flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_pin);
                    has_session_pin = true;
                } 
            }
            else if (tag == 0x82) { //sopin pin
                if (file_sopin && file_sopin->data) {
                    uint8_t dhash[33];
                    dhash[0] = tag_len;
                    double_hash_pin(tag_data, tag_len, dhash+1);
                    flash_write_data_to_file(file_sopin, dhash, sizeof(dhash));
                    hash_multi(tag_data, tag_len, session_sopin);
                    has_session_sopin = true;
                } 
            }
            else if (tag == 0x91) { //retries user pin
                file_t *tf = search_by_fid(0x1082, NULL, SPECIFY_EF);
                if (tf && tf->data) {
                    flash_write_data_to_file(tf, tag_data, tag_len);
                }
                if (file_retries_pin1 && file_retries_pin1->data) {
                    flash_write_data_to_file(file_retries_pin1, tag_data, tag_len);
                }
            }
            else if (tag == 0x92) {
                dkeks = tag_data;
                file_t *tf = file_new(EF_DKEK);
                if (!tf)
                    return SW_MEMORY_FAILURE();
                flash_write_data_to_file(tf, NULL, 0);
            }
            else if (tag == 0x97) {
                kds = tag_data;
                for (int i = 0; i < MIN(*kds,MAX_KEY_DOMAINS); i++) {
                    file_t *tf = file_new(EF_DKEK+i);
                    if (!tf)
                        return SW_MEMORY_FAILURE();
                    flash_write_data_to_file(tf, NULL, 0);
                }
            }
        }
        //At least, the first DKEK shall exist
        file_t *tf_kd = search_by_fid(EF_KEY_DOMAIN, NULL, SPECIFY_EF);
        if (!tf_kd)
            return SW_EXEC_ERROR();
        file_t *tf = search_dynamic_file(EF_DKEK);
        if (!tf) {
            tf = file_new(EF_DKEK);
            if (!tf)
                return SW_MEMORY_FAILURE();
        }
        uint8_t t[DKEK_SIZE];
        memset(t, 0, sizeof(t));
        flash_write_data_to_file(tf, t, sizeof(t));
        if (dkeks) {
            if (*dkeks > 0) {
                uint16_t d = *dkeks;
                if (flash_write_data_to_file(tf_kd, (const uint8_t *)&d, sizeof(d)) != CCID_OK)
                    return SW_EXEC_ERROR();
            }
            else {
                int r = save_dkek_key(0, random_bytes_get(32));
                if (r != CCID_OK)
                    return SW_EXEC_ERROR();
                uint16_t d = 0x0101;
                if (flash_write_data_to_file(tf_kd, (const uint8_t *)&d, sizeof(d)) != CCID_OK)
                    return SW_EXEC_ERROR();
            }
        }
        if (kds) {
            uint8_t t[MAX_KEY_DOMAINS*2], k = MIN(*kds,MAX_KEY_DOMAINS);
            memset(t, 0xff, 2*k);
            if (flash_write_data_to_file(tf_kd, t, 2*k) != CCID_OK)
                return SW_EXEC_ERROR();
        }
        low_flash_available();
    }
    else { //free memory bytes request
        int heap_left = heapLeft();
        res_APDU[0] = ((heap_left >> 24) & 0xff);
        res_APDU[1] = ((heap_left >> 16) & 0xff);
        res_APDU[2] = ((heap_left >> 8) & 0xff);
        res_APDU[3] = ((heap_left >> 0) & 0xff);
        res_APDU[4] = 0;
        res_APDU[5] = HSM_VERSION_MAJOR;
        res_APDU[6] = HSM_VERSION_MINOR;
        res_APDU_size = 7;
    }
    return SW_OK();
}

static int cmd_key_domain() {
    //if (dkeks == 0)
    //    return SW_COMMAND_NOT_ALLOWED();
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (has_session_pin == false && apdu.nc > 0)
        return SW_CONDITIONS_NOT_SATISFIED();
    if (p2 >= MAX_KEY_DOMAINS)
        return SW_WRONG_P1P2();
    file_t *tf_kd = search_by_fid(EF_KEY_DOMAIN, NULL, SPECIFY_EF);
    if (!tf_kd)
        return SW_EXEC_ERROR();
    uint16_t tf_kd_size = file_get_size(tf_kd);
    if (tf_kd_size == 0)
        return SW_WRONG_P1P2();
    uint8_t *kdata = file_get_data(tf_kd), dkeks = kdata ? *(kdata+2*p2) : 0, current_dkeks = kdata ? *(kdata+2*p2+1) : 0;
    if (p1 == 0x0) { //dkek import
        if (apdu.nc > 0) {
            file_t *tf = file_new(EF_DKEK+p2);
            if (!tf)
                return SW_MEMORY_FAILURE();
            if (apdu.nc < 32)
                return SW_WRONG_LENGTH();
            import_dkek_share(p2, apdu.data);
            if (++current_dkeks >= dkeks) {
                if (save_dkek_key(p2, NULL) != CCID_OK)
                    return SW_FILE_NOT_FOUND();
            }
            uint8_t t[MAX_KEY_DOMAINS*2];
            memcpy(t, kdata, tf_kd_size);
            t[2*p2+1] = current_dkeks;
            if (flash_write_data_to_file(tf_kd, t, tf_kd_size) != CCID_OK)
                return SW_EXEC_ERROR();
            low_flash_available();
        }
        else {
            file_t *tf = search_dynamic_file(EF_DKEK+p2);
            if (!tf)
                return SW_INCORRECT_P1P2();
            if (current_dkeks == 0xff)
                return SW_REFERENCE_NOT_FOUND();
        }
    }
    else if (p1 == 0x1) { //key domain setup
        if (apdu.nc != 1)
            return SW_WRONG_LENGTH();
        uint8_t t[MAX_KEY_DOMAINS*2];
        memcpy(t, kdata, tf_kd_size);
        t[2*p2] = dkeks = apdu.data[0];
        t[2*p2+1] = current_dkeks = 0;
        if (flash_write_data_to_file(tf_kd, t, tf_kd_size) != CCID_OK)
            return SW_EXEC_ERROR();
        low_flash_available();
    }
    memset(res_APDU,0,10);
    res_APDU[0] = dkeks;
    res_APDU[1] = dkeks > current_dkeks ? dkeks-current_dkeks : 0;
    dkek_kcv(p2, res_APDU+2);
    res_APDU_size = 2+8;
    return SW_OK();
}

uint8_t get_key_domain(file_t *fkey) {
    if (!fkey)
        return 0xff;
    uint8_t *meta_data = NULL;
    uint8_t meta_size = meta_find(fkey->fid, &meta_data);
    DEBUG_PAYLOAD(meta_data,meta_size);
    if (meta_size > 0 && meta_data != NULL) {
        uint16_t tag = 0x0;
        uint8_t *tag_data = NULL, *p = NULL;
        size_t tag_len = 0;
        while (walk_tlv(meta_data, meta_size, &p, &tag, &tag_len, &tag_data)) {
            if (tag == 0x92) { //ofset tag
                return *tag_data;
            }
        }
    }
    return 0;
}

//Stores the private and public keys in flash
int store_keys(void *key_ctx, int type, uint8_t key_id, uint8_t kdom) {
    int r, key_size = 0;
    uint8_t kdata[4096/8]; //worst case
    if (type == SC_PKCS15_TYPE_PRKEY_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)key_ctx;
        key_size = mbedtls_mpi_size(&rsa->P)+mbedtls_mpi_size(&rsa->Q);
        mbedtls_mpi_write_binary(&rsa->P, kdata, key_size/2);
        mbedtls_mpi_write_binary(&rsa->Q, kdata+key_size/2, key_size/2);
    }
    else if (type == SC_PKCS15_TYPE_PRKEY_EC) {
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *)key_ctx;
        key_size = mbedtls_mpi_size(&ecdsa->d);
        kdata[0] = ecdsa->grp.id & 0xff;
        mbedtls_mpi_write_binary(&ecdsa->d, kdata+1, key_size);
        key_size++;
    }
    else if (type & HSM_KEY_AES) {
        if (type == HSM_KEY_AES_128)
            key_size = 16;
        else if (type == HSM_KEY_AES_192)
            key_size = 24;
        else if (type == HSM_KEY_AES_256)
            key_size = 32;
        memcpy(kdata, key_ctx, key_size);
    }
    else
        return CCID_WRONG_DATA;
    file_t *fpk = file_new((KEY_PREFIX << 8) | key_id);
    if (!fpk)
        return SW_MEMORY_FAILURE();
    r = dkek_encrypt(kdom, kdata, key_size);
    if (r != CCID_OK) {
        return r;
    }
    r = flash_write_data_to_file(fpk, kdata, key_size);
    if (r != CCID_OK)
        return r;
    //add_file_to_chain(fpk, &ef_kf);
    /*
    if (type == SC_PKCS15_TYPE_PRKEY_RSA || type == SC_PKCS15_TYPE_PRKEY_EC) {
        struct sc_pkcs15_object *p15o = (struct sc_pkcs15_object *)calloc(1,sizeof (struct sc_pkcs15_object));
        
        sc_pkcs15_prkey_info_t *prkd = (sc_pkcs15_prkey_info_t *)calloc(1, sizeof (sc_pkcs15_prkey_info_t));
        memset(prkd, 0, sizeof(sc_pkcs15_prkey_info_t));
        prkd->id.len = 1;
        prkd->id.value[0] = key_id;
        prkd->usage = SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_UNWRAP;
        prkd->access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_LOCAL;
        prkd->native = 1;
        prkd->key_reference = key_id;
        prkd->path.value[0] = PRKD_PREFIX;
        prkd->path.value[1] = key_id;
        prkd->path.len = 2;
        if (type == SC_PKCS15_TYPE_PRKEY_RSA)
            prkd->modulus_length = key_size;
        else
            prkd->field_length = key_size-1; //contains 1 byte for the grp id
        
        p15o->data = prkd;
        p15o->type = SC_PKCS15_TYPE_PRKEY | (type & 0xff);
        
        r = sc_pkcs15_encode_prkdf_entry(ctx, p15o, &asn1bin, &asn1len);
        free(prkd);
        //sc_asn1_print_tags(asn1bin, asn1len);
    }
    
    fpk = file_new((PRKD_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, asn1bin, asn1len);
    if (asn1bin)
        free(asn1bin);
    if (r != CCID_OK)
        return r;
        */
    //add_file_to_chain(fpk, &ef_prkdf);
    /*
    sc_pkcs15_pubkey_info_t *pukd = (sc_pkcs15_pubkey_info_t *)calloc(1, sizeof(sc_pkcs15_pubkey_info_t));
    memset(pukd, 0, sizeof(sc_pkcs15_pubkey_info_t));
    pukd->id.len = 1;
    pukd->id.value[0] = key_id;
    pukd->usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_VERIFY;
    pukd->access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
    pukd->native = 1;
    pukd->key_reference = key_id;
    pukd->path.value[0] = CD_PREFIX;
    pukd->path.value[1] = key_id;
    pukd->path.len = 2;
    
    if (type == SC_PKCS15_TYPE_PRKEY_RSA)
        pukd->modulus_length = key_size;
    else
        pukd->field_length = key_size-1;
    
    p15o->data = pukd;
    p15o->type = SC_PKCS15_TYPE_PUBKEY | (type & 0xff);
    
    r = sc_pkcs15_encode_pukdf_entry(ctx, p15o, &asn1bin, &asn1len);
    free(pukd);
    free(p15o);
    //sc_asn1_print_tags(asn1bin, asn1len);
    fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, asn1bin, asn1len);
    free(asn1bin);
    if (r != CCID_OK)
        return r;
    //add_file_to_chain(fpk, &ef_cdf);
    */
    low_flash_available();
    return CCID_OK;
}

static int cmd_keypair_gen() {
    uint8_t key_id = P1(apdu), kdom = 0;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    sc_context_t *ctx = create_context();
    struct sc_pkcs15_card p15card;
    p15card.card = (sc_card_t *)calloc(1, sizeof(sc_card_t));
    p15card.card->ctx = ctx;
    int ret = 0;
    sc_cvc_t cvc;
    cvc_init_common(&cvc);
    
    size_t tout = 0;
    //sc_asn1_print_tags(apdu.data, apdu.nc);
    uint8_t *p = NULL;
    if (asn1_find_tag(apdu.data, apdu.nc, 0x7f49, &tout, &p) && tout > 0 && p != NULL) {
        size_t oid_len = 0;
        uint8_t *oid = NULL;
        if (asn1_find_tag(p, tout, 0x6, &oid_len, &oid) && oid_len > 0 && oid != NULL) {
            size_t kdom_size = 0;
            uint8_t *kdomd = NULL;
            if (asn1_find_tag(apdu.data, apdu.nc, 0x92, &kdom_size, &kdomd) && kdom_size > 0 && kdomd != NULL)
                kdom = *kdomd;
            if (memcmp(oid, "\x4\x0\x7F\x0\x7\x2\x2\x2\x1\x2",MIN(oid_len,10)) == 0) { //RSA
                size_t ex_len, ks_len;
                uint8_t *ex = NULL;
                uint8_t *ks = NULL;
                asn1_find_tag(p, tout, 0x82, &ex_len, &ex);
                asn1_find_tag(p, tout, 0x2, &ks_len, &ks);
                int exponent = 65537, key_size = 2048;
                if (ex) {
                    exponent = 0;
                    while (ex_len-- > 0) {
                        exponent = (exponent << 8) | *ex++;
                    }
                }
                if (ks) {
                    key_size = 0;
                    while (ks_len-- > 0) {
                        key_size = (key_size << 8) | *ks++;
                    }
                }
                printf("KEYPAIR RSA %d\r\n",key_size);
                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa);
                uint8_t index = 0;
                ret = mbedtls_rsa_gen_key(&rsa, random_gen, &index, key_size, exponent);
                if (ret != 0) {
                    sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                
            	struct sc_object_id rsa15withSHA256 = { { 0,4,0,127,0,7,2,2,2,1,2,-1 } };
            	cvc.coefficientAorExponentlen = ex_len;
            	cvc.coefficientAorExponent = calloc(1, cvc.coefficientAorExponentlen);
	            memcpy(cvc.coefficientAorExponent, &exponent, cvc.coefficientAorExponentlen);

	            cvc.pukoid = rsa15withSHA256;
	            //cvc.modulusSize = key_size; //NOT EXPECTED. DO NOT COMMENT (it seems not standard)
	            cvc.primeOrModuluslen = key_size/8;
	            cvc.primeOrModulus = (uint8_t *)calloc(1, cvc.primeOrModuluslen);
	            ret = mbedtls_mpi_write_binary(&rsa.N, cvc.primeOrModulus, cvc.primeOrModuluslen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
                uint8_t hsh[32];
	            ret = cvc_prepare_signatures(&p15card, &cvc, key_size/8, hsh);
	            if (ret != CCID_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, random_gen, &index, MBEDTLS_MD_SHA256, 32, hsh, cvc.signature);
                if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            ret = store_keys(&rsa, SC_PKCS15_TYPE_PRKEY_RSA, key_id, kdom);
	            if (ret != CCID_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                mbedtls_rsa_free(&rsa);            
            }
            else if (memcmp(oid, "\x4\x0\x7F\x0\x7\x2\x2\x2\x2\x3",MIN(oid_len,10)) == 0) { //ECC
                size_t prime_len;
                uint8_t *prime = NULL;
                if (asn1_find_tag(p, tout, 0x81, &prime_len, &prime) != true)
                    return SW_WRONG_DATA();
                mbedtls_ecp_group_id ec_id = ec_get_curve_from_prime(prime, prime_len);
                printf("KEYPAIR ECC %d\r\n",ec_id);
                if (ec_id == MBEDTLS_ECP_DP_NONE) {
                    sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    free(ctx);
                    free(p15card.card);
                    return SW_FUNC_NOT_SUPPORTED();
                }
                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);
                uint8_t index = 0;
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, &index);
                if (ret != 0) {
                    sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                
                struct sc_object_id ecdsaWithSHA256 = { { 0,4,0,127,0,7,2,2,2,2,3,-1 } };
	            cvc.pukoid = ecdsaWithSHA256;
	            
            	cvc.coefficientAorExponentlen = prime_len;//mbedtls_mpi_size(&ecdsa.grp.A);
            	cvc.coefficientAorExponent = calloc(1, cvc.coefficientAorExponentlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.A, cvc.coefficientAorExponent, cvc.coefficientAorExponentlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }

	            cvc.primeOrModuluslen = mbedtls_mpi_size(&ecdsa.grp.P);
	            cvc.primeOrModulus = (uint8_t *)calloc(1, cvc.primeOrModuluslen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.P, cvc.primeOrModulus, cvc.primeOrModuluslen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
	            cvc.coefficientBlen = mbedtls_mpi_size(&ecdsa.grp.B);
	            cvc.coefficientB = (uint8_t *)calloc(1, cvc.coefficientBlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.B, cvc.coefficientB, cvc.coefficientBlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
	            cvc.basePointGlen = mbedtls_mpi_size(&ecdsa.grp.G.X)+mbedtls_mpi_size(&ecdsa.grp.G.Y)+mbedtls_mpi_size(&ecdsa.grp.G.Z);
	            cvc.basePointG = (uint8_t *)calloc(1, cvc.basePointGlen);
	            ret = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &cvc.basePointGlen, cvc.basePointG, cvc.basePointGlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
	            cvc.orderlen = mbedtls_mpi_size(&ecdsa.grp.N);
	            cvc.order = (uint8_t *)calloc(1, cvc.orderlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.N, cvc.order, cvc.orderlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
	            cvc.publicPointlen = mbedtls_mpi_size(&ecdsa.Q.X)+mbedtls_mpi_size(&ecdsa.Q.Y)+mbedtls_mpi_size(&ecdsa.Q.Z);
	            cvc.publicPoint = (uint8_t *)calloc(1, cvc.publicPointlen);
	            ret = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &cvc.publicPointlen, cvc.publicPoint, cvc.publicPointlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
	            
	            cvc.cofactorlen = 1;
	            cvc.cofactor = (uint8_t *)calloc(1, cvc.cofactorlen);
	            cvc.cofactor[0] = 1;
	            	            
	            cvc.modulusSize = ec_id; //we store the ec_id in the modulusSize, used for RSA, as it is an integer
	            
                uint8_t hsh[32];
	            ret = cvc_prepare_signatures(&p15card, &cvc, ecdsa.grp.pbits*2/8+9, hsh);
	            if (ret != CCID_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hsh, sizeof(hsh), cvc.signature, cvc.signatureLen, &cvc.signatureLen, random_gen, &index);
                if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                
	            ret = store_keys(&ecdsa, SC_PKCS15_TYPE_PRKEY_EC, key_id, kdom);
	            if (ret != CCID_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    free(ctx);
                    free(p15card.card);
                    return SW_EXEC_ERROR();
                }
                mbedtls_ecdsa_free(&ecdsa);
            }
            
        }
    }
    else
        return SW_WRONG_DATA();
    uint8_t *cvcbin;
    size_t cvclen;
    ret = sc_pkcs15emu_sc_hsm_encode_cvc(&p15card, &cvc, &cvcbin, &cvclen);
    sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
    free(ctx);
    free(p15card.card);
    if (ret != SC_SUCCESS) {
        if (cvcbin)
            free(cvcbin);
        return SW_EXEC_ERROR();
    }
    size_t lt[4] = { 0 }, meta_size = 0;
    uint8_t *pt[4] = { NULL };
    for (int t = 0; t < 4; t++) {
        if (asn1_find_tag(apdu.data, apdu.nc, 0x90+t, &lt[t], &pt[t]) && pt[t] != NULL && lt[t] > 0)
            meta_size += 1+format_tlv_len(lt[t], NULL)+lt[t];
    }
    if (meta_size) {
        uint8_t *meta = (uint8_t *)calloc(1, meta_size), *m = meta;
        for (int t = 0; t < 4; t++) {
            if (lt[t] > 0 && pt[t] != NULL) {
                *m++ = 0x90+t;
                m += format_tlv_len(lt[t], m);
                memcpy(m, pt[t], lt[t]);
            }
        }
        DEBUG_PAYLOAD(meta,meta_size);
        ret = meta_add((KEY_PREFIX << 8) | key_id, meta, meta_size);
        free(meta);
        if (ret != 0)
            return SW_EXEC_ERROR();
    }
    
    res_APDU[res_APDU_size++] = 0x67;
    int outer_len = 2+strlen(cvc.outer_car)+3+4;
    int bytes_length = format_tlv_len(cvclen+outer_len, res_APDU+res_APDU_size);
    res_APDU_size += bytes_length;
    memcpy(res_APDU+res_APDU_size, cvcbin, cvclen);
    res_APDU_size += cvclen;
    res_APDU[res_APDU_size++] = 0x42;
    res_APDU[res_APDU_size++] = strlen(cvc.outer_car);
    memcpy(res_APDU+res_APDU_size, cvc.outer_car, strlen(cvc.outer_car));
    res_APDU_size += strlen(cvc.outer_car);
    memcpy(res_APDU+res_APDU_size, "\x5F\x37\x04",3);
    res_APDU_size += 3;
    memset(res_APDU+res_APDU_size, 0, 4);
    res_APDU_size += 4;
    free(cvcbin);
    //res_APDU_size = cvclen+bytes_length+1+outer_len;
    apdu.ne = res_APDU_size;

    //sc_asn1_print_tags(res_APDU, res_APDU_size);
    file_t *fpk = file_new((EE_CERTIFICATE_PREFIX << 8) | key_id);
    ret = flash_write_data_to_file(fpk, res_APDU, res_APDU_size);
    if (ret != 0)
        return SW_EXEC_ERROR();
    
    low_flash_available();
    return SW_OK();
}

static int cmd_update_ef() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    uint16_t fid = (p1 << 8) | p2;
    uint8_t *data = NULL;
    uint16_t offset = 0;
    uint16_t data_len = 0;
    file_t *ef = NULL;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (fid == 0x0)
        ef = currentEF;
    else if (p1 != EE_CERTIFICATE_PREFIX && p1 != PRKD_PREFIX && p1 != CA_CERTIFICATE_PREFIX && p1 != CD_PREFIX && p1 != DATA_PREFIX && p1 != DCOD_PREFIX && p1 != PROT_DATA_PREFIX)
        return SW_INCORRECT_P1P2();
        
    if (ef && !authenticate_action(ef, ACL_OP_UPDATE_ERASE))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
        
    uint16_t tag = 0x0;
    uint8_t *tag_data = NULL, *p = NULL;
    size_t tag_len = 0;    
    while (walk_tlv(apdu.data, apdu.nc, &p, &tag, &tag_len, &tag_data)) {
        if (tag == 0x54) { //ofset tag
            for (int i = 1; i <= tag_len; i++)
                offset |= (*tag_data++ << (8*(tag_len-i)));
        }
        else if (tag == 0x53) { //data 
            data_len = tag_len;
            data = tag_data;
        }
    }
    if (data_len == 0 && offset == 0) { //new file
        ef = file_new(fid);
        //if ((fid & 0xff00) == (EE_CERTIFICATE_PREFIX << 8))
        //    add_file_to_chain(ef, &ef_pukdf);
        select_file(ef);
    }
    else {
        if (fid == 0x0 && !ef)
            return SW_FILE_NOT_FOUND();
        else if (fid != 0x0 && !(ef = search_by_fid(fid, NULL, SPECIFY_EF)) && !(ef = search_dynamic_file(fid))) { //if does not exist, create it
            //return SW_FILE_NOT_FOUND();
            ef = file_new(fid);
        }
        if (offset == 0) {
            int r = flash_write_data_to_file(ef, data, data_len);
            if (r != CCID_OK)
                return SW_MEMORY_FAILURE();
        }
        else {
            if (!ef->data)
                return SW_DATA_INVALID();
            uint8_t *data_merge = (uint8_t *)calloc(1, offset+data_len);
            memcpy(data_merge, file_get_data(ef), offset);
            memcpy(data_merge+offset, data, data_len);
            int r = flash_write_data_to_file(ef, data_merge, offset+data_len);
            free(data_merge);
            if (r != CCID_OK)
                return SW_MEMORY_FAILURE();
        }
        low_flash_available();
    }
    return SW_OK(); 
}

static int cmd_delete_file() {
    file_t *ef = NULL;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
        
    if (apdu.nc == 0) {
        ef = currentEF;
        if (!(ef = search_dynamic_file(ef->fid)))
            return SW_FILE_NOT_FOUND();
    }
    else {
        uint16_t fid = (apdu.data[0] << 8) | apdu.data[1];
        if (!(ef = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_DELETE_SELF))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (flash_clear_file(ef) != CCID_OK)
        return SW_EXEC_ERROR();
    if (delete_dynamic_file(ef) != CCID_OK)
        return SW_EXEC_ERROR();
    low_flash_available();
    return SW_OK();
}

static int cmd_change_pin() {
    if (P1(apdu) == 0x0) {
        if (P2(apdu) == 0x81) {
            if (!file_sopin || !file_pin1) {
                return SW_FILE_NOT_FOUND();
            }
            if (!file_pin1->data) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_read_uint8(file_get_data(file_pin1));
            uint16_t r = check_pin(file_pin1, apdu.data, pin_len);
            if (r != 0x9000)
                return r;
            uint8_t old_session_pin[32];
            memcpy(old_session_pin, session_pin, sizeof(old_session_pin));
            for (uint8_t kdom = 0; kdom < MAX_KEY_DOMAINS; kdom++) {
                uint8_t dkek[DKEK_SIZE];
                memcpy(session_pin, old_session_pin, sizeof(session_pin));
                if (load_dkek(kdom, dkek) != CCID_OK) //loads the DKEK with old pin
                    return SW_EXEC_ERROR();
                //encrypt DKEK with new pin
                hash_multi(apdu.data+pin_len, apdu.nc-pin_len, session_pin);
                has_session_pin = true;
                r = store_dkek_key(kdom, dkek);
                release_dkek(dkek);
                if (r != CCID_OK)
                    return SW_EXEC_ERROR();
            }
            memset(old_session_pin, 0, sizeof(old_session_pin));
            uint8_t dhash[33];
            dhash[0] = apdu.nc-pin_len;
            double_hash_pin(apdu.data+pin_len, apdu.nc-pin_len, dhash+1);
            flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
            low_flash_available();
            return SW_OK();
        }
    }
    return SW_WRONG_P1P2();
}

static int cmd_key_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    uint8_t key_size = 32;
    int r;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (p2 == 0xB2)
        key_size = 32;
    else if (p2 == 0xB1)
        key_size = 24;
    else if (p2 == 0xB0)
        key_size = 16;
    //at this moment, we do not use the template, as only CBC is supported by the driver (encrypt, decrypt and CMAC)
    uint8_t aes_key[32]; //maximum AES key size
    memcpy(aes_key, random_bytes_get(key_size), key_size);
    int aes_type = 0x0;
    if (key_size == 16)
        aes_type = HSM_KEY_AES_128;
    else if (key_size == 24)
        aes_type = HSM_KEY_AES_192;
    else if (key_size == 32)
        aes_type = HSM_KEY_AES_256;
    r = store_keys(aes_key, aes_type, key_id, 0);
    if (r != CCID_OK)
        return SW_MEMORY_FAILURE();
    low_flash_available();
    return SW_OK();
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey) {
    if (wait_button() == true) //timeout
        return CCID_VERIFICATION_FAILED;
        
    int key_size = file_get_size(fkey);
    uint8_t kdata[4096/8], kdom = get_key_domain(fkey);
    memcpy(kdata, file_get_data(fkey), key_size);
    if (dkek_decrypt(kdom, kdata, key_size) != 0) {
        return CCID_EXEC_ERROR;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size/2) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata+key_size/2, key_size/2) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return CCID_WRONG_DATA;
    }
    return CCID_OK;
}

int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey) {
    if (wait_button() == true) //timeout
        return CCID_VERIFICATION_FAILED;
        
    int key_size = file_get_size(fkey), kdom = get_key_domain(fkey);
    uint8_t kdata[67]; //Worst case, 521 bit + 1byte
    memcpy(kdata, file_get_data(fkey), key_size);
    if (dkek_decrypt(kdom, kdata, key_size) != 0) {
        return CCID_EXEC_ERROR;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    int r = mbedtls_ecp_read_key(gid, ctx, kdata+1, key_size-1);
    if (r != 0) {
        mbedtls_ecdsa_free(ctx);
        return CCID_EXEC_ERROR;
    }
    return CCID_OK;
}

//-----
/* From OpenSC */
static const u8 hdr_md5[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const u8 hdr_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
	0x05, 0x00, 0x04, 0x14
};
static const u8 hdr_sha256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const u8 hdr_sha384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const u8 hdr_sha512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const u8 hdr_sha224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const u8 hdr_ripemd160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};
static const struct digest_info_prefix {
	mbedtls_md_type_t algorithm;
	const uint8_t *	hdr;
	size_t hdr_len;
	size_t hash_len;
} digest_info_prefix[] = {
      {	MBEDTLS_MD_MD5,	hdr_md5, sizeof(hdr_md5), 16 },
      { MBEDTLS_MD_SHA1, hdr_sha1, sizeof(hdr_sha1), 20	},
      { MBEDTLS_MD_SHA256, hdr_sha256, sizeof(hdr_sha256), 32 },
      { MBEDTLS_MD_SHA384, hdr_sha384, sizeof(hdr_sha384), 48 },
      { MBEDTLS_MD_SHA512, hdr_sha512, sizeof(hdr_sha512), 64 },
      { MBEDTLS_MD_SHA224, hdr_sha224, sizeof(hdr_sha224), 28 },
      { MBEDTLS_MD_RIPEMD160,hdr_ripemd160,	sizeof(hdr_ripemd160), 20 },
      {	0, NULL, 0,	0 }
};
int pkcs1_strip_digest_info_prefix(mbedtls_md_type_t *algorithm, const uint8_t *in_dat, size_t in_len, uint8_t *out_dat, size_t *out_len)
{
	for (int i = 0; digest_info_prefix[i].algorithm != 0; i++) {
		size_t hdr_len = digest_info_prefix[i].hdr_len, hash_len = digest_info_prefix[i].hash_len;
		const uint8_t *hdr = digest_info_prefix[i].hdr;
		if (in_len == (hdr_len + hash_len) && !memcmp(in_dat, hdr, hdr_len)) {
			if (algorithm)
				*algorithm = digest_info_prefix[i].algorithm;
			if (out_dat == NULL)
				return CCID_OK;
			if (*out_len < hash_len)
				return CCID_WRONG_DATA;
			memmove(out_dat, in_dat + hdr_len, hash_len);
			*out_len = hash_len;
			return CCID_OK;
		}
	}
	return CCID_EXEC_ERROR;
}
//-------

static int cmd_signature() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    file_t *fkey;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) || !fkey->data) 
        return SW_FILE_NOT_FOUND();
    int key_size = file_get_size(fkey);
    if (p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_EC_SHA1)
        md = MBEDTLS_MD_SHA1;
    else if (p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS_SHA256 || p2 == ALGO_EC_SHA256)
        md = MBEDTLS_MD_SHA256;
    else if (p2 == ALGO_EC_SHA224)
        md = MBEDTLS_MD_SHA224;
    if (p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_EC_SHA1 || p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS_SHA256 || p2 == ALGO_EC_SHA256 || p2 == ALGO_EC_SHA224) {
        generic_hash(md, apdu.data, apdu.nc, apdu.data);
        apdu.nc = mbedtls_md_get_size(mbedtls_md_info_from_type(md));
    }
    if (p2 == ALGO_RSA_RAW || p2 == ALGO_RSA_PKCS1 || p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_RSA_PSS_SHA256) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        
        int r;
        r = load_private_key_rsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        uint8_t *hash = apdu.data;
        size_t hash_len = apdu.nc;
        if (p2 == ALGO_RSA_PKCS1) { //DigestInfo attached
            size_t nc = apdu.nc;
            if (pkcs1_strip_digest_info_prefix(&md, apdu.data, apdu.nc, apdu.data, &nc) != CCID_OK) //gets the MD algo id and strips it off
                return SW_EXEC_ERROR();
            apdu.nc = nc;
        }
        else {
            //sc_asn1_print_tags(apdu.data, apdu.nc);
            size_t tout = 0, oid_len = 0;
            uint8_t *p = NULL, *oid = NULL;
            if (asn1_find_tag(apdu.data, apdu.nc, 0x30, &tout, &p) && tout > 0 && p != NULL) {
                size_t tout30 = 0;
                uint8_t *c30 = NULL;
                if (asn1_find_tag(p, tout, 0x30, &tout30, &c30) && tout30 > 0 && c30 != NULL) {
                    asn1_find_tag(c30, tout30, 0x6, &oid_len, &oid);
                }
                asn1_find_tag(p, tout, 0x4, &hash_len, &hash);
            }
            if (oid && oid_len > 0) {
                if (memcmp(oid, "\x2B\x0E\x03\x02\x1A", oid_len) == 0) 
                    md = MBEDTLS_MD_SHA1;
                else if (memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", oid_len) == 0) 
                    md = MBEDTLS_MD_SHA224;
                else if (memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", oid_len) == 0) 
                    md = MBEDTLS_MD_SHA256;
                else if (memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", oid_len) == 0) 
                    md = MBEDTLS_MD_SHA384;
                else if (memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", oid_len) == 0) 
                    md = MBEDTLS_MD_SHA512;
            }
            if (p2 == ALGO_RSA_PSS || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_RSA_PSS_SHA256) {
                if (p2 == ALGO_RSA_PSS && !oid) {
                    if (apdu.nc == 20) //default is sha1
                        md = MBEDTLS_MD_SHA1;
                    else if (apdu.nc == 32) 
                        md = MBEDTLS_MD_SHA256;
                }
                mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, md);
            }
        }
        if (md == MBEDTLS_MD_NONE) {
            if (apdu.nc < key_size) //needs padding
                memset(apdu.data+apdu.nc, 0, key_size-apdu.nc);
            r = mbedtls_rsa_private(&ctx, random_gen, NULL, apdu.data, res_APDU);
        }
        else {
            uint8_t *signature = (uint8_t *)calloc(key_size, sizeof(uint8_t));
            r = mbedtls_rsa_pkcs1_sign(&ctx, random_gen, NULL, md, hash_len, hash, signature);
            memcpy(res_APDU, signature, key_size);
            free(signature);
        }
        if (r != 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        res_APDU_size = key_size;
        apdu.ne = key_size;
        mbedtls_rsa_free(&ctx);
    }
    else if (p2 == ALGO_EC_RAW || p2 == ALGO_EC_SHA1 || p2 == ALGO_EC_SHA224 || p2 == ALGO_EC_SHA256) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        md = MBEDTLS_MD_SHA256;
        if (p2 == ALGO_EC_RAW) {
            if (apdu.nc == 32)
                md = MBEDTLS_MD_SHA256;
            else if (apdu.nc == 20)
                md = MBEDTLS_MD_SHA1;
            else if (apdu.nc == 28)
                md = MBEDTLS_MD_SHA224;
            else if (apdu.nc == 48)
                md = MBEDTLS_MD_SHA384;
            else if (apdu.nc == 64)
                md = MBEDTLS_MD_SHA512;
        }
        if (p2 == ALGO_EC_SHA1)
            md = MBEDTLS_MD_SHA1;
        else if (p2 == ALGO_EC_SHA224)
            md = MBEDTLS_MD_SHA224;
        else if (p2 == ALGO_EC_SHA256)
            md = MBEDTLS_MD_SHA256;
        int r;
        r = load_private_key_ecdsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        uint8_t buf[MBEDTLS_ECDSA_MAX_LEN];
        if (mbedtls_ecdsa_write_signature(&ctx, md, apdu.data, apdu.nc, buf, MBEDTLS_ECDSA_MAX_LEN, &olen, random_gen, NULL) != 0) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        memcpy(res_APDU, buf, olen);
        res_APDU_size = olen;
        mbedtls_ecdsa_free(&ctx);
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}

static int cmd_key_wrap() {
    int key_id = P1(apdu), r = 0;
    if (P2(apdu) != 0x92)
        return SW_WRONG_P1P2();
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    uint8_t kdom = get_key_domain(ef);
    if (!ef)
        return SW_FILE_NOT_FOUND();
    file_t *prkd = search_dynamic_file((PRKD_PREFIX << 8) | key_id);
    if (!prkd)
        return SW_FILE_NOT_FOUND();
    const uint8_t *dprkd = file_get_data(prkd);
    size_t wrap_len = MAX_DKEK_ENCODE_KEY_BUFFER;
    if (*dprkd == P15_KEYTYPE_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, HSM_KEY_RSA, res_APDU, &wrap_len);
        mbedtls_rsa_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_ECC) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        r = dkek_encode_key(kdom, &ctx, HSM_KEY_EC, res_APDU, &wrap_len);
        mbedtls_ecdsa_free(&ctx);
    }
    else if (*dprkd == P15_KEYTYPE_AES) {
        uint8_t kdata[32]; //maximum AES key size
        if (wait_button() == true) //timeout
            return SW_SECURE_MESSAGE_EXEC_ERROR();
        
        int key_size = file_get_size(ef), aes_type = HSM_KEY_AES;
        memcpy(kdata, file_get_data(ef), key_size);
        if (dkek_decrypt(kdom, kdata, key_size) != 0) {
            return SW_EXEC_ERROR();
        }
        if (key_size == 32)
            aes_type = HSM_KEY_AES_256;
        else if (key_size == 24)
            aes_type = HSM_KEY_AES_192;
        else if (key_size == 16)
            aes_type = HSM_KEY_AES_128;
        r = dkek_encode_key(kdom, kdata, aes_type, res_APDU, &wrap_len);
    }
    if (r != CCID_OK)
        return SW_EXEC_ERROR();
    res_APDU_size = wrap_len;
    return SW_OK();
}

static int cmd_key_unwrap() {
    int key_id = P1(apdu), r = 0;
    if (P2(apdu) != 0x93)
        return SW_WRONG_P1P2();
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    int key_type = dkek_type_key(apdu.data);
    uint8_t kdom = -1;
    if (key_type == 0x0)
        return SW_DATA_INVALID();
    if (key_type == HSM_KEY_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        do {
            r = dkek_decode_key(++kdom, &ctx, apdu.data, apdu.nc, NULL);
        } while((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, SC_PKCS15_TYPE_PRKEY_RSA, key_id, kdom);
        mbedtls_rsa_free(&ctx);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (key_type == HSM_KEY_EC) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        do {
            r = dkek_decode_key(++kdom, &ctx, apdu.data, apdu.nc, NULL);
        } while((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, SC_PKCS15_TYPE_PRKEY_EC, key_id, kdom);
        mbedtls_ecdsa_free(&ctx);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (key_type == HSM_KEY_AES) {
        uint8_t aes_key[32];
        int key_size = 0, aes_type = 0;
        do {
            r = dkek_decode_key(++kdom, aes_key, apdu.data, apdu.nc, &key_size);
        } while((r == CCID_ERR_FILE_NOT_FOUND || r == CCID_WRONG_DKEK) && kdom < MAX_KEY_DOMAINS);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        if (key_size == 32)
            aes_type = HSM_KEY_AES_256;
        else if (key_size == 24)
            aes_type = HSM_KEY_AES_192;
        else if (key_size == 16)
            aes_type = HSM_KEY_AES_128;
        else
            return SW_EXEC_ERROR();
        r = store_keys(aes_key, aes_type, key_id, kdom);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
    }
    if (kdom > 0) {
        uint8_t meta[3] = {0x92,1,kdom};
        r = meta_add((KEY_PREFIX << 8) | key_id, meta, sizeof(meta));
        if (r != CCID_OK)
            return r;
    }
    return SW_OK();
}

static int cmd_decrypt_asym() {
    int key_id = P1(apdu);
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef)
        return SW_FILE_NOT_FOUND();
    if (P2(apdu) == ALGO_RSA_DECRYPT) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        int r = load_private_key_rsa(&ctx, ef);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        int key_size = file_get_size(ef);
        if (apdu.nc < key_size) //needs padding
            memset(apdu.data+apdu.nc, 0, key_size-apdu.nc);
        r = mbedtls_rsa_private(&ctx, random_gen, NULL, apdu.data, res_APDU);
        if (r != 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        res_APDU_size = key_size;
        mbedtls_rsa_free(&ctx);
    }
    else if (P2(apdu) == ALGO_EC_DH) {
        mbedtls_ecdh_context ctx;
        if (wait_button() == true) //timeout
            return SW_SECURE_MESSAGE_EXEC_ERROR();
        int key_size = file_get_size(ef);
        uint8_t *kdata = (uint8_t *)calloc(1,key_size), kdom = get_key_domain(ef);
        memcpy(kdata, file_get_data(ef), key_size);
        if (dkek_decrypt(kdom, kdata, key_size) != 0) {
            free(kdata);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecdh_init(&ctx);
        mbedtls_ecp_group_id gid = kdata[0];
        int r = 0;
        r = mbedtls_ecdh_setup(&ctx, gid);
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            free(kdata);
            return SW_DATA_INVALID();
        }
        r = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.d, kdata+1, key_size-1);
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            free(kdata);
            return SW_DATA_INVALID();
        }
        free(kdata);
        r = mbedtls_ecdh_read_public(&ctx, apdu.data-1, apdu.nc+1);
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            return SW_DATA_INVALID();
        }
        size_t olen = 0;
        res_APDU[0] = 0x04;
        r = mbedtls_ecdh_calc_secret(&ctx, &olen, res_APDU+1, MBEDTLS_ECP_MAX_BYTES, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecdh_free(&ctx);
            return SW_EXEC_ERROR();
        }
        res_APDU_size = olen+1;
        mbedtls_ecdh_free(&ctx);
    }
    else
        return SW_WRONG_P1P2();
    return SW_OK();
}

static int cmd_cipher_sym() {
    int key_id = P1(apdu);
    int algo = P2(apdu);
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef)
        return SW_FILE_NOT_FOUND();
    if ((apdu.nc % 16) != 0) {
        return SW_WRONG_LENGTH();
    }
    if (wait_button() == true) //timeout
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    int key_size = file_get_size(ef);
    uint8_t kdata[32]; //maximum AES key size
    uint8_t kdom = get_key_domain(ef);
    memcpy(kdata, file_get_data(ef), key_size);
    if (dkek_decrypt(kdom, kdata, key_size) != 0) {
        return SW_EXEC_ERROR();
    }
    if (algo == ALGO_AES_CBC_ENCRYPT || algo == ALGO_AES_CBC_DECRYPT) {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        uint8_t tmp_iv[IV_SIZE];
        memset(tmp_iv, 0, sizeof(tmp_iv));
        if (algo == ALGO_AES_CBC_ENCRYPT) {
            int r = mbedtls_aes_setkey_enc(&aes, kdata, key_size*8);
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, apdu.nc, tmp_iv, apdu.data, res_APDU);
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
        }
        else if (algo == ALGO_AES_CBC_DECRYPT) {
            int r = mbedtls_aes_setkey_dec(&aes, kdata, key_size*8);
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, apdu.nc, tmp_iv, apdu.data, res_APDU);
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
        }
        res_APDU_size = apdu.nc;
        mbedtls_aes_free(&aes);
    }
    else if (algo == ALGO_AES_CMAC) {
        const mbedtls_cipher_info_t *cipher_info;
        if (key_size == 16)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        else if (key_size == 24)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
        else if (key_size == 32)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        else
            return SW_WRONG_DATA();
        int r = mbedtls_cipher_cmac(cipher_info, kdata, key_size*8, apdu.data, apdu.nc, res_APDU);
        if (r != 0)
            return SW_EXEC_ERROR();
        res_APDU_size = 16;
    }
    else if (algo == ALGO_AES_DERIVE) {
        int r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, file_get_data(ef), key_size, apdu.data, apdu.nc, res_APDU, apdu.nc);
        if (r != 0)
            return SW_EXEC_ERROR();
        res_APDU_size = apdu.nc;
    }
    else {
        return SW_WRONG_P1P2();
    }
    return SW_OK();
}

#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
#define MOD_ADD( N )                                                    \
    while( mbedtls_mpi_cmp_mpi( &(N), &grp->P ) >= 0 )                  \
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( &(N), &(N), &grp->P ) )
static inline int mbedtls_mpi_add_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( X, A, B ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

static int cmd_derive_asym() {
    uint8_t key_id = P1(apdu);
    uint8_t dest_id = P2(apdu);
    file_t *fkey;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) || !fkey->data) 
        return SW_FILE_NOT_FOUND();

    if (apdu.nc == 0)
        return SW_WRONG_LENGTH();
    if (apdu.data[0] == ALGO_EC_DERIVE) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        
        int r;
        r = load_private_key_ecdsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED)
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            return SW_EXEC_ERROR();
        }
        mbedtls_mpi a, nd;
        mbedtls_mpi_init(&a);
        mbedtls_mpi_init(&nd);
        r = mbedtls_mpi_read_binary(&a, apdu.data+1, apdu.nc-1);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_DATA_INVALID();
        }
        r = mbedtls_mpi_add_mod(&ctx.grp, &nd, &ctx.d, &a);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_copy(&ctx.d, &nd);
        if (r != 0) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_EXEC_ERROR();
        }
        uint8_t kdom = get_key_domain(fkey);
        r = store_keys(&ctx, SC_PKCS15_TYPE_PRKEY_EC, dest_id, kdom);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecdsa_free(&ctx);
        mbedtls_mpi_free(&a);
        mbedtls_mpi_free(&nd);
    }
    else 
        return SW_WRONG_DATA();
    return SW_OK();
}

static int cmd_extras() {
    if (P2(apdu) != 0x0)
        return SW_INCORRECT_P1P2();
    if (P1(apdu) == 0xA) { //datetime operations
        if (apdu.nc == 0) {
            datetime_t dt;
            if (!rtc_get_datetime(&dt))
                return SW_EXEC_ERROR();
            res_APDU[res_APDU_size++] = dt.year >> 8;
            res_APDU[res_APDU_size++] = dt.year & 0xff;
            res_APDU[res_APDU_size++] = dt.month;
            res_APDU[res_APDU_size++] = dt.day;
            res_APDU[res_APDU_size++] = dt.dotw;
            res_APDU[res_APDU_size++] = dt.hour;
            res_APDU[res_APDU_size++] = dt.min;
            res_APDU[res_APDU_size++] = dt.sec;
        }
        else {
            if (apdu.nc != 8)
                return SW_WRONG_LENGTH();
            datetime_t dt;
            dt.year = (apdu.data[0] << 8) | (apdu.data[1]);
            dt.month = apdu.data[2];
            dt.day = apdu.data[3];
            dt.dotw = apdu.data[4];
            dt.hour = apdu.data[5];
            dt.min = apdu.data[6];
            dt.sec = apdu.data[7];
            if (!rtc_set_datetime(&dt))
                return SW_WRONG_DATA();
        }
    }
    else if (P1(apdu) == 0x6) { //dynamic options
        if (apdu.nc > sizeof(uint8_t))
            return SW_WRONG_LENGTH();
        uint16_t opts = get_device_options();
        if (apdu.nc == 0) {
            res_APDU[res_APDU_size++] = opts >> 8;
            res_APDU[res_APDU_size++] = opts & 0xff;
        }
        else {
            uint8_t newopts[] = { apdu.data[0], (opts & 0xff) };
            file_t *tf = search_by_fid(EF_DEVOPS, NULL, SPECIFY_EF);
            flash_write_data_to_file(tf, newopts, sizeof(newopts));
            low_flash_available();
        }
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}

static int cmd_mse() {
    int p1 = P1(apdu);
    int p2 = P2(apdu);
    if (p1 & 0x1) { //SET
        if (p2 == 0xA4) { //AT
            uint16_t tag = 0x0;
            uint8_t *tag_data = NULL, *p = NULL;
            size_t tag_len = 0;    
            while (walk_tlv(apdu.data, apdu.nc, &p, &tag, &tag_len, &tag_data)) {
                if (tag == 0x80) {
                    if (tag_len == 10 && memcmp(tag_data, "\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x02", tag_len) == 0)
                        sm_set_protocol(MSE_AES);
                    else if (tag_len == 10 && memcmp(tag_data, "\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x01", tag_len) == 0)
                        sm_set_protocol(MSE_3DES);
                    else
                        return SW_REFERENCE_NOT_FOUND();
                }
            }
        }
        else
            return SW_INCORRECT_P1P2();
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}

int cmd_general_authenticate() {
    if (P1(apdu) == 0x0 && P2(apdu) == 0x0) {
        if (apdu.data[0] == 0x7C) {
            int r = 0;
            size_t pubkey_len = 0;
            const uint8_t *pubkey = NULL;
            uint16_t tag = 0x0;
            uint8_t *tag_data = NULL, *p = NULL;
            size_t tag_len = 0;    
            while (walk_tlv(apdu.data+2, apdu.nc-2, &p, &tag, &tag_len, &tag_data)) {
                if (tag == 0x80) {
                    pubkey = tag_data-1; //mbedtls ecdh starts reading one pos before
                    pubkey_len = tag_len+1;
                }
            }
            mbedtls_ecdh_context ctx;
            int key_size = file_read_uint16(termca_pk);
            mbedtls_ecdh_init(&ctx);
            mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_SECP192R1;
            r = mbedtls_ecdh_setup(&ctx, gid);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.d, termca_pk+2, key_size);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecdh_read_public(&ctx, pubkey, pubkey_len);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            uint8_t derived[MBEDTLS_ECP_MAX_BYTES];
            r = mbedtls_ecdh_calc_secret(&ctx, &olen, derived, MBEDTLS_ECP_MAX_BYTES, random_gen, NULL);
            mbedtls_ecdh_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }

            sm_derive_all_keys(derived, olen);
            
            uint8_t *t = (uint8_t *)calloc(1, pubkey_len+16);
            memcpy(t, "\x7F\x49\x3F\x06\x0A", 5);
            if (sm_get_protocol() == MSE_AES)
                memcpy(t+5, "\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x02", 10);
            else if (sm_get_protocol() == MSE_3DES)
                memcpy(t+5, "\x04\x00\x7F\x00\x07\x02\x02\x03\x02\x01", 10);
            t[15] = 0x86;
            memcpy(t+16, pubkey, pubkey_len);
            
            res_APDU[res_APDU_size++] = 0x7C;
            res_APDU[res_APDU_size++] = 20;
            res_APDU[res_APDU_size++] = 0x81;
            res_APDU[res_APDU_size++] = 8;
            memcpy(res_APDU+res_APDU_size, sm_get_nonce(), 8);
            res_APDU_size += 8;
            res_APDU[res_APDU_size++] = 0x82;
            res_APDU[res_APDU_size++] = 8;
            
            r = sm_sign(t, pubkey_len+16, res_APDU+res_APDU_size);
            
            free(t);
            if (r != CCID_OK) 
                return SW_EXEC_ERROR();
            res_APDU_size += 8;
        }
    }
    return SW_OK();
}

int cmd_session_pin() {
    if (P1(apdu) == 0x01 && P2(apdu) == 0x81) {
        memcpy(sm_session_pin, random_bytes_get(8), 8);
        sm_session_pin_len = 8;
        
        memcpy(res_APDU, sm_session_pin, sm_session_pin_len);
        res_APDU_size = sm_session_pin_len;
        apdu.ne = sm_session_pin_len;
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

#define INS_VERIFY                  0x20
#define INS_MSE                     0x22
#define INS_CHANGE_PIN              0x24
#define INS_RESET_RETRY             0x2C
#define INS_KEYPAIR_GEN             0x46
#define INS_KEY_GEN                 0x48
#define INS_INITIALIZE              0x50
#define INS_KEY_DOMAIN              0x52
#define INS_LIST_KEYS               0x58
#define INS_SESSION_PIN             0x5A
#define INS_DECRYPT_ASYM            0x62
#define INS_EXTRAS                  0x64
#define INS_SIGNATURE               0x68
#define INS_WRAP                    0x72
#define INS_UNWRAP                  0x74
#define INS_DERIVE_ASYM             0x76
#define INS_CIPHER_SYM              0x78
#define INS_CHALLENGE               0x84
#define INS_GENERAL_AUTHENTICATE    0x86
#define INS_SELECT_FILE				0xA4
#define INS_READ_BINARY				0xB0
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
    { 0x00, 0x0}
};

int sc_hsm_process_apdu() {
    sm_unwrap();
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
