#include "sc_hsm.h"
#include "file.h"
#include "libopensc/card-sc-hsm.h"
#include "random.h"
#include "common.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"

const uint8_t sc_hsm_aid[] = {
    11, 
    0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01
};

uint8_t session_pin[32], session_sopin[32];
bool has_session_pin = false, has_session_sopin = false;
static uint8_t dkeks = 0, current_dkeks = 0;
static uint8_t tmp_dkek[IV_SIZE+32];

static int sc_hsm_process_apdu();

static void init_sc_hsm();

app_t *sc_hsm_select_aid(app_t *a) {
    if (!memcmp(apdu.cmd_apdu_data, sc_hsm_aid+1, MIN(apdu.cmd_apdu_data_len,sc_hsm_aid[0]))) {
        a->aid = sc_hsm_aid;
        a->process_apdu = sc_hsm_process_apdu;
        init_sc_hsm();
        return a;
    }
    return NULL;
}

void __attribute__ ((constructor)) sc_hsm_ctor() { 
    register_app(sc_hsm_select_aid);
}

void init_sc_hsm() {
    scan_flash();
    has_session_pin = has_session_sopin = false;
}

static int encrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len)
{
    mbedtls_aes_context aes;
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    memcpy(tmp_iv, iv, IV_SIZE);
    int r = mbedtls_aes_setkey_enc (&aes, key, 256);
    if (r != 0)
        return HSM_EXEC_ERROR;
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, tmp_iv, data, data);
}

static int decrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len)
{
    mbedtls_aes_context aes;
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    memcpy(tmp_iv, iv, IV_SIZE);
    int r = mbedtls_aes_setkey_enc (&aes, key, 256);
    if (r != 0)
        return HSM_EXEC_ERROR;
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, tmp_iv, data, data);
}

int load_dkek() {
    if (has_session_pin == false)
        return HSM_NO_LOGIN;
    file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
    if (!tf)
        return HSM_ERR_FILE_NOT_FOUND;
    memcpy(tmp_dkek, file_read(tf->data+sizeof(uint16_t)), IV_SIZE+32);
    int ret = decrypt(session_pin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
    if (ret != 0)
        return HSM_EXEC_ERROR;
    return HSM_OK;
}

void release_dkek() {
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
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
        isUserAuthenticated = false;
    }
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
    
    if (apdu.cmd_apdu_data_len >= 2)
        fid = get_uint16_t(apdu.cmd_apdu_data, 0);

    if ((fid & 0xff00) == (PRKD_PREFIX << 8)) {
        if (!(pe = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    else if ((fid & 0xff00) == (CD_PREFIX << 8)) {
        if (!(pe = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    else if ((fid & 0xff00) == (EE_CERTIFICATE_PREFIX << 8)) {
        if (!(pe = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    if (!pe) {
        if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
            if (apdu.cmd_apdu_data_len == 0) {
            	pe = (file_t *)MF;
            	//ac_fini();
            }
            else if (apdu.cmd_apdu_data_len == 2) {
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
            if (apdu.cmd_apdu_data_len != 0)
                return SW_FILE_NOT_FOUND();
        }
        else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
            if (!(pe = search_by_name(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len))) {
                return SW_FILE_NOT_FOUND();
            }
            if (card_terminated) {
                return set_res_sw (0x62, 0x85);
            }        
        }
        else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
            if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, MF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
            if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, currentDF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        process_fci(pe);
    }
    else
        return SW_INCORRECT_P1P2();
    select_file(pe);
    return SW_OK ();
}

int parse_token_info(const file_t *f, int mode) {
    char *label = "HSM2040";
    char *manu = "Pol Henarejos";
    sc_pkcs15_tokeninfo_t *ti = (sc_pkcs15_tokeninfo_t *)calloc(1, sizeof(sc_pkcs15_tokeninfo_t));
    ti->version = 3;
    ti->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_EID_COMPLIANT;
    ti->label = (char *)calloc(strlen(label)+1, sizeof(char));
    strlcpy(ti->label, label, strlen(label)+1);
    ti->serial_number = (char *)calloc(2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1, sizeof(char));
    pico_get_unique_board_id_string(ti->serial_number, 2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1);
    ti->manufacturer_id = (char *)calloc(strlen(manu)+1, sizeof(char));
    strlcpy(ti->manufacturer_id, manu, strlen(manu)+1);

    uint8_t *b;
    size_t len;
    int r = sc_pkcs15_encode_tokeninfo(NULL, ti, &b, &len);
    if (mode == 1) {
        memcpy(res_APDU, b, len);
        res_APDU_size = len;
    }
    free(b);
    sc_pkcs15_free_tokeninfo(ti);
    return len;
}


static int cmd_list_keys()
{
    //first CC
    for (int i = 0; i < dynamic_files; i++) {
        file_t *f = &dynamic_file[i];
        if ((f->fid & 0xff00) == (PRKD_PREFIX << 8)) {
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
    return SW_OK();
}

static int cmd_read_binary()
{
    uint16_t fid;
    uint32_t offset;
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
            
            if (apdu.cmd_apdu_data[0] != 0x54)
                return SW_WRONG_DATA();
                
            offset = 0;
            for (int d = 0; d < apdu.cmd_apdu_data[1]; d++)
                offset |= apdu.cmd_apdu_data[2+d]<<(apdu.cmd_apdu_data[1]-1-d)*8;
        }        
    }
    
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            uint16_t data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *)ef, 1); //already copies content to res_APDU
            if (offset > data_len)
                return SW_WRONG_P1P2();
            uint16_t maxle = data_len-offset;
            if (apdu.expected_res_size > maxle)
                apdu.expected_res_size = maxle;
            if (offset) {
                res_APDU += offset;
                res_APDU_size -= offset;
            }
        }
        else {
            uint16_t data_len = file_read_uint16(ef->data);
            if (offset > data_len)
                return SW_WRONG_P1P2();
        
            uint16_t maxle = data_len-offset;
            if (apdu.expected_res_size > maxle)
                apdu.expected_res_size = maxle;
            res_APDU = file_read(ef->data+2+offset);
            res_APDU_size = data_len-offset;
        }
    }

    return SW_OK();
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin)
        return HSM_ERR_NULL_PARAM; 
    const file_t *max = search_by_fid(pin->fid+1, NULL, SPECIFY_EF);
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!max || !act)
        return HSM_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(act->data+2);
    if (retries == 0 && force == false) //blocked
        return HSM_ERR_BLOCKED;
    retries = file_read_uint8(max->data+2);
    int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
    low_flash_available();
    return r;
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin)
        return HSM_ERR_NULL_PARAM; 
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!act)
        return HSM_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(act->data+2);
    if (retries > 0) {
        retries -= 1;
        int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
        low_flash_available();
        return r;
    }
    return HSM_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!pin)
        return SW_FILE_NOT_FOUND();
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    uint8_t dhash[32];
    double_hash_pin(data, len, dhash);
    if (sizeof(dhash) != file_read_uint16(pin->data)-1) //1 byte for pin len
        return SW_CONDITIONS_NOT_SATISFIED();
    if (memcmp(file_read(pin->data+3), dhash, sizeof(dhash)) != 0) {
        if (pin_wrong_retry(pin) != HSM_OK)
            return SW_PIN_BLOCKED();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int r = pin_reset_retries(pin, false);
    if (r == HSM_ERR_BLOCKED)
        return SW_PIN_BLOCKED();
    if (r != HSM_OK)
        return SW_MEMORY_FAILURE();
    isUserAuthenticated = true;
    hash_multi(data, len, session_pin);
    has_session_pin = true;
    return SW_OK();
}

static int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    
    if (p1 != 0x0 || (p2 & 0x60) != 0x0)
        return SW_WRONG_P1P2();
    uint8_t qualifier = p2&0x1f;
    if (p2 == 0x81) { //UserPin
        if (apdu.cmd_apdu_data_len > 0) {
            return check_pin(file_pin1, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
        }
        if (file_read_uint8(file_retries_pin1->data+2) == 0)
            return SW_PIN_BLOCKED();
        return set_res_sw (0x63, 0xc0 | file_read_uint8(file_retries_pin1->data+2));
    }
    else if (p2 == 0x88) { //SOPin
    }
    return SW_REFERENCE_NOT_FOUND();
}

static int cmd_reset_retry() {
    if (P1(apdu) == 0x0) {
        if (P2(apdu) == 0x81) {
            if (!file_sopin || !file_pin1) {
                return SW_FILE_NOT_FOUND();
            }
            if (!file_sopin->data) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint16_t r = check_pin(file_sopin, apdu.cmd_apdu_data, 8);
            if (r != 0x9000)
                return r;
            uint8_t dhash[33];
            dhash[0] = apdu.cmd_apdu_data_len-8;
            double_hash_pin(apdu.cmd_apdu_data+8, apdu.cmd_apdu_data_len-8, dhash+1);
            flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
            if (pin_reset_retries(file_pin1, true) != HSM_OK)
                return SW_MEMORY_FAILURE();
            low_flash_available();
            return SW_OK();
        }
    }
}

static int cmd_challenge() {
    memcpy(res_APDU, random_bytes_get(apdu.expected_res_size), apdu.expected_res_size);
    res_APDU_size = apdu.expected_res_size;
    return SW_OK();
}

static int cmd_initialize() {
    initialize_flash(true);
    scan_flash();
    dkeks = 0;
    const uint8_t *p = apdu.cmd_apdu_data;
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        uint8_t tag = *p++;
        uint8_t tag_len = *p++;
        if (tag == 0x80) { //options
        }
        else if (tag == 0x81) { //user pin
            if (file_pin1 && file_pin1->data) {
                uint8_t dhash[33];
                dhash[0] = tag_len;
                double_hash_pin(p, tag_len, dhash+1);
                flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
                hash_multi(p, tag_len, session_pin);
                has_session_pin = true;
            } 
        }
        else if (tag == 0x82) { //user pin
            if (file_sopin && file_sopin->data) {
                uint8_t dhash[33];
                dhash[0] = tag_len;
                double_hash_pin(p, tag_len, dhash+1);
                flash_write_data_to_file(file_sopin, dhash, sizeof(dhash));
                hash_multi(p, tag_len, session_sopin);
                has_session_sopin = true;
            } 
        }
        else if (tag == 0x91) { //user pin
            file_t *tf = search_by_fid(0x1082, NULL, SPECIFY_EF);
            if (tf && tf->data) {
                flash_write_data_to_file(tf, p, tag_len);
            }
            if (file_retries_pin1 && file_retries_pin1->data) {
                flash_write_data_to_file(file_retries_pin1, p, tag_len);
            }
        }
        else if (tag == 0x92) {
            dkeks = *p;
            current_dkeks = 0;
        }
        p += tag_len;
    }
    p = random_bytes_get(32);
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
    memcpy(tmp_dkek, p, IV_SIZE);
    if (dkeks == 0) {
        p = random_bytes_get(32);
        memcpy(tmp_dkek+IV_SIZE, p, 32);
        encrypt(session_pin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
        file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
        flash_write_data_to_file(tf, tmp_dkek, sizeof(tmp_dkek));
        low_flash_available();
    }
    return SW_OK();
}

void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]) {
    uint8_t o1[32];
    hash_multi(pin, len, o1);
    for (int i = 0; i < sizeof(o1); i++)
        o1[i] ^= pin[i%len];
    hash_multi(o1, sizeof(o1), output);
}

void hash_multi(const uint8_t *input, size_t len, uint8_t output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int iters = 256;
    
    pico_get_unique_board_id(&unique_id);
    
    mbedtls_sha256_starts (&ctx, 0);
    mbedtls_sha256_update (&ctx, unique_id.id, sizeof(unique_id.id));
    
    while (iters > len)
    {
        mbedtls_sha256_update (&ctx, input, len);
        iters -= len;
    }
    if (iters > 0) // remaining iterations
        mbedtls_sha256_update (&ctx, input, iters);
    mbedtls_sha256_finish (&ctx, output);
    mbedtls_sha256_free (&ctx);
}

void hash(const uint8_t *input, size_t len, uint8_t output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    
    mbedtls_sha256_starts (&ctx, 0);
    mbedtls_sha256_update (&ctx, input, len);

    mbedtls_sha256_finish (&ctx, output);
    mbedtls_sha256_free (&ctx);
}

static int cmd_import_dkek() {
    if (dkeks == 0)
        return SW_COMMAND_NOT_ALLOWED();
    if (has_session_pin == false)
        return SW_CONDITIONS_NOT_SATISFIED();
    file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
    if (!authenticate_action(get_parent(tf), ACL_OP_CREATE_EF)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.cmd_apdu_data_len > 0) {
        for (int i = 0; i < apdu.cmd_apdu_data_len; i++)
            tmp_dkek[IV_SIZE+i] ^= apdu.cmd_apdu_data[i];
        if (++current_dkeks == dkeks) {
            encrypt(session_pin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
            flash_write_data_to_file(tf, tmp_dkek, sizeof(tmp_dkek));
            memset(tmp_dkek, 0, sizeof(tmp_dkek));
            low_flash_available();
        }
    }
    res_APDU[0] = dkeks;
    res_APDU[1] = dkeks-current_dkeks;
    //FNV hash
    uint64_t hash = 0xcbf29ce484222325;
    memcpy(tmp_dkek, file_read(tf->data+sizeof(uint16_t)), IV_SIZE+32);
    decrypt(session_pin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
    for (int i = 0; i < 32; i++) {
        hash ^= tmp_dkek[IV_SIZE+i];
        hash *= 0x00000100000001B3;
    }
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
    memcpy(res_APDU+2,&hash,sizeof(hash));
    res_APDU_size = 2+sizeof(hash);
    return SW_OK();
}

struct ec_curve_mbed_id {
    struct sc_lv_data curve;
    mbedtls_ecp_group_id id;
};
struct ec_curve_mbed_id ec_curves_mbed[] = {
    {   { (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 24}, MBEDTLS_ECP_DP_SECP192R1 },
    {   { (unsigned char *) "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 32}, MBEDTLS_ECP_DP_SECP256R1 },
    {   { (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF", 48}, MBEDTLS_ECP_DP_SECP384R1 },
    {   { (unsigned char *) "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 66}, MBEDTLS_ECP_DP_SECP521R1 },
    {   { (unsigned char *) "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77", 32}, MBEDTLS_ECP_DP_BP256R1 },
    {   { (unsigned char *) "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x53", 48}, MBEDTLS_ECP_DP_BP384R1 },
    {   { (unsigned char *) "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF3", 64}, MBEDTLS_ECP_DP_BP512R1 },
    {   { (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xEE\x37", 24}, MBEDTLS_ECP_DP_SECP192K1 },
    {   { (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F", 32}, MBEDTLS_ECP_DP_SECP256K1 },
    {   { NULL, 0 }, MBEDTLS_ECP_DP_NONE }
};

//Stores the private and public keys in flash
int store_keys(void *key_ctx, int type, uint8_t key_id, sc_context_t *ctx) {
    int r, key_size;
    uint8_t *asn1bin, *kdata;
    size_t asn1len = 0;
    if (type == SC_PKCS15_TYPE_PRKEY_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *)key_ctx;
        key_size = mbedtls_mpi_size(&rsa->P)+mbedtls_mpi_size(&rsa->Q);
        kdata = (uint8_t *)calloc(1, key_size);
        mbedtls_mpi_write_binary(&rsa->P, kdata, key_size/2);
        mbedtls_mpi_write_binary(&rsa->Q, kdata+key_size/2, key_size/2);
    }
    else {
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *)key_ctx;
        key_size = mbedtls_mpi_size(&ecdsa->d);
        kdata = (uint8_t *)calloc(1, key_size+1);
        kdata[0] = ecdsa->grp.id & 0xff;
        mbedtls_mpi_write_binary(&ecdsa->d, kdata+1, key_size);
        key_size++;
    }
    if ((r = load_dkek()) != HSM_OK)    
        return r;
    if ((r = encrypt(tmp_dkek+IV_SIZE, tmp_dkek, kdata, key_size)) != 0)
        return r;
    release_dkek();
    file_t *fpk = file_new((KEY_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, kdata, key_size);
    free(kdata); 
    if (r != HSM_OK)
        return r;
    //add_file_to_chain(fpk, &ef_kf);
        
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
    fpk = file_new((PRKD_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, asn1bin, asn1len);
    free(asn1bin);
    if (r != HSM_OK)
        return r;
    //add_file_to_chain(fpk, &ef_prkdf);
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
    fpk = file_new((CD_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, asn1bin, asn1len);
    free(asn1bin);
    if (r != HSM_OK)
        return r;
    //add_file_to_chain(fpk, &ef_cdf);
    low_flash_available();
    return HSM_OK;
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

#define C_ASN1_CVC_PUBKEY_SIZE 10
static const struct sc_asn1_entry c_asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE] = {
	{ "publicKeyOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "primeOrModulus", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientAorExponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 2,  SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "coefficientB", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 3, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "basePointG", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 4, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "order", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 5, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "publicPoint", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "cofactor", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 7, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ "modulusSize", SC_ASN1_INTEGER, SC_ASN1_UNI | SC_ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#define C_ASN1_CVC_BODY_SIZE 5
static const struct sc_asn1_entry c_asn1_cvc_body[C_ASN1_CVC_BODY_SIZE] = {
	{ "certificateProfileIdentifier", SC_ASN1_INTEGER, SC_ASN1_APP | 0x1F29, 0, NULL, NULL },
	{ "certificationAuthorityReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "publicKey", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F49, 0, NULL, NULL },
	{ "certificateHolderReference", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 0x1F20, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#define C_ASN1_CVCERT_SIZE 3
static const struct sc_asn1_entry c_asn1_cvcert[C_ASN1_CVCERT_SIZE] = {
	{ "certificateBody", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F4E, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#define C_ASN1_CVC_SIZE 2
static const struct sc_asn1_entry c_asn1_cvc[C_ASN1_CVC_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#define C_ASN1_AUTHREQ_SIZE 4
static const struct sc_asn1_entry c_asn1_authreq[C_ASN1_AUTHREQ_SIZE] = {
	{ "certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ "outerCAR", SC_ASN1_PRINTABLESTRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "signature", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F37, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#define C_ASN1_REQ_SIZE 2
static const struct sc_asn1_entry c_asn1_req[C_ASN1_REQ_SIZE] = {
	{ "authenticatedrequest", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 7, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15emu_sc_hsm_encode_cvc_req(sc_pkcs15_card_t * p15card, sc_cvc_t *cvc, u8 ** buf, size_t *buflen, bool only_body)
{
	sc_card_t *card = p15card->card;
	struct sc_asn1_entry asn1_req[C_ASN1_REQ_SIZE];
	struct sc_asn1_entry asn1_authreq[C_ASN1_AUTHREQ_SIZE];
	struct sc_asn1_entry asn1_cvc[C_ASN1_CVC_SIZE];
	struct sc_asn1_entry asn1_cvcert[C_ASN1_CVCERT_SIZE];
	struct sc_asn1_entry asn1_cvc_body[C_ASN1_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_cvc_pubkey[C_ASN1_CVC_PUBKEY_SIZE];
	size_t lenchr;
	size_t lencar;
	size_t lenoutCar;
	int r;

	sc_copy_asn1_entry(c_asn1_req, asn1_req);
	sc_copy_asn1_entry(c_asn1_authreq, asn1_authreq);
	sc_copy_asn1_entry(c_asn1_cvc, asn1_cvc);
	sc_copy_asn1_entry(c_asn1_cvcert, asn1_cvcert);
	sc_copy_asn1_entry(c_asn1_cvc_body, asn1_cvc_body);
	sc_copy_asn1_entry(c_asn1_cvc_pubkey, asn1_cvc_pubkey);

	asn1_cvc_pubkey[1].flags = SC_ASN1_OPTIONAL;
	asn1_cvcert[1].flags = SC_ASN1_OPTIONAL;

	sc_format_asn1_entry(asn1_cvc_pubkey    , &cvc->pukoid, NULL, 1);
	if (cvc->primeOrModulus && (cvc->primeOrModuluslen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 1, cvc->primeOrModulus, &cvc->primeOrModuluslen, 1);
	}
	sc_format_asn1_entry(asn1_cvc_pubkey + 2, cvc->coefficientAorExponent, &cvc->coefficientAorExponentlen, 1);
	if (cvc->coefficientB && (cvc->coefficientBlen > 0)) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 3, cvc->coefficientB, &cvc->coefficientBlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 4, cvc->basePointG, &cvc->basePointGlen, 1);
		sc_format_asn1_entry(asn1_cvc_pubkey + 5, cvc->order, &cvc->orderlen, 1);
		if (cvc->publicPoint && (cvc->publicPointlen > 0)) {
			sc_format_asn1_entry(asn1_cvc_pubkey + 6, cvc->publicPoint, &cvc->publicPointlen, 1);
		}
		sc_format_asn1_entry(asn1_cvc_pubkey + 7, cvc->cofactor, &cvc->cofactorlen, 1);
	}
	if (cvc->modulusSize > 0) {
		sc_format_asn1_entry(asn1_cvc_pubkey + 8, &cvc->modulusSize, NULL, 1);
	}

	sc_format_asn1_entry(asn1_cvc_body    , &cvc->cpi, NULL, 1);
	lencar = strnlen(cvc->car, sizeof cvc->car);
	sc_format_asn1_entry(asn1_cvc_body + 1, &cvc->car, &lencar, 1);
	sc_format_asn1_entry(asn1_cvc_body + 2, &asn1_cvc_pubkey, NULL, 1);
	lenchr = strnlen(cvc->chr, sizeof cvc->chr);
	sc_format_asn1_entry(asn1_cvc_body + 3, &cvc->chr, &lenchr, 1);

	sc_format_asn1_entry(asn1_cvcert    , &asn1_cvc_body, NULL, 1);
	if (only_body == true) {
	    r = sc_asn1_encode(card->ctx, asn1_cvcert, buf, buflen);
	}
	else {
    	if (cvc->signature && (cvc->signatureLen > 0)) {
    		sc_format_asn1_entry(asn1_cvcert + 1, cvc->signature, &cvc->signatureLen, 1);
    	}
    
    	sc_format_asn1_entry(asn1_authreq , &asn1_cvcert, NULL, 1);
    	lenoutCar = strnlen(cvc->outer_car, sizeof cvc->outer_car);
    	sc_format_asn1_entry(asn1_authreq + 1, &cvc->outer_car, &lenoutCar, 1);
    	if (cvc->outerSignature && (cvc->outerSignatureLen > 0)) {
    		sc_format_asn1_entry(asn1_authreq + 2, cvc->outerSignature, &cvc->outerSignatureLen, 1);
    	}
    	
    	sc_format_asn1_entry(asn1_req , &asn1_authreq, NULL, 1);
    	r = sc_asn1_encode(card->ctx, asn1_req, buf, buflen);
    }
    
	LOG_TEST_RET(card->ctx, r, "Could not encode card verifiable certificate");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

void cvc_init_common(sc_cvc_t *cvc) {
    memset(cvc, 0, sizeof(sc_cvc_t));

	strlcpy(cvc->car, "UTCA00001", sizeof cvc->car);
	strlcpy(cvc->chr, "ESHSMCVCA", sizeof cvc->chr);
	strlcat(cvc->chr, "00001", sizeof cvc->chr);
	strlcpy(cvc->outer_car, "ESHSM00001", sizeof(cvc->outer_car));
}

int cvc_prepare_signatures(sc_pkcs15_card_t *p15card, sc_cvc_t *cvc, size_t sig_len, uint8_t *hsh) {
    uint8_t *cvcbin;
    size_t cvclen;
    cvc->signatureLen = sig_len;
    cvc->signature = (uint8_t *)calloc(1, sig_len);
    cvc->outerSignatureLen = sig_len;
    cvc->outerSignature = (uint8_t *)calloc(1, sig_len);
    int r = sc_pkcs15emu_sc_hsm_encode_cvc_req(p15card, cvc, &cvcbin, &cvclen, true);
    if (r != SC_SUCCESS) {
        if (cvcbin)
            free(cvcbin);
        return r;
    }
    hash(cvcbin, cvclen, hsh);
    free(cvcbin);
    return HSM_OK;
}

static int cmd_keypair_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t auth_key_id = P2(apdu);
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    sc_context_t *ctx = create_context();
    struct sc_pkcs15_card p15card;
    p15card.card = (sc_card_t *)calloc(1, sizeof(sc_card_t));
    p15card.card->ctx = ctx;
    int ret = 0;
    
    size_t tout = 0;
    //sc_asn1_print_tags(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
    const uint8_t *p = sc_asn1_find_tag(ctx, (const uint8_t *)apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, 0x7f49, &tout);
    if (p) {
        size_t oid_len = 0;
        const uint8_t *oid = sc_asn1_find_tag(ctx, p, tout, 0x6, &oid_len);
        if (oid) {
            if (memcmp(oid, "\x4\x0\x7F\x0\x7\x2\x2\x2\x1\x2",MIN(oid_len,10)) == 0) { //RSA
                size_t ex_len, ks_len;
                const uint8_t *ex = sc_asn1_find_tag(ctx, p, tout, 0x82, &ex_len);
                const uint8_t *ks = sc_asn1_find_tag(ctx, p, tout, 0x2, &ks_len);
                int exponent = 65537, key_size = 2048;
                uint8_t *cvcbin = NULL;
	            size_t cvclen;
                if (ex) {
                    sc_asn1_decode_integer(ex, ex_len, &exponent, 0);
                }
                if (ks) {
                    sc_asn1_decode_integer(ks, ks_len, &key_size, 0);
                }
                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa);
                uint8_t index = 0;
                ret = mbedtls_rsa_gen_key(&rsa, random_gen, &index, key_size, exponent);
                if (ret != 0) {
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
                
                sc_cvc_t cvc;
                cvc_init_common(&cvc);
            	struct sc_object_id rsa15withSHA256 = { { 0,4,0,127,0,7,2,2,2,1,2,-1 } };
            	cvc.coefficientAorExponentlen = ex_len;
            	cvc.coefficientAorExponent = calloc(1, cvc.coefficientAorExponentlen);
	            memcpy(cvc.coefficientAorExponent, &exponent, cvc.coefficientAorExponentlen);

	            cvc.pukoid = rsa15withSHA256;
	            cvc.modulusSize = key_size;
	            cvc.primeOrModuluslen = key_size/8;
	            cvc.primeOrModulus = (uint8_t *)calloc(1, cvc.primeOrModuluslen);
	            ret = mbedtls_mpi_write_binary(&rsa.N, cvc.primeOrModulus, cvc.primeOrModuluslen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
	            
                uint8_t hsh[32];
	            ret = cvc_prepare_signatures(&p15card, &cvc, key_size/8, hsh);
	            if (ret != HSM_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
                ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, random_gen, &index, MBEDTLS_MD_SHA256, 32, hsh, cvc.signature);
                if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
            	            
	            ret = sc_pkcs15emu_sc_hsm_encode_cvc_req(&p15card, &cvc, &cvcbin, &cvclen, false);
	            if (ret != SC_SUCCESS) {
	                if (cvcbin)
	                    free(cvcbin);
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
                memcpy(res_APDU, cvcbin, cvclen);
                free(cvcbin);
	            sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                res_APDU_size = cvclen;
                apdu.expected_res_size = cvclen;
                //sc_asn1_print_tags(cvcbin, cvclen);
                
	            ret = store_keys(&rsa, SC_PKCS15_TYPE_PRKEY_RSA, key_id, ctx);
	            if (ret != HSM_OK) {
                    mbedtls_rsa_free(&rsa);
                    goto error;
                }
	            
                mbedtls_rsa_free(&rsa);
            }
            else if (memcmp(oid, "\x4\x0\x7F\x0\x7\x2\x2\x2\x2\x3",MIN(oid_len,10)) == 0) { //ECC
                size_t prime_len;
                const uint8_t *prime = sc_asn1_find_tag(ctx, p, tout, 0x81, &prime_len);
                mbedtls_ecp_group_id ec_id = MBEDTLS_ECP_DP_NONE;
                for (struct ec_curve_mbed_id *ec = ec_curves_mbed; ec->id != MBEDTLS_ECP_DP_NONE; ec++) {
                    if (prime_len == ec->curve.len && memcmp(prime, ec->curve.value, prime_len) == 0) {
                        ec_id = ec->id;
                        break;
                    }
                }
                if (ec_id == MBEDTLS_ECP_DP_NONE) 
                    return SW_FUNC_NOT_SUPPORTED();
                mbedtls_ecdsa_context ecdsa;
                mbedtls_ecdsa_init(&ecdsa);
                uint8_t index = 0;
                ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, &index);
                if (ret != 0) {
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
                
                uint8_t *cvcbin;
                size_t cvclen;
                sc_cvc_t cvc;
                cvc_init_common(&cvc);
            	struct sc_object_id ecdsaWithSHA256 = { { 0,4,0,127,0,7,2,2,2,2,3,-1 } };
	            cvc.pukoid = ecdsaWithSHA256;
	            
            	cvc.coefficientAorExponentlen = prime_len;//mbedtls_mpi_size(&ecdsa.grp.A);
            	cvc.coefficientAorExponent = calloc(1, cvc.coefficientAorExponentlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.A, cvc.coefficientAorExponent, cvc.coefficientAorExponentlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }

	            cvc.primeOrModuluslen = mbedtls_mpi_size(&ecdsa.grp.P);
	            cvc.primeOrModulus = (uint8_t *)calloc(1, cvc.primeOrModuluslen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.P, cvc.primeOrModulus, cvc.primeOrModuluslen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
	            
	            cvc.coefficientBlen = mbedtls_mpi_size(&ecdsa.grp.B);
	            cvc.coefficientB = (uint8_t *)calloc(1, cvc.coefficientBlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.B, cvc.coefficientB, cvc.coefficientBlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
	            
	            cvc.basePointGlen = mbedtls_mpi_size(&ecdsa.grp.G.X)+mbedtls_mpi_size(&ecdsa.grp.G.Y)+mbedtls_mpi_size(&ecdsa.grp.G.Z);
	            cvc.basePointG = (uint8_t *)calloc(1, cvc.basePointGlen);
	            ret = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &cvc.basePointGlen, cvc.basePointG, cvc.basePointGlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
	            
	            cvc.orderlen = mbedtls_mpi_size(&ecdsa.grp.N);
	            cvc.order = (uint8_t *)calloc(1, cvc.orderlen);
	            ret = mbedtls_mpi_write_binary(&ecdsa.grp.N, cvc.order, cvc.orderlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
	            
	            cvc.publicPointlen = mbedtls_mpi_size(&ecdsa.Q.X)+mbedtls_mpi_size(&ecdsa.Q.Y)+mbedtls_mpi_size(&ecdsa.Q.Z);
	            cvc.publicPoint = (uint8_t *)calloc(1, cvc.publicPointlen);
	            ret = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &cvc.publicPointlen, cvc.publicPoint, cvc.publicPointlen);
	            if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
	            
	            cvc.cofactorlen = 1;
	            cvc.cofactor = (uint8_t *)calloc(1, cvc.cofactorlen);
	            cvc.cofactor[0] = 1;
	            	            
	            cvc.modulusSize = ec_id; //we store the ec_id in the modulusSize, used for RSA, as it is an integer
	            
                uint8_t hsh[32];
	            ret = cvc_prepare_signatures(&p15card, &cvc, ecdsa.grp.pbits*2/8+9, hsh);
	            if (ret != HSM_OK) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
                ret = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hsh, sizeof(hsh), cvc.signature, cvc.signatureLen, &cvc.signatureLen, random_gen, &index);
                if (ret != 0) {
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
            	            
	            ret = sc_pkcs15emu_sc_hsm_encode_cvc_req(&p15card, &cvc, &cvcbin, &cvclen, false);
	            if (ret != SC_SUCCESS) {
	                if (cvcbin)
	                    free(cvcbin);
	                sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
                memcpy(res_APDU, cvcbin, cvclen);
                free(cvcbin);
	            sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                res_APDU_size = cvclen;
                apdu.expected_res_size = cvclen;
                //sc_asn1_print_tags(cvcbin, cvclen);
                
	            ret = store_keys(&ecdsa, SC_PKCS15_TYPE_PRKEY_EC, key_id, ctx);
	            if (ret != HSM_OK) {
                    mbedtls_ecdsa_free(&ecdsa);
                    goto error;
                }
                
                mbedtls_ecdsa_free(&ecdsa);
            }
            
        }
    }
    error:
    free(ctx);
    free(p15card.card);
    if (ret != 0)
        return SW_EXEC_ERROR();
    return SW_OK();
}

static int cmd_update_ef() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    uint16_t fid = (p1 << 8) | p2;
    uint8_t *p = apdu.cmd_apdu_data, *data;
    uint16_t offset = 0;
    uint16_t data_len = 0;
    file_t *ef = NULL;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (fid == 0x0)
        ef = currentEF;
    else if (p1 != EE_CERTIFICATE_PREFIX && p1 != PRKD_PREFIX)
        return SW_INCORRECT_P1P2();
        
    if (ef && !authenticate_action(ef, ACL_OP_UPDATE_ERASE))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
        
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        uint8_t tag = *p++;
        uint8_t taglen = *p++;
        if (tag == 0x54) { //ofset tag
            for (int i = 0; i < taglen; i++)
                offset |= (*p++ << (8*(taglen-i-1)));
        }
        else if (tag == 0x53) { //data 
            if (taglen == 0x82) {
                data_len = *p++ << 8;
                data_len |= *p++;
            }
            else if (taglen == 0x81) {
                data_len = *p++;
            }
            else 
                data_len = taglen;
            data = p;
            p += data_len;
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
        else if (fid != 0x0 && !(ef = search_by_fid(fid, NULL, SPECIFY_EF)) && !(ef = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
        if (offset == 0) {
            int r = flash_write_data_to_file(ef, data, data_len);
            if (r != HSM_OK)
                return SW_MEMORY_FAILURE();
        }
        else {
            if (!ef->data)
                return SW_DATA_INVALID();
            uint8_t *data_merge = (uint8_t *)calloc(1, offset+data_len);
            memcpy(data_merge, file_read(ef->data), offset);
            memcpy(data_merge+offset, data, data_len);
            int r = flash_write_data_to_file(ef, data_merge, data_len);
            free(data_merge);
            if (r != HSM_OK)
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
        
    if (apdu.cmd_apdu_data_len == 0) {
        ef = currentEF;
        if (!(ef = search_dynamic_file(ef->fid)))
            return SW_FILE_INVALID();
    }
    else {
        uint16_t fid = (apdu.cmd_apdu_data[0] << 8) | apdu.cmd_apdu_data[1];
        if (!(ef = search_dynamic_file(fid)))
            return SW_FILE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_DELETE_SELF))
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (flash_clear_file(ef) != HSM_OK)
        return SW_EXEC_ERROR();
    if (delete_dynamic_file(ef) != HSM_OK)
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
            uint8_t pin_len = file_read_uint8(file_pin1->data+2);
            uint16_t r = check_pin(file_pin1, apdu.cmd_apdu_data, pin_len);
            if (r != 0x9000)
                return r;
            if (load_dkek() != HSM_OK) //loads the DKEK with old pin
                return SW_EXEC_ERROR();
            //encrypt DKEK with new pin
            hash_multi(apdu.cmd_apdu_data+pin_len, apdu.cmd_apdu_data_len-pin_len, session_pin);
            has_session_pin = true;
            encrypt(session_pin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
            file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
            flash_write_data_to_file(tf, tmp_dkek, sizeof(tmp_dkek));
            release_dkek();
            uint8_t dhash[33];
            dhash[0] = apdu.cmd_apdu_data_len-pin_len;
            double_hash_pin(apdu.cmd_apdu_data+pin_len, apdu.cmd_apdu_data_len-pin_len, dhash+1);
            flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
            low_flash_available();
            return SW_OK();
        }
    }
}

static int cmd_key_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    uint8_t key_size = 32;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (p2 == 0xB2)
        key_size = 32;
    else if (p2 == 0xB1)
        key_size = 24;
    else if (p2 == 0xB0)
        key_size = 16;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
   //at this moment, we do not use the template, as only CBC is supported by the driver (encrypt, decrypt and CMAC)
    const uint8_t *aes_key = random_bytes_get(32);
    file_t *fpk = file_new((KEY_PREFIX << 8) | key_id);
    int r = flash_write_data_to_file(fpk, aes_key, key_size);
    if (r != HSM_OK)
        return SW_MEMORY_FAILURE();
    fpk = file_new((PRKD_PREFIX << 8) | key_id);
    r = flash_write_data_to_file(fpk, NULL, 0);
    if (r != HSM_OK)
        return SW_MEMORY_FAILURE();
    low_flash_available();
    return SW_OK();
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey) {
    int key_size = file_read_uint16(fkey->data);
    if (load_dkek() != HSM_OK)
        return SW_EXEC_ERROR();
    uint8_t *kdata = (uint8_t *)calloc(1,key_size);
    memcpy(kdata, file_read(fkey->data+2), key_size);
    if (decrypt(tmp_dkek+IV_SIZE, tmp_dkek, kdata, key_size) != 0)
        return SW_EXEC_ERROR();
    release_dkek();
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size/2) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_DATA_INVALID();
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata+key_size/2, key_size/2) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_DATA_INVALID();
    }
    free(kdata);
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_EXEC_ERROR();
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_DATA_INVALID();
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_DATA_INVALID();
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return SW_DATA_INVALID();
    }
    return HSM_OK;
}

int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey) {
    int key_size = file_read_uint16(fkey->data);
    if (load_dkek() != HSM_OK)
        return SW_EXEC_ERROR();
    uint8_t *kdata = (uint8_t *)calloc(1,key_size);
    memcpy(kdata, file_read(fkey->data+2), key_size);
    if (decrypt(tmp_dkek+IV_SIZE, tmp_dkek, kdata, key_size) != 0)
        return SW_EXEC_ERROR();
    release_dkek();
    mbedtls_ecp_group_id gid = kdata[0];
    if (mbedtls_ecp_group_load(&ctx->grp, gid) != 0) {
        mbedtls_ecdsa_free(ctx);
        return SW_DATA_INVALID();
    }
    if (mbedtls_mpi_read_binary(&ctx->d, kdata+1, key_size-1) != 0) {
        mbedtls_ecdsa_free(ctx);
        return SW_DATA_INVALID();
    }
    free(kdata);
    return HSM_OK;
}

static int cmd_signature() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    file_t *fkey;
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    if (!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) || !fkey->data) 
        return SW_FILE_NOT_FOUND();
    int key_size = file_read_uint16(fkey->data);
    if (p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_EC_SHA1)
        md = MBEDTLS_MD_SHA1;
    else if (p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS_SHA256 || p2 == ALGO_EC_SHA256)
        md = MBEDTLS_MD_SHA256;
    else if (p2 == ALGO_EC_SHA224)
        md = MBEDTLS_MD_SHA224;
    if (p2 == ALGO_RSA_RAW || p2 == ALGO_RSA_PKCS1 || p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_RSA_PSS_SHA256) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        if (p2 == ALGO_RSA_PSS || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_RSA_PSS_SHA256) {
            mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, md);
        }
        else if (p2 == ALGO_RSA_PKCS1) { //DigestInfo attached
            unsigned int algo;
            if (sc_pkcs1_strip_digest_info_prefix(&algo, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, apdu.cmd_apdu_data, &apdu.cmd_apdu_data_len) != SC_SUCCESS) //gets the MD algo id and strips it off
                return SW_EXEC_ERROR();
            if (algo == SC_ALGORITHM_RSA_HASH_SHA1)
                md = MBEDTLS_MD_SHA1;
            else if (algo == SC_ALGORITHM_RSA_HASH_SHA224)
                md = MBEDTLS_MD_SHA224;
            else if (algo == SC_ALGORITHM_RSA_HASH_SHA256)
                md = MBEDTLS_MD_SHA256;
            else if (algo == SC_ALGORITHM_RSA_HASH_SHA384)
                md = MBEDTLS_MD_SHA384;
            else if (algo == SC_ALGORITHM_RSA_HASH_SHA512)
                md = MBEDTLS_MD_SHA512;
        }
        
        int r;
        r = load_private_key_rsa(&ctx, fkey);
        if (r != HSM_OK)
            return r;
        if (md == MBEDTLS_MD_NONE) {
            if (apdu.cmd_apdu_data_len < key_size) //needs padding
                memset(apdu.cmd_apdu_data+apdu.cmd_apdu_data_len, 0, key_size-apdu.cmd_apdu_data_len);
            r = mbedtls_rsa_private(&ctx, random_gen, NULL, apdu.cmd_apdu_data, res_APDU);
        }
        else {
            r = mbedtls_rsa_pkcs1_sign(&ctx, random_gen, NULL, md, apdu.cmd_apdu_data_len, apdu.cmd_apdu_data, res_APDU);
        }
        if (r != 0) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        res_APDU_size = key_size;
        apdu.expected_res_size = key_size;
        mbedtls_rsa_free(&ctx);
    }
    else if (p2 == ALGO_EC_RAW || p2 == ALGO_EC_SHA1 || p2 == ALGO_EC_SHA224 || p2 == ALGO_EC_SHA256) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        if (p2 == ALGO_EC_RAW) {
            if (apdu.cmd_apdu_data_len == 32)
                md = MBEDTLS_MD_SHA256;
            else if (apdu.cmd_apdu_data_len == 20)
                md = MBEDTLS_MD_SHA1;
            else if (apdu.cmd_apdu_data_len == 28)
                md = MBEDTLS_MD_SHA224;
            else if (apdu.cmd_apdu_data_len == 48)
                md = MBEDTLS_MD_SHA384;
            else if (apdu.cmd_apdu_data_len == 64)
                md = MBEDTLS_MD_SHA512;
        }
        int r;
        r = load_private_key_ecdsa(&ctx, fkey);
        if (r != HSM_OK)
            return r;
        size_t olen = 0;
        if (mbedtls_ecdsa_write_signature(&ctx, md, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, res_APDU, MBEDTLS_ECDSA_MAX_LEN, &olen, random_gen, NULL) != 0) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        
        res_APDU_size = olen;
        mbedtls_ecdsa_free(&ctx);
    }
    else
        return SW_INCORRECT_P1P2();
    return SW_OK();
}

static int cmd_key_wrap() {
    int key_id = P1(apdu);
    if (P2(apdu) != 0x92)
        return SW_WRONG_P1P2();
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef)
        return SW_FILE_NOT_FOUND();
    int key_len = file_read_uint16(ef->data);
    memcpy(res_APDU, file_read(ef->data+2), key_len);
    res_APDU_size = key_len;
    return SW_OK();
}

static int cmd_key_unwrap() {
    int key_id = P1(apdu);
    if (P2(apdu) != 0x93)
        return SW_WRONG_P1P2();
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef)
        ef = file_new((KEY_PREFIX << 8) | key_id);
    flash_write_data_to_file(ef, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
    low_flash_available();
    return SW_OK();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

#define INS_VERIFY                  0x20
#define INS_CHANGE_PIN              0x24
#define INS_RESET_RETRY             0x2C
#define INS_KEYPAIR_GEN             0x46
#define INS_KEY_GEN                 0x48
#define INS_INITIALIZE              0x50
#define INS_IMPORT_DKEK             0x52
#define INS_LIST_KEYS               0x58
#define INS_SIGNATURE               0x68
#define INS_WRAP                    0x72
#define INS_UNWRAP                  0x74
#define INS_CHALLENGE               0x84
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
    { INS_IMPORT_DKEK, cmd_import_dkek },
    { INS_KEYPAIR_GEN, cmd_keypair_gen },
    { INS_UPDATE_EF, cmd_update_ef },
    { INS_DELETE_FILE, cmd_delete_file },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_KEY_GEN, cmd_key_gen },
    { INS_SIGNATURE, cmd_signature },
    { INS_WRAP, cmd_key_wrap },
    { INS_UNWRAP, cmd_key_unwrap },
    { 0x00, 0x0}
};

int sc_hsm_process_apdu() {
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu))
            return cmd->cmd_handler();
    }
    return SW_INS_NOT_SUPPORTED();
}