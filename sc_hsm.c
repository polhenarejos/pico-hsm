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
    mbedtls_aes_setkey_enc (&aes, key, 256);
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, len, &iv_offset, tmp_iv, data, data);
}

static int decrypt(const uint8_t *key, const uint8_t *iv, uint8_t *data, int len)
{
    mbedtls_aes_context aes;
    uint8_t tmp_iv[IV_SIZE];
    size_t iv_offset = 0;
    memcpy(tmp_iv, iv, IV_SIZE);
    mbedtls_aes_setkey_enc (&aes, key, 256);
    return mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, len, &iv_offset, tmp_iv, data, data);
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
    if (currentEF == file_openpgp || currentEF == file_sc_hsm)
        selected_applet = currentEF;
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
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        process_fci(pe);
    }
    else
        return SW_INCORRECT_P1P2();
    select_file(pe);
    return SW_OK ();
}


static int cmd_list_keys()
{
    static uint16_t r[] = { KEY_PREFIX | 0x100, KEY_PREFIX | 0x200, DCOD_PREFIX | 0x100, CD_PREFIX | 0x300 };
    res_APDU = (uint8_t *)r;
    res_APDU_size = sizeof(r);
    return SW_OK();
}

static int cmd_read_binary()
{
    uint16_t fid;
    uint32_t offset;
    uint8_t ins = INS(apdu), p1 = P1(apdu), p2 = P2(apdu);
    const file_t *ef = NULL;
    
    DEBUG_INFO (" - Read binary\r\n");
    
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
            uint16_t file_id = make_uint16_t(p1, p2) & 0x7fff;
            if (file_id == 0x0)
                ef = currentEF;
            else if (!(ef = search_by_fid(file_id, NULL, SPECIFY_EF)))
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
        uint16_t data_len = file_read_uint16(ef->data);
        if (offset > data_len)
            return SW_WRONG_P1P2();
        
        uint16_t maxle = data_len-offset;
        if (apdu.expected_res_size > maxle)
            apdu.expected_res_size = maxle;
        res_APDU = file_read(ef->data+2+offset);
        res_APDU_size = data_len-offset;
    }

    return SW_OK();
}

int pin_reset_retries(const file_t *pin) {
    if (!pin)
        return HSM_ERR_NULL_PARAM; 
    const file_t *max = search_by_fid(pin->fid+1, NULL, SPECIFY_EF);
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!max || !act)
        return HSM_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(max->data+2);
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
    uint8_t dhash[32];
    double_hash_pin(data, len, dhash);
    if (sizeof(dhash) != file_read_uint16(pin->data))
        return SW_CONDITIONS_NOT_SATISFIED();
    if (memcmp(file_read(pin->data+2), dhash, sizeof(dhash)) != 0) {
        if (pin_wrong_retry(pin) != HSM_OK)
            return SW_PIN_BLOCKED();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    int r = pin_reset_retries(pin);
    if (r != HSM_OK)
        return SW_MEMORY_FAILURE();
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
            flash_write_data_to_file(file_pin1, apdu.cmd_apdu_data+8, apdu.cmd_apdu_data_len-8);
            if (pin_reset_retries(file_pin1) != HSM_OK)
                return SW_MEMORY_FAILURE();
            low_flash_available();
            return SW_OK();
        }
    }
}

static int cmd_challenge() {
    memcpy(res_APDU, random_bytes_get(), apdu.expected_res_size);
    res_APDU_size = apdu.expected_res_size;
    return SW_OK();
}

static int cmd_initialize() {
    const uint8_t *p = apdu.cmd_apdu_data;
    while (p-apdu.cmd_apdu_data < apdu.cmd_apdu_data_len) {
        uint8_t tag = *p++;
        uint8_t tag_len = *p++;
        if (tag == 0x80) { //options
        }
        else if (tag == 0x81) { //user pin
            if (file_pin1 && file_pin1->data) {
                uint8_t dhash[32];
                double_hash_pin(p, tag_len, dhash);
                flash_write_data_to_file(file_pin1, dhash, sizeof(dhash));
                hash(p, tag_len, session_pin);
                has_session_pin = true;
            } 
        }
        else if (tag == 0x82) { //user pin
            if (file_sopin && file_sopin->data) {
                uint8_t dhash[32];
                double_hash_pin(p, tag_len, dhash);
                flash_write_data_to_file(file_sopin, dhash, sizeof(dhash));
                hash(p, tag_len, session_sopin);
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
    p = random_bytes_get();
    memset(tmp_dkek, 0, sizeof(tmp_dkek));
    memcpy(tmp_dkek, p, IV_SIZE);
    if (dkeks == 0) {
        p = random_bytes_get();
        memcpy(tmp_dkek, p, 32);
        encrypt(session_sopin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
        file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
        flash_write_data_to_file(tf, tmp_dkek, sizeof(tmp_dkek));
    }
    return SW_OK();
}

void double_hash_pin(const uint8_t *pin, size_t len, uint8_t output[32]) {
    uint8_t o1[32];
    hash(pin, len, o1);
    for (int i = 0; i < sizeof(o1); i++)
        o1[i] ^= pin[i%len];
    hash(o1, sizeof(o1), output);
}

void hash(const uint8_t *input, size_t len, uint8_t output[32])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int iters = 256;
    
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

static int cmd_import_dkek() {
    if (dkeks == 0)
        return SW_COMMAND_NOT_ALLOWED();
    if (has_session_sopin == false)
        return SW_CONDITIONS_NOT_SATISFIED();
    file_t *tf = search_by_fid(EF_DKEK, NULL, SPECIFY_EF);
    if (apdu.cmd_apdu_data_len > 0) {
        for (int i = 0; i < apdu.cmd_apdu_data_len; i++)
            tmp_dkek[IV_SIZE+i] ^= apdu.cmd_apdu_data[i];
        if (++current_dkeks == dkeks) {
            encrypt(session_sopin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
            flash_write_data_to_file(tf, tmp_dkek, sizeof(tmp_dkek));
            memset(tmp_dkek, 0, sizeof(tmp_dkek));
        }
    }
    res_APDU[0] = dkeks;
    res_APDU[1] = dkeks-current_dkeks;
    //FNV hash
    uint64_t hash = 0xcbf29ce484222325;
    memcpy(tmp_dkek, file_read(tf->data+sizeof(uint16_t)), IV_SIZE+32);
    decrypt(session_sopin, tmp_dkek, tmp_dkek+IV_SIZE, 32);
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
int store_key_rsa(mbedtls_rsa_context *rsa, int key_bits, uint8_t key_id) /*in bits*/ {
    int key_size = key_bits/8;
    uint8_t *pq = (uint8_t *)malloc(key_size);
    mbedtls_mpi_write_binary(&rsa->P, pq, key_size/2);
    mbedtls_mpi_write_binary(&rsa->Q, pq+key_size/2, key_size/2);
    file_t *fpk = file_new((KEY_PREFIX << 8) | key_id);
    int r = flash_write_data_to_file(fpk, pq, key_size);
    if (r != HSM_OK)
        return r;
    add_file_to_chain(fpk, &ef_prkdf);
}

sc_context_t *create_context() {
    sc_context_t *ctx;
    sc_context_param_t ctx_opts;
    memset(&ctx_opts, 0, sizeof(sc_context_param_t));
    sc_context_create(&ctx, &ctx_opts);
    ctx->debug = 9;
    ctx->debug_file = stdout;
    return ctx;
}

static int cmd_keypair_gen() {
    uint8_t key_id = P1(apdu);
    uint8_t auth_key_id = P2(apdu);
    sc_context_t *ctx = create_context();
    
    size_t tout = 0;
    sc_asn1_print_tags(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
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
                if (ex) {
                    sc_asn1_decode_integer(ex, ex_len, &exponent, 0);
                }
                if (ks) {
                    sc_asn1_decode_integer(ks, ks_len, &key_size, 0);
                }
                printf("exponent %d, key_size %d\r\n",exponent,key_size);
                mbedtls_rsa_context rsa;
                mbedtls_rsa_init(&rsa);
                uint8_t index = 0;
                int ret = mbedtls_rsa_gen_key(&rsa, random_gen, &index, key_size, exponent);
                printf("ret %d\r\n",ret);
                sc_cvc_t cvc;
                memset(&cvc, 0, sizeof(cvc));

            	strlcpy(cvc.car, "UTCA00001", sizeof cvc.car);
            	strlcpy(cvc.chr, "ESHSMCVCA", sizeof cvc.chr);
            	strlcat(cvc.chr, "00001", sizeof cvc.chr);
            	struct sc_object_id rsa15withSHA256 = { { 0,4,0,127,0,7,2,2,2,1,2,-1 } };
            	cvc.coefficientAorExponentlen = ex_len;
            	cvc.coefficientAorExponent = malloc(ex_len);
	            memcpy(cvc.coefficientAorExponent, &exponent, ex_len);

	            cvc.pukoid = rsa15withSHA256;
	            cvc.modulusSize = key_size;
	            cvc.primeOrModuluslen = key_size/8;
	            cvc.primeOrModulus = (uint8_t *)malloc(cvc.primeOrModuluslen);
	            mbedtls_mpi_write_binary(&rsa.N, cvc.primeOrModulus, key_size/8);
	            cvc.signatureLen = key_size/8;
	            cvc.signature = (uint8_t *)malloc(key_size/8);
	            ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, NULL, NULL, MBEDTLS_MD_NONE, offsetof(sc_cvc_t, signature), (uint8_t *)&cvc, cvc.signature);
	            printf("ret %d\r\n");
	            u8 *cvcbin;
	            size_t cvclen;
	            struct sc_pkcs15_card p15card;
	            p15card.card = (sc_card_t *)malloc(sizeof(sc_card_t));
	            p15card.card->ctx = ctx;
	            int r = sc_pkcs15emu_sc_hsm_encode_cvc(&p15card, &cvc, &cvcbin, &cvclen);
	            printf("r %d\r\n",r);
	            sc_pkcs15emu_sc_hsm_free_cvc(&cvc);
                mbedtls_rsa_free(&rsa);
                free(p15card.card);
                memcpy(res_APDU, cvcbin, cvclen);
                res_APDU_size = cvclen;
                apdu.expected_res_size = cvclen;
                free(cvcbin);
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
                int ret = mbedtls_ecdsa_genkey(&ecdsa, ec_id, random_gen, &index);
                printf("ret %d\r\n",ret) ;
                mbedtls_ecdsa_free(&ecdsa);
            }
            
        }
    }
    sc_release_context(ctx);
    return SW_OK();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

#define INS_SELECT_FILE				0xA4
#define INS_READ_BINARY				0xB0
#define INS_READ_BINARY_ODD         0xB1
#define INS_VERIFY                  0x20
#define INS_RESET_RETRY             0x2C
#define INS_INITIALIZE              0x50
#define INS_IMPORT_DKEK             0x52
#define INS_CHALLENGE               0x84
#define INS_LIST_KEYS               0x58
#define INS_KEYPAIR_GEN             0x46

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
    { 0x00, 0x0}
};

int sc_hsm_process_apdu() {
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu))
            return cmd->cmd_handler();
    }
    return SW_INS_NOT_SUPPORTED();
}