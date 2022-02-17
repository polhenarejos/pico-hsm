#include "sc_hsm.h"
#include "file.h"
#include "libopensc/card-sc-hsm.h"
#include "random.h"

const uint8_t sc_hsm_aid[] = {
    11, 
    0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01
};

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
}

static int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    
    if (p1 != 0x0 || (p2 & 0x60) != 0x0)
        return SW_WRONG_P1P2();
    uint8_t qualifier = p2&0x1f;
    if (p2 == 0x81) { //UserPin
        if (!file_retries_pin1) {
            return SW_REFERENCE_NOT_FOUND();
        }
        return set_res_sw (0x63, 0xc0 | file_read_uint8(file_retries_pin1->data+2));
    }
    else if (p2 == 0x88) { //SOPin
    }
    return SW_REFERENCE_NOT_FOUND();
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
    if (len != file_read_uint16(pin->data))
        return SW_CONDITIONS_NOT_SATISFIED();
    if (memcmp(file_read(pin->data+2), data, len) != 0) {
        if (pin_wrong_retry(pin) != HSM_OK)
            return SW_PIN_BLOCKED();
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    return pin_reset_retries(pin);
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
#define INS_CHALLENGE               0x84

static const cmd_t cmds[] = {
    { INS_SELECT_FILE, cmd_select },
    { 0x58, cmd_list_keys }, 
    { INS_READ_BINARY, cmd_read_binary },
    { INS_READ_BINARY_ODD, cmd_read_binary },
    { INS_VERIFY, cmd_verify },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_CHALLENGE, cmd_challenge },
    { 0x00, 0x0}
};

int sc_hsm_process_apdu() {
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu))
            return cmd->cmd_handler();
    }
    return SW_INS_NOT_SUPPORTED();
}