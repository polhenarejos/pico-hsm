#include "file.h"
#include "gnuk.h"
#include "tusb.h"
#include "hsm2040.h"
#include "sc_hsm.h"
#include <string.h>

extern const uintptr_t end_data_pool;
extern const uintptr_t start_data_pool;
extern int flash_write_data_to_file(file_t *file, const uint8_t *data, uint16_t len);
extern int flash_program_halfword (uintptr_t addr, uint16_t data);
extern int flash_program_word (uintptr_t addr, uint32_t data);
extern int flash_program_uintptr (uintptr_t addr, uintptr_t data);
extern int flash_program_block(uintptr_t addr, const uint8_t *data, size_t len);
extern uintptr_t flash_read_uintptr(uintptr_t addr);
extern uint16_t flash_read_uint16(uintptr_t addr);
extern void low_flash_available();

//puts FCI in the RAPDU
void process_fci(const file_t *pe) {
    uint8_t *p = res_APDU;
    uint8_t buf[64];
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0x6f;
    res_APDU[res_APDU_size++] = 0x00; //computed later
    
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 2;
    if (pe->data)
        memcpy(res_APDU+res_APDU_size, pe->data, 2);
    else
        memset(res_APDU+res_APDU_size, 0, 2);
    res_APDU_size += 2;
    
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size] = 0;
    if (pe->type == FILE_TYPE_INTERNAL_EF)
        res_APDU[res_APDU_size++] |= 0x08;
    else if (pe->type == FILE_TYPE_WORKING_EF)
        res_APDU[res_APDU_size++] |= pe->ef_structure & 0x7;
    else if (pe->type == FILE_TYPE_DF)
        res_APDU[res_APDU_size++] |= 0x38;
    
    res_APDU[res_APDU_size++] = 0x83;
    res_APDU[res_APDU_size++] = 2;
    put_uint16_t(pe->fid, res_APDU+res_APDU_size);
    res_APDU_size += 2;
    res_APDU[1] = res_APDU_size-2;
}

const uint8_t t[] = {
    0x01,0xbb,
    0x7F,0x21,0x82,0x01,0xB6,0x7F,0x4E,0x82,0x01,0x6E,0x5F,0x29,0x01,0x00,0x42,0x0E,0x44,0x45,0x43,0x56,0x43,0x41,0x65,0x49,0x44,0x30,0x30,0x31,0x30,0x32,0x7F,0x49,0x82,0x01,0x1D,0x06,0x0A,0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x02,0x02,0x03,0x81,0x20,0xA9,0xFB,0x57,0xDB,0xA1,0xEE,0xA9,0xBC,0x3E,0x66,0x0A,0x90,0x9D,0x83,0x8D,0x72,0x6E,0x3B,0xF6,0x23,0xD5,0x26,0x20,0x28,0x20,0x13,0x48,0x1D,0x1F,0x6E,0x53,0x77,0x82,0x20,0x7D,0x5A,0x09,0x75,0xFC,0x2C,0x30,0x57,0xEE,0xF6,0x75,0x30,0x41,0x7A,0xFF,0xE7,0xFB,0x80,0x55,0xC1,0x26,0xDC,0x5C,0x6C,0xE9,0x4A,0x4B,0x44,0xF3,0x30,0xB5,0xD9,0x83,0x20,0x26,0xDC,0x5C,0x6C,0xE9,0x4A,0x4B,0x44,0xF3,0x30,0xB5,0xD9,0xBB,0xD7,0x7C,0xBF,0x95,0x84,0x16,0x29,0x5C,0xF7,0xE1,0xCE,0x6B,0xCC,0xDC,0x18,0xFF,0x8C,0x07,0xB6,0x84,0x41,0x04,0x8B,0xD2,0xAE,0xB9,0xCB,0x7E,0x57,0xCB,0x2C,0x4B,0x48,0x2F,0xFC,0x81,0xB7,0xAF,0xB9,0xDE,0x27,0xE1,0xE3,0xBD,0x23,0xC2,0x3A,0x44,0x53,0xBD,0x9A,0xCE,0x32,0x62,0x54,0x7E,0xF8,0x35,0xC3,0xDA,0xC4,0xFD,0x97,0xF8,0x46,0x1A,0x14,0x61,0x1D,0xC9,0xC2,0x77,0x45,0x13,0x2D,0xED,0x8E,0x54,0x5C,0x1D,0x54,0xC7,0x2F,0x04,0x69,0x97,0x85,0x20,0xA9,0xFB,0x57,0xDB,0xA1,0xEE,0xA9,0xBC,0x3E,0x66,0x0A,0x90,0x9D,0x83,0x8D,0x71,0x8C,0x39,0x7A,0xA3,0xB5,0x61,0xA6,0xF7,0x90,0x1E,0x0E,0x82,0x97,0x48,0x56,0xA7,0x86,0x41,0x04,0x33,0x47,0xEC,0xF9,0x6F,0xFB,0x4B,0xD9,0xB8,0x55,0x4E,0xFB,0xCC,0xFC,0x7D,0x0B,0x24,0x2F,0x10,0x71,0xE2,0x9B,0x4C,0x9C,0x62,0x2C,0x79,0xE3,0x39,0xD8,0x40,0xAF,0x67,0xBE,0xB9,0xB9,0x12,0x69,0x22,0x65,0xD9,0xC1,0x6C,0x62,0x57,0x3F,0x45,0x79,0xFF,0xD4,0xDE,0x2D,0xE9,0x2B,0xAB,0x40,0x9D,0xD5,0xC5,0xD4,0x82,0x44,0xA9,0xF7,0x87,0x01,0x01,0x5F,0x20,0x0E,0x44,0x45,0x43,0x56,0x43,0x41,0x65,0x49,0x44,0x30,0x30,0x31,0x30,0x32,0x7F,0x4C,0x12,0x06,0x09,0x04,0x00,0x7F,0x00,0x07,0x03,0x01,0x02,0x02,0x53,0x05,0xFE,0x0F,0x01,0xFF,0xFF,0x5F,0x25,0x06,0x01,0x00,0x01,0x00,0x01,0x08,0x5F,0x24,0x06,0x01,0x03,0x01,0x00,0x01,0x08,0x5F,0x37,0x40,0x50,0x67,0x14,0x5C,0x68,0xCA,0xE9,0x52,0x0F,0x5B,0xB3,0x48,0x17,0xF1,0xCA,0x9C,0x43,0x59,0x3D,0xB5,0x64,0x06,0xC6,0xA3,0xB0,0x06,0xCB,0xF3,0xF3,0x14,0xE7,0x34,0x9A,0xCF,0x0C,0xC6,0xBF,0xEB,0xCB,0xDE,0xFD,0x10,0xB4,0xDC,0xF0,0xF2,0x31,0xDA,0x56,0x97,0x7D,0x88,0xF9,0xF9,0x01,0x82,0xD1,0x99,0x07,0x6A,0x56,0x50,0x64,0x51
};
const uint8_t token_info[] = {
    0x0, 0x28, 
    0x30, 0x26, 0x2, 0x1, 0x1, 0x4, 0x4, 0xd, 0x0, 0x0, 0x0, 0xc, 0xd, 0x50, 0x6f, 0x6c, 0x20, 0x48, 0x65, 0x6e, 0x61, 0x72, 0x65, 0x6a, 0x6f, 0x73, 0x80, 0x8, 0x48, 0x53, 0x4d, 0x20, 0x32, 0x30, 0x34, 0x30, 0x3, 0x2, 0x4, 0xf0
};

extern const uint8_t sc_hsm_aid[];

file_t file_entries[] = {
    /*  0 */ { .fid = 0x3f00, .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, // MF
    /*  1 */ { .fid = 0x2f00, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DIR
    /*  2 */ { .fid = 0x2f01, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ATR
    /*  3 */ { .fid = 0x2f02, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = (uint8_t *)t, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.GDO
    /*  4 */ { .fid = 0x2f03, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = (uint8_t *)token_info, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  5 */ { .fid = 0x5015, .parent = 0, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, //DF.PKCS15
    /*  6 */ { .fid = 0x5031, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ODF
    /*  7 */ { .fid = 0x5032, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  8 */ { .fid = 0x5033, .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.UnusedSpace
    /*  9 */ { .fid = 0x1081, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (PIN1)
    /* 10 */ { .fid = 0x1082, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (PIN1)
    /* 11 */ { .fid = 0x1083, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (PIN1)
    /* 12 */ { .fid = 0x1088, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (SOPIN)
    /* 13 */ { .fid = 0x1089, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (SOPIN)
    /* 14 */ { .fid = 0x1090, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (SOPIN)
    /* 15 */ { .fid = 0x6040, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PrKDFs
    /* 16 */ { .fid = 0x6041, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PuKDFs
    /* 17 */ { .fid = 0x6042, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.CDFs
    /* 18 */ { .fid = 0x6043, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.AODFs
    /* 19 */ { .fid = 0x6044, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DODFs
    /* 20 */ { .fid = 0x6045, .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.SKDFs
    ///* 21 */ { .fid = 0x0000, .parent = 0, .name = openpgpcard_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    /* 22 */ { .fid = 0x0000, .parent = 5, .name = sc_hsm_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    /* 23 */ { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL, .ef_structure = 0, .acl = {0} } //end
};

const file_t *MF = &file_entries[0];
const file_t *file_last = &file_entries[sizeof(file_entries)/sizeof(file_t)-1];
const file_t *file_openpgp = &file_entries[sizeof(file_entries)/sizeof(file_t)-3];
const file_t *file_sc_hsm = &file_entries[sizeof(file_entries)/sizeof(file_t)-2];
file_t *file_pin1 = NULL;
file_t *file_retries_pin1 = NULL;
file_t *file_sopin = NULL;
file_t *file_retries_sopin = NULL;

bool card_terminated = false;

bool is_parent(const file_t *child, const file_t *parent) {
    if (child == parent)
        return true;
    if (child == MF)
        return false;
    return is_parent(&file_entries[child->parent], parent);
}

file_t *search_by_name(uint8_t *name, uint16_t namelen) {
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->name && *p->name == apdu.cmd_apdu_data_len && memcmp(p->name+1, name, namelen) == 0) {
            return p;
        }
    }
    return NULL;
}

file_t *search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    
    for (file_t *p = file_entries; p != file_last; p++) {
        if (p->fid != 0x0000 && p->fid == fid) {
            if (!parent || (parent && is_parent(p, parent))) {
                if (!sp || sp == SPECIFY_ANY || (((sp & SPECIFY_EF) && (p->type & FILE_TYPE_INTERNAL_EF)) || ((sp & SPECIFY_DF) && p->type == FILE_TYPE_DF)))
                    return p;
            }
        }
    }
    return NULL;
}

uint8_t make_path_buf(const file_t *pe, uint8_t *buf, uint8_t buflen, const file_t *top) {
    if (!buflen)
        return 0;
    if (pe == top) //MF or relative DF
        return 0;
    put_uint16_t(pe->fid, buf);
    return make_path_buf(&file_entries[pe->parent], buf+2, buflen-2, top)+2;
}

uint8_t make_path(const file_t *pe, const file_t *top, uint8_t *path) {
    uint8_t buf[MAX_DEPTH*2], *p = path;
    put_uint16_t(pe->fid, buf);
    uint8_t depth = make_path_buf(&file_entries[pe->parent], buf+2, sizeof(buf)-2, top)+2;
    for (int d = depth-2; d >= 0; d -= 2) {
        memcpy(p, buf+d, 2);
        p += 2;
    }
    return depth;
}

file_t *search_by_path(const uint8_t *pe_path, uint8_t pathlen, const file_t *parent) {
    uint8_t path[MAX_DEPTH*2];
    if (pathlen > sizeof(path)) {
        return NULL;
    }
    for (file_t *p = file_entries; p != file_last; p++) {
        uint8_t depth = make_path(p, parent, path);
        if (pathlen == depth && memcmp(path, pe_path, depth))
            return p;
    }
    return NULL;
}

file_t *currentEF = NULL;
file_t *currentDF = NULL;
const file_t *selected_applet = NULL;
bool isUserAuthenticated = false;

bool authenticate_action(const file_t *ef, uint8_t op) {
    uint8_t acl = ef->acl[op];
    if (acl == 0x0)
        return true;
    else if (acl == 0xff)
        return false;
    else if (acl == 0x90 || acl & 0x9F == 0x10) {
            // PIN required.
        if(isUserAuthenticated) {
            return true;
        } 
        else {
            return false;
        }
    }
    return false;
}

#include "libopensc/pkcs15.h"

int reset_pin_retries(const file_t *pin) {
    if (!pin)
        return HSM_ERR_NULL_PARAM; 
    const file_t *max = search_by_fid(pin->fid+1, NULL, SPECIFY_EF);
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!max || !act)
        return HSM_ERR_FILE_NOT_FOUND;
    return flash_write_data_to_file((file_t *)act, &max->data[2], sizeof(uint8_t));
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin)
        return HSM_ERR_NULL_PARAM; 
    const file_t *act = search_by_fid(pin->fid+2, NULL, SPECIFY_EF);
    if (!act)
        return HSM_ERR_FILE_NOT_FOUND;
    if (act->data[2] > 0)
        return flash_write_data_to_file((file_t *)act, &act->data[2]-1, sizeof(uint8_t));
    return HSM_ERR_BLOCKED;
}

void scan_flash() {
    if (*(uintptr_t *)end_data_pool == 0xffffffff && *(uintptr_t *)(end_data_pool+sizeof(uintptr_t)) == 0xffffffff) 
    {
        printf("First initialization (or corrupted!)\r\n");
        const uint8_t empty[8] = { 0 };
        flash_program_block(end_data_pool, empty, sizeof(empty));
        //low_flash_available();
        //wait_flash_finish();
    }
    printf("SCAN\r\n");
    
    sc_context_t *ctx;
    sc_context_param_t ctx_opts;
    memset(&ctx_opts, 0, sizeof(sc_context_param_t));
    sc_thread_context_t sc_thread_ctx = {
    	0, NULL, NULL,
    	NULL, NULL, NULL
    };
	ctx_opts.ver        = 0;
	ctx_opts.app_name   = "opensc-pkcs11";
	ctx_opts.thread_ctx = &sc_thread_ctx;
    int r = sc_context_create(&ctx, &ctx_opts);
    ctx->debug = 9;
	
    
    struct sc_pkcs15_object obj;
    memset(&obj, 0, sizeof(obj));
    obj.type = SC_PKCS15_TYPE_PRKEY_RSA;
    struct sc_pkcs15_prkey_info info;

	/* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.key_reference = 0x2a;
	info.native = 1;
	char id[] = "0309";
	info.id.len = sizeof(id);
	memcpy(info.id.value, id, sizeof(id));
	info.usage = 1;
	info.access_flags = 1;
	obj.data = malloc(sizeof(info));
	if (obj.data == NULL) {
		int r = SC_ERROR_OUT_OF_MEMORY;
			TU_LOG1("Out of memory");

		return ;
	}
	memcpy(obj.data, &info, sizeof(info));

    u8 *buf;
    size_t len;
    r = sc_pkcs15_encode_prkdf_entry(ctx, &obj, &buf, &len);
    printf("r %d, len %d\r\n",r,len);
    DEBUG_PAYLOAD(buf, len);
    uintptr_t base = flash_read_uintptr(end_data_pool);
    for (uintptr_t base = flash_read_uintptr(end_data_pool); base >= start_data_pool; base = flash_read_uintptr(base)) {
        if (base == 0x0) //all is empty
            break;
        
        uint16_t fid = flash_read_uint16(base+sizeof(uintptr_t));
        file_t *file = (file_t *)search_by_fid(fid, NULL, SPECIFY_EF);
        if (!file) {
            TU_LOG1("SCAN FOUND ORPHAN FILE: %x\r\n",fid);
            continue;
        }
        file->data = (uint8_t *)(base+sizeof(uintptr_t)+sizeof(uint16_t));
        if (flash_read_uintptr(base) == 0x0) {
            break;
        }
    }
    file_pin1 = search_by_fid(0x1081, NULL, SPECIFY_EF);
    if (file_pin1) {
        if (!file_pin1->data) {
            TU_LOG1("PIN1 is empty. Initializing with default password\r\n");
            const uint8_t empty[16] = { 0 }, default_pin1[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            flash_write_data_to_file(file_pin1, empty, sizeof(empty));
            flash_write_data_to_file(file_pin1, default_pin1, sizeof(default_pin1));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: PIN1 not found in memory!\r\n");
    }
    file_sopin = search_by_fid(0x1088, NULL, SPECIFY_EF);
    if (file_sopin) {
        if (!file_sopin->data) {
            TU_LOG1("SOPIN is empty. Initializing with default password\r\n");
            const uint8_t empty[8] = { 0 }, default_sopin[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
            flash_write_data_to_file(file_sopin, empty, sizeof(empty));
            flash_write_data_to_file(file_sopin, default_sopin, sizeof(default_sopin));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: SOPIN not found in memory!\r\n");
    }
    file_retries_pin1 = search_by_fid(0x1083, NULL, SPECIFY_EF);
    if (file_retries_pin1) {
        if (!file_retries_pin1->data) {
            TU_LOG1("Retries PIN1 is empty. Initializing with default retriesr\n");
            const uint8_t retries = 3;
            flash_write_data_to_file(file_retries_pin1, &retries, sizeof(uint8_t));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: Retries PIN1 not found in memory!\r\n");
    }
    file_retries_sopin = search_by_fid(0x1090, NULL, SPECIFY_EF);
    if (file_retries_sopin) {
        if (!file_retries_sopin->data) {
            TU_LOG1("Retries SOPIN is empty. Initializing with default retries\r\n");
            const uint8_t retries = 15;
            flash_write_data_to_file(file_retries_sopin, &retries, sizeof(uint8_t));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: Retries SOPIN not found in memory!\r\n");
    }
    file_t *tf = NULL;
    
    tf = search_by_fid(0x1082, NULL, SPECIFY_EF);
    if (tf) {
        if (!tf->data) {
            TU_LOG1("Max retries PIN1 is empty. Initializing with default max retriesr\n");
            const uint8_t retries = 3;
            flash_write_data_to_file(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: Max Retries PIN1 not found in memory!\r\n");
    }
    tf = search_by_fid(0x1089, NULL, SPECIFY_EF);
    if (tf) {
        if (!tf->data) {
            TU_LOG1("Max Retries SOPIN is empty. Initializing with default max retries\r\n");
            const uint8_t retries = 15;
            flash_write_data_to_file(tf, &retries, sizeof(uint8_t));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: Retries SOPIN not found in memory!\r\n");
    }
    low_flash_available();
}
