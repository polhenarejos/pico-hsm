#include "file.h"
#include "gnuk.h"
#include "tusb.h"
#include "hsm2040.h"
#include "sc_hsm.h"
#include "libopensc/card-sc-hsm.h"
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
extern uint8_t flash_read_uint8(uintptr_t addr);
extern uint8_t *flash_read(uintptr_t addr);
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

const uint8_t cvca[] = {
    0x6A, 0x01,
    0x7f, 0x21, 0x82, 0x01, 0x65, 0x7f, 0x4e, 0x82, 0x01, 0x2d, 0x5f, 
	0x29, 0x01, 0x00, 0x42, 0x0e, 0x45, 0x53, 0x48, 0x53, 0x4d, 0x43, 
	0x56, 0x43, 0x41, 0x32, 0x30, 0x34, 0x30, 0x31, 0x7f, 0x49, 0x81, 
	0xdd, 0x06, 0x0a, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x02, 
	0x02, 0x03, 0x81, 0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x82, 0x18, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x83, 
	0x18, 0x64, 0x21, 0x05, 0x19, 0xe5, 0x9c, 0x80, 0xe7, 0x0f, 0xa7, 
	0xe9, 0xab, 0x72, 0x24, 0x30, 0x49, 0xfe, 0xb8, 0xde, 0xec, 0xc1, 
	0x46, 0xb9, 0xb1, 0x84, 0x31, 0x04, 0x18, 0x8d, 0xa8, 0x0e, 0xb0, 
	0x30, 0x90, 0xf6, 0x7c, 0xbf, 0x20, 0xeb, 0x43, 0xa1, 0x88, 0x00, 
	0xf4, 0xff, 0x0a, 0xfd, 0x82, 0xff, 0x10, 0x12, 0x07, 0x19, 0x2b, 
	0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed, 0x6b, 0x24, 
	0xcd, 0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11, 0x85, 
	0x18, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0x99, 0xde, 0xf8, 0x36, 0x14, 0x6b, 0xc9, 0xb1, 0xb4, 
	0xd2, 0x28, 0x31, 0x86, 0x31, 0x04, 0x4d, 0x28, 0x34, 0x67, 0xb5, 
	0x43, 0xfd, 0x84, 0x22, 0x09, 0xbd, 0xd2, 0xd6, 0x26, 0x27, 0x2d, 
	0x53, 0xa7, 0xdf, 0x52, 0x8f, 0xc2, 0xde, 0x7c, 0x9a, 0xcd, 0x1f, 
	0xf2, 0x10, 0x42, 0x7c, 0x13, 0x44, 0x03, 0xb0, 0xa5, 0xdf, 0x8a, 
	0xd4, 0x59, 0xd1, 0x86, 0x4b, 0xde, 0x33, 0xb1, 0x60, 0x17, 0x87, 
	0x01, 0x01, 0x5f, 0x20, 0x0e, 0x45, 0x53, 0x48, 0x53, 0x4d, 0x43, 
	0x56, 0x43, 0x41, 0x32, 0x30, 0x34, 0x30, 0x31, 0x7f, 0x4c, 0x12, 
	0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02, 
	0x53, 0x05, 0xc0, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x25, 0x06, 0x02, 
	0x02, 0x00, 0x02, 0x01, 0x09, 0x5f, 0x24, 0x06, 0x03, 0x00, 0x01, 
	0x02, 0x03, 0x01, 0x5f, 0x37, 0x30, 0x26, 0x2d, 0x6f, 0xa6, 0xd0, 
	0x52, 0x01, 0xf1, 0x41, 0x1e, 0xe9, 0x33, 0x29, 0x19, 0x42, 0x42, 
	0x9b, 0xb0, 0xeb, 0xf7, 0x46, 0x20, 0xcb, 0x81, 0xfe, 0xda, 0xd7, 
	0xab, 0x2b, 0xdc, 0xa7, 0x38, 0xf4, 0xc8, 0xec, 0x4c, 0x66, 0xb4, 
	0x0a, 0x2d, 0x16, 0xfb, 0xf3, 0x79, 0xe9, 0x93, 0xc8, 0x25 
};
const uint8_t token_info[] = {
    0x28, 0x00, //litle endian
    0x30, 0x26, 0x2, 0x1, 0x1, 0x4, 0x4, 0xd, 0x0, 0x0, 0x0, 0xc, 0xd, 0x50, 0x6f, 0x6c, 0x20, 0x48, 0x65, 0x6e, 0x61, 0x72, 0x65, 0x6a, 0x6f, 0x73, 0x80, 0x8, 0x48, 0x53, 0x4d, 0x20, 0x32, 0x30, 0x34, 0x30, 0x3, 0x2, 0x4, 0xf0
};

extern const uint8_t sc_hsm_aid[];

file_t file_entries[] = {
    /*  0 */ { .fid = 0x3f00    , .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, // MF
    /*  1 */ { .fid = 0x2f00    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DIR
    /*  2 */ { .fid = 0x2f01    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ATR
    /*  3 */ { .fid = 0x2f02    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = (uint8_t *)cvca, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.GDO
    /*  4 */ { .fid = 0x2f03    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF,.data = (uint8_t *)token_info, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  5 */ { .fid = 0x5015    , .parent = 0, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, //DF.PKCS15
    /*  6 */ { .fid = 0x5031    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ODF
    /*  7 */ { .fid = 0x5032    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  8 */ { .fid = 0x5033    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.UnusedSpace
    /*  9 */ { .fid = 0x1081    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (PIN1)
    /* 10 */ { .fid = 0x1082    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (PIN1)
    /* 11 */ { .fid = 0x1083    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (PIN1)
    /* 12 */ { .fid = 0x1088    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (SOPIN)
    /* 13 */ { .fid = 0x1089    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (SOPIN)
    /* 14 */ { .fid = 0x108A    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (SOPIN)
    /* 15 */ { .fid = EF_DKEK   , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //DKEK
    /* 16 */ { .fid = EF_PRKDFS , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PrKDFs
    /* 17 */ { .fid = EF_PUKDFS , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PuKDFs
    /* 18 */ { .fid = EF_CDFS   , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.CDFs
    /* 19 */ { .fid = EF_AODFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.AODFs
    /* 20 */ { .fid = EF_DODFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DODFs
    /* 21 */ { .fid = EF_SKDFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.SKDFs
    ///* 22 */ { .fid = 0x0000, .parent = 0, .name = openpgpcard_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    /* 23 */ { .fid = 0x0000, .parent = 5, .name = sc_hsm_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    /* 24 */ { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL, .ef_structure = 0, .acl = {0} } //end
};

const file_t *MF = &file_entries[0];
const file_t *file_last = &file_entries[sizeof(file_entries)/sizeof(file_t)-1];
const file_t *file_openpgp = &file_entries[sizeof(file_entries)/sizeof(file_t)-3];
const file_t *file_sc_hsm = &file_entries[sizeof(file_entries)/sizeof(file_t)-2];
file_t *file_pin1 = NULL;
file_t *file_retries_pin1 = NULL;
file_t *file_sopin = NULL;
file_t *file_retries_sopin = NULL;

file_chain_t *ef_prkdf = NULL;
file_chain_t *ef_pukdf = NULL;
file_chain_t *ef_cdf = NULL;

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
        if (pathlen == depth && memcmp(path, pe_path, depth) == 0)
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
            if ((fid & 0xff00) == (KEY_PREFIX << 8)) {
                file = file_new(fid);
                add_file_to_chain(file, &ef_prkdf);
            }
            else {
                TU_LOG1("SCAN FOUND ORPHAN FILE: %x\r\n",fid);
                continue;
            }
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
            const uint8_t empty[32] = { 0 };
            flash_write_data_to_file(file_pin1, empty, sizeof(empty));
        }
    }
    else {
        TU_LOG1("FATAL ERROR: PIN1 not found in memory!\r\n");
    }
    file_sopin = search_by_fid(0x1088, NULL, SPECIFY_EF);
    if (file_sopin) {
        if (!file_sopin->data) {
            TU_LOG1("SOPIN is empty. Initializing with default password\r\n");
            const uint8_t empty[32] = { 0 };
            flash_write_data_to_file(file_sopin, empty, sizeof(empty));
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
    file_retries_sopin = search_by_fid(0x108A, NULL, SPECIFY_EF);
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

uint8_t *file_read(const uint8_t *addr) {
    return flash_read((uintptr_t)addr);
}
uint16_t file_read_uint16(const uint8_t *addr) {
    return flash_read_uint16((uintptr_t)addr);
}
uint8_t file_read_uint8(const uint8_t *addr) {
    return flash_read_uint8((uintptr_t)addr);
}

file_t *file_new(uint16_t fid) {
    file_t *f = (file_t *)malloc(sizeof(file_t));
    file_t file = {
        .fid = fid,
        .parent = 5,
        .name = NULL,
        .type = FILE_TYPE_WORKING_EF,
        .ef_structure = FILE_EF_TRANSPARENT,
        .data = NULL,
        .acl = {0}
    };
    memcpy(f, &file, sizeof(file_t));
    memset((uint8_t *)f->acl, 0x90, sizeof(f->acl));
    return f;
}

file_chain_t *add_file_to_chain(file_t *file, file_chain_t **chain) {
    file_chain_t *f_chain = (file_chain_t *)malloc(sizeof(file_chain_t));
    f_chain->file = file;
    f_chain->next = *chain;
    *chain = f_chain;
    return f_chain;
}