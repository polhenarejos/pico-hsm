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

#include "files.h"

extern const uint8_t sc_hsm_aid[];
extern int parse_token_info(const file_t *f, int mode);
extern int parse_cvca(const file_t *f, int mode);

file_t file_entries[] = {
    /*  0 */ { .fid = 0x3f00    , .parent = 0xff, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, // MF
    /*  1 */ { .fid = 0x2f00    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DIR
    /*  2 */ { .fid = 0x2f01    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ATR
    /*  3 */ { .fid = 0x2f02    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF | FILE_DATA_FUNC,.data = (uint8_t *)parse_cvca, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.GDO
    /*  4 */ { .fid = 0x2f03    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF | FILE_DATA_FUNC,.data = (uint8_t *)parse_token_info, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  5 */ { .fid = 0x5015    , .parent = 0, .name = NULL, .type = FILE_TYPE_DF, .data = NULL, .ef_structure = 0, .acl = {0} }, //DF.PKCS15
    /*  6 */ { .fid = 0x5031    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.ODF
    /*  7 */ { .fid = 0x5032    , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.TokenInfo
    /*  8 */ { .fid = 0x5033    , .parent = 0, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.UnusedSpace
    /*  9 */ { .fid = 0x1081    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (PIN1)
    /* 10 */ { .fid = 0x1082    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (PIN1)
    /* 11 */ { .fid = 0x1083    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (PIN1)
    /* 12 */ { .fid = 0x1088    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //PIN (SOPIN)
    /* 13 */ { .fid = 0x1089    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //max retries PIN (SOPIN)
    /* 14 */ { .fid = 0x108A    , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //retries PIN (SOPIN)
    /* 15 */ { .fid = EF_DEVOPS , .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //Device options
    /* 16 */ { .fid = EF_PRKDFS , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PrKDFs
    /* 17 */ { .fid = EF_PUKDFS , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.PuKDFs
    /* 18 */ { .fid = EF_CDFS   , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.CDFs
    /* 19 */ { .fid = EF_AODFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.AODFs
    /* 20 */ { .fid = EF_DODFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.DODFs
    /* 21 */ { .fid = EF_SKDFS  , .parent = 5, .name = NULL, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} }, //EF.SKDFs
    /* 15 */ { .fid = EF_KEY_DOMAIN, .parent = 5, .name = NULL, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0xff} }, //Key domain options
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