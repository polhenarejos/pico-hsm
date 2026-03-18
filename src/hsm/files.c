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

#include "files.h"

extern const uint8_t sc_hsm_aid[];
extern int parse_token_info(const file_t *f, int mode);
extern int parse_ef_dir(const file_t *f, int mode);

file_t file_entries[] = {
    /*  0 */ { .fid = 0x3f00, // MF
               .parent = 0xff,
               .name = NULL,
               .type = FILE_TYPE_DF,
               .data = NULL,
               .ef_structure = 0,
               .acl = ACL_ALL },
    /*  1 */ { .fid = 0x2f00, //EF.DIR
               .parent = 0,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF | FILE_DATA_FUNC,
               .data = (uint8_t *) parse_ef_dir,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  2 */ { .fid = 0x2f01, // EF.ATR
               .parent = 0,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  3 */ { .fid = EF_TERMCA, // EF.GDO
               .parent = 0,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  4 */ { .fid = 0x2f03, // EF.TokenInfo
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF | FILE_DATA_FUNC,
               .data = (uint8_t *) parse_token_info,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  5 */ { .fid = 0x5015, // DF.PKCS15
               .parent = 0,
               .name = NULL,
               .type = FILE_TYPE_DF,
               .data = NULL,
               .ef_structure = 0,
               .acl = ACL_ALL },
    /*  6 */ { .fid = 0x5031, // EF.ODF
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  7 */ { .fid = 0x5032, // EF.TokenInfo
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  8 */ { .fid = 0x5033, // EF.UnusedSpace
               .parent = 0,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /*  9 */ { .fid = EF_PIN1, // PIN (PIN1)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 10 */ { .fid = EF_PIN1_MAX_RETRIES, // max retries PIN (PIN1)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 11 */ { .fid = EF_PIN1_RETRIES, // retries PIN (PIN1)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 12 */ { .fid = EF_SOPIN, // PIN (SOPIN)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 13 */ { .fid = EF_SOPIN_MAX_RETRIES, // max retries PIN (SOPIN)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 14 */ { .fid = EF_SOPIN_RETRIES, // retries PIN (SOPIN)
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 15 */ { .fid = EF_DEVOPS, // Device options
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 16 */ { .fid = EF_PRKDFS, // EF.PrKDFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 17 */ { .fid = EF_PUKDFS, // EF.PuKDFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 18 */ { .fid = EF_CDFS, // EF.CDFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 19 */ { .fid = EF_AODFS, // EF.AODFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 20 */ { .fid = EF_DODFS, // EF.DODFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 21 */ { .fid = EF_SKDFS, // EF.SKDFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 22 */ { .fid = EF_KEY_DOMAIN, // Key domain options
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 23 */ { .fid = EF_META, // EF.CDFs
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 24 */ { .fid = EF_PUKAUT, // Public Key Authentication
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 25 */ { .fid = EF_KEY_DEV, // Device Key
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 26 */ { .fid = EF_PRKD_DEV, // PrKD Device
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 27 */ { .fid = EF_EE_DEV, // End Entity Certificate Device
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 28 */ { .fid = EF_MKEK, // MKEK
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 29 */ { .fid = EF_MKEK_SO, // MKEK with SO-PIN
               .parent = 5,
               .name = NULL,
               .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_NONE },
    /* 30 */ { .fid = 0x0000,
               .parent = 5,
               .name = sc_hsm_aid,
               .type = FILE_TYPE_WORKING_EF,
               .data = NULL,
               .ef_structure = FILE_EF_TRANSPARENT,
               .acl = ACL_ALL },
    /* 31 */ { .fid = 0x0000, // end
               .parent = 0xff,
               .name = NULL,
               .type = FILE_TYPE_NOT_KNOWN,
               .data = NULL,
               .ef_structure = 0,
               .acl = { 0 } }
};

const file_t *MF = &file_entries[0];
const file_t *file_last = &file_entries[sizeof(file_entries) / sizeof(file_t) - 1];
const file_t *file_openpgp = &file_entries[sizeof(file_entries) / sizeof(file_t) - 3];
const file_t *file_sc_hsm = &file_entries[sizeof(file_entries) / sizeof(file_t) - 2];
file_t *file_pin1 = NULL;
file_t *file_retries_pin1 = NULL;
file_t *file_sopin = NULL;
file_t *file_retries_sopin = NULL;
