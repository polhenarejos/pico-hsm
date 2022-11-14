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

#ifndef _OID_H_
#define _OID_H_

#include <stdlib.h>
#include "pico/stdlib.h"

#define OID_BSI_DE                      "\x04\x00\x7F\x00\x07"

#define OID_ID_PK                       OID_BSI_DE "\x02\x02\x01"
#define OID_ID_PK_DH                    OID_ID_PK "\x01"
#define OID_ID_PK_ECDH                  OID_ID_PK "\x02"

#define OID_ID_TA                       OID_BSI_DE "\x02\x02\x02"

#define OID_ID_TA_RSA                   OID_ID_TA "\x01"

#define OID_ID_TA_RSA_V1_5_SHA_1        OID_ID_TA_RSA "\x01"
#define OID_ID_TA_RSA_V1_5_SHA_256      OID_ID_TA_RSA "\x02"
#define OID_ID_TA_RSA_PSS_SHA_1         OID_ID_TA_RSA "\x03"
#define OID_ID_TA_RSA_PSS_SHA_256       OID_ID_TA_RSA "\x04"
#define OID_ID_TA_RSA_V1_5_SHA_512      OID_ID_TA_RSA "\x05"
#define OID_ID_TA_RSA_PSS_SHA_512       OID_ID_TA_RSA "\x06"

#define OID_ID_TA_ECDSA                 OID_ID_TA "\x02"

#define OID_ID_TA_ECDSA_SHA_1           OID_ID_TA_ECDSA "\x01"
#define OID_ID_TA_ECDSA_SHA_224         OID_ID_TA_ECDSA "\x02"
#define OID_ID_TA_ECDSA_SHA_256         OID_ID_TA_ECDSA "\x03"
#define OID_ID_TA_ECDSA_SHA_384         OID_ID_TA_ECDSA "\x04"
#define OID_ID_TA_ECDSA_SHA_512         OID_ID_TA_ECDSA "\x05"

#define OID_ID_CA                       OID_BSI_DE "\x02\x02\x03"

#define OID_ID_CA_DH                    OID_ID_CA "\x01"
#define OID_ID_CA_DH_3DES_CBC_CBC       OID_ID_CA_DH "\x01"
#define OID_ID_CA_DH_AES_CBC_CMAC_128   OID_ID_CA_DH "\x02"
#define OID_ID_CA_DH_AES_CBC_CMAC_192   OID_ID_CA_DH "\x03"
#define OID_ID_CA_DH_AES_CBC_CMAC_256   OID_ID_CA_DH "\x04"

#define OID_ID_CA_ECDH                  OID_ID_CA "\x02"
#define OID_ID_CA_ECDH_3DES_CBC_CBC     OID_ID_CA_ECDH "\x01"
#define OID_ID_CA_ECDH_AES_CBC_CMAC_128 OID_ID_CA_ECDH "\x02"
#define OID_ID_CA_ECDH_AES_CBC_CMAC_192 OID_ID_CA_ECDH "\x03"
#define OID_ID_CA_ECDH_AES_CBC_CMAC_256 OID_ID_CA_ECDH "\x04"

#define OID_ID_RI                       OID_BSI_DE "\x02\x02\x05"

#define OID_ID_RI_DH                    OID_ID_RI "\x01"

#define OID_ID_RI_DH_SHA_1              OID_ID_RI_DH "\x01"
#define OID_ID_RI_DH_SHA_224            OID_ID_RI_DH "\x02"
#define OID_ID_RI_DH_SHA_256            OID_ID_RI_DH "\x03"

#define OID_ID_RI_ECDH                  OID_ID_RI "\x02"

#define OID_ID_RI_ECDH_SHA_1            OID_ID_RI_ECDH "\x01"
#define OID_ID_RI_ECDH_SHA_224          OID_ID_RI_ECDH "\x02"
#define OID_ID_RI_ECDH_SHA_256          OID_ID_RI_ECDH "\x03"

#define OID_ID_CI                       OID_BSI_DE "\x02\x02\x06"

#define OID_CARDCONTACT                 "\x2B\x06\x01\x04\x01\x81\xC3\x1F"

#define OID_OPENSCDP                    OID_CARDCONTACT "\x01"
#define OID_CC_ISO7816                  OID_CARDCONTACT "\x02"
#define OID_CC_PKI                      OID_CARDCONTACT "\x03"
#define OID_CC_FORMAT                   OID_CARDCONTACT "\x04"
#define OID_CC_GP_PROFILES              OID_CARDCONTACT "\x10"

#define OID_SCSH3                       OID_OPENSCDP "\x01"
#define OID_SCSH3GUI                    OID_OPENSCDP "\x02"

#define OID_SMARCARD_HSM                OID_CC_ISO7816 "\x01"
#define OID_CC_APDUTEST                 OID_CC_ISO7816 "\x02"
#define OID_CC_PACKAGES                 OID_CC_ISO7816 "\x7F"

#define OID_CC_ROLES                    OID_CC_PKI "\x01"
#define OID_CC_ROLE_SC_HSM              OID_CC_ROLES "\x01"

#define OID_CC_EXTENSIONS               OID_CC_PKI "\x02"
#define OID_ID_IMPU                     OID_CC_EXTENSIONS "\x01"
#define OID_ID_KEY_DOMAIN_UID           OID_CC_EXTENSIONS "\x02"

#define OID_CC_FF_DEVICEID              OID_CC_FORMAT "\x01"
#define OID_CC_FF_KDM                   OID_CC_FORMAT "\x02"
#define OID_CC_FF_PKA                   OID_CC_FORMAT "\x03"
#define OID_CC_FF_KDA                   OID_CC_FORMAT "\x04"

#define OID_RSADSI                      "\x2A\x86\x48\x86\xF7\x0D"

#define OID_PKCS                        OID_RSADSI "\x01"

#define OID_PKCS_5                      OID_PKCS "\x05"
#define OID_PKCS5_PBKDF2                OID_PKCS_5 "\x0C"
#define OID_PKCS5_PBES2                 OID_PKCS_5 "\x0D"

#define OID_PKCS_9                      OID_PKCS "\x09"

#define OID_PKCS9_SMIME_ALG             OID_PKCS_9 "\x10\x03"

#define OID_CHACHA20_POLY1305           OID_PKCS9_SMIME_ALG "\x12"
#define OID_HKDF_SHA256                 OID_PKCS9_SMIME_ALG "\x1D"
#define OID_HKDF_SHA384                 OID_PKCS9_SMIME_ALG "\x1E"
#define OID_HKDF_SHA512                 OID_PKCS9_SMIME_ALG "\x1F"


#define OID_DIGEST                      OID_RSADSI "\x02"

#define OID_HMAC_SHA1                   OID_DIGEST "\x07"
#define OID_HMAC_SHA224                 OID_DIGEST "\x08"
#define OID_HMAC_SHA256                 OID_DIGEST "\x09"
#define OID_HMAC_SHA384                 OID_DIGEST "\x0A"
#define OID_HMAC_SHA512                 OID_DIGEST "\x0B"

#endif
