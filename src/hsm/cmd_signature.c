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
#include "crypto_utils.h"
#include "sc_hsm.h"
#include "asn1.h"
#include "mbedtls/oid.h"
#include "random.h"

extern mbedtls_ecp_keypair hd_context;
extern uint8_t hd_keytype;

//-----
/* From OpenSC */
static const uint8_t hdr_md5[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const uint8_t hdr_sha1[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
    0x05, 0x00, 0x04, 0x14
};
static const uint8_t hdr_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const uint8_t hdr_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const uint8_t hdr_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const uint8_t hdr_sha224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const uint8_t hdr_ripemd160[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x14
};
static const struct digest_info_prefix {
    mbedtls_md_type_t algorithm;
    const uint8_t *hdr;
    uint16_t hdr_len;
    uint16_t hash_len;
} digest_info_prefix[] = {
    { MBEDTLS_MD_MD5, hdr_md5, sizeof(hdr_md5), 16 },
    { MBEDTLS_MD_SHA1, hdr_sha1, sizeof(hdr_sha1), 20 },
    { MBEDTLS_MD_SHA256, hdr_sha256, sizeof(hdr_sha256), 32 },
    { MBEDTLS_MD_SHA384, hdr_sha384, sizeof(hdr_sha384), 48 },
    { MBEDTLS_MD_SHA512, hdr_sha512, sizeof(hdr_sha512), 64 },
    { MBEDTLS_MD_SHA224, hdr_sha224, sizeof(hdr_sha224), 28 },
    { MBEDTLS_MD_RIPEMD160, hdr_ripemd160, sizeof(hdr_ripemd160), 20 },
    { 0, NULL, 0, 0 }
};
int pkcs1_strip_digest_info_prefix(mbedtls_md_type_t *algorithm,
                                   const uint8_t *in_dat,
                                   uint16_t in_len,
                                   uint8_t *out_dat,
                                   uint16_t *out_len) {
    for (int i = 0; digest_info_prefix[i].algorithm != 0; i++) {
        uint16_t hdr_len = digest_info_prefix[i].hdr_len, hash_len = digest_info_prefix[i].hash_len;
        const uint8_t *hdr = digest_info_prefix[i].hdr;
        if (in_len == (hdr_len + hash_len) && !memcmp(in_dat, hdr, hdr_len)) {
            if (algorithm) {
                *algorithm = digest_info_prefix[i].algorithm;
            }
            if (out_dat == NULL) {
                return CCID_OK;
            }
            if (*out_len < hash_len) {
                return CCID_WRONG_DATA;
            }
            memmove(out_dat, in_dat + hdr_len, hash_len);
            *out_len = hash_len;
            return CCID_OK;
        }
    }
    return CCID_EXEC_ERROR;
}
//-----

int cmd_signature() {
    uint8_t key_id = P1(apdu);
    uint8_t p2 = P2(apdu);
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    file_t *fkey;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) &&
         !(fkey =
               search_by_fid((KEY_PREFIX << 8) | key_id, NULL,
                             SPECIFY_EF))) || !file_has_data(fkey)) {
        return SW_FILE_NOT_FOUND();
    }
    if (get_key_counter(fkey) == 0) {
        return SW_FILE_FULL();
    }
    if (key_has_purpose(fkey, p2) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    uint16_t key_size = file_get_size(fkey);
    if (p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_EC_SHA1) {
        md = MBEDTLS_MD_SHA1;
    }
    else if (p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS_SHA256 || p2 == ALGO_EC_SHA256) {
        md = MBEDTLS_MD_SHA256;
    }
    else if (p2 == ALGO_EC_SHA224 || p2 == ALGO_RSA_PKCS1_SHA224 || p2 == ALGO_RSA_PSS_SHA224) {
        md = MBEDTLS_MD_SHA224;
    }
    else if (p2 == ALGO_EC_SHA384 || p2 == ALGO_RSA_PKCS1_SHA384 || p2 == ALGO_RSA_PSS_SHA384) {
        md = MBEDTLS_MD_SHA384;
    }
    else if (p2 == ALGO_EC_SHA512 || p2 == ALGO_RSA_PKCS1_SHA512 || p2 == ALGO_RSA_PSS_SHA512) {
        md = MBEDTLS_MD_SHA512;
    }
    if (p2 == ALGO_RSA_PKCS1_SHA1 || p2 == ALGO_RSA_PSS_SHA1 || p2 == ALGO_EC_SHA1 ||
        p2 == ALGO_RSA_PKCS1_SHA256 || p2 == ALGO_RSA_PSS_SHA256 || p2 == ALGO_EC_SHA256 ||
        p2 == ALGO_EC_SHA224 || p2 == ALGO_EC_SHA384 || p2 == ALGO_EC_SHA512 ||
        p2 == ALGO_RSA_PKCS1_SHA224 || p2 == ALGO_RSA_PKCS1_SHA384 || p2 == ALGO_RSA_PKCS1_SHA512 ||
        p2 == ALGO_RSA_PSS_SHA224 || p2 == ALGO_RSA_PSS_SHA384 || p2 == ALGO_RSA_PSS_SHA512) {
        generic_hash(md, apdu.data, apdu.nc, apdu.data);
        apdu.nc = mbedtls_md_get_size(mbedtls_md_info_from_type(md));
    }
    if (p2 >= ALGO_RSA_RAW && p2 <= ALGO_RSA_PSS_SHA512) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);

        int r = load_private_key_rsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_rsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        uint8_t *hash = apdu.data;
        uint16_t hash_len = apdu.nc;
        if (p2 == ALGO_RSA_PKCS1) { //DigestInfo attached
            uint16_t nc = apdu.nc;
            if (pkcs1_strip_digest_info_prefix(&md, apdu.data, apdu.nc, apdu.data,
                                               &nc) != CCID_OK) {                                   //gets the MD algo id and strips it off
                return SW_EXEC_ERROR();
            }
            apdu.nc = nc;
        }
        else {
            //sc_asn1_print_tags(apdu.data, apdu.nc);
            uint16_t tout = 0, oid_len = 0;
            uint8_t *p = NULL, *oid = NULL;
            if (asn1_find_tag(apdu.data, apdu.nc, 0x30, &tout, &p) && tout > 0 && p != NULL) {
                uint16_t tout30 = 0;
                uint8_t *c30 = NULL;
                if (asn1_find_tag(p, tout, 0x30, &tout30, &c30) && tout30 > 0 && c30 != NULL) {
                    asn1_find_tag(c30, tout30, 0x6, &oid_len, &oid);
                }
                asn1_find_tag(p, tout, 0x4, &hash_len, &hash);
            }
            if (oid && oid_len > 0) {
                if (memcmp(oid, MBEDTLS_OID_DIGEST_ALG_SHA1, oid_len) == 0) {
                    md = MBEDTLS_MD_SHA1;
                }
                else if (memcmp(oid, MBEDTLS_OID_DIGEST_ALG_SHA224, oid_len) == 0) {
                    md = MBEDTLS_MD_SHA224;
                }
                else if (memcmp(oid, MBEDTLS_OID_DIGEST_ALG_SHA256, oid_len) == 0) {
                    md = MBEDTLS_MD_SHA256;
                }
                else if (memcmp(oid, MBEDTLS_OID_DIGEST_ALG_SHA384, oid_len) == 0) {
                    md = MBEDTLS_MD_SHA384;
                }
                else if (memcmp(oid, MBEDTLS_OID_DIGEST_ALG_SHA512, oid_len) == 0) {
                    md = MBEDTLS_MD_SHA512;
                }
            }
            if (p2 >= ALGO_RSA_PSS && p2 <= ALGO_RSA_PSS_SHA512) {
                if (p2 == ALGO_RSA_PSS && !oid) {
                    if (apdu.nc == 20) { //default is sha1
                        md = MBEDTLS_MD_SHA1;
                    }
                    else if (apdu.nc == 28) {
                        md = MBEDTLS_MD_SHA224;
                    }
                    else if (apdu.nc == 32) {
                        md = MBEDTLS_MD_SHA256;
                    }
                    else if (apdu.nc == 48) {
                        md = MBEDTLS_MD_SHA384;
                    }
                    else if (apdu.nc == 64) {
                        md = MBEDTLS_MD_SHA512;
                    }
                }
                mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, md);
            }
        }
        if (md == MBEDTLS_MD_NONE) {
            if (apdu.nc < key_size) { //needs padding
                memset(apdu.data + apdu.nc, 0, key_size - apdu.nc);
            }
            r = mbedtls_rsa_private(&ctx, random_gen, NULL, apdu.data, res_APDU);
        }
        else {
            uint8_t *signature = (uint8_t *) calloc(key_size, sizeof(uint8_t));
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
    else if (p2 >= ALGO_EC_RAW && p2 <= ALGO_EC_SHA512) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        md = MBEDTLS_MD_SHA256;
        if (p2 == ALGO_EC_RAW) {
            if (apdu.nc == 32) {
                md = MBEDTLS_MD_SHA256;
            }
            else if (apdu.nc == 20) {
                md = MBEDTLS_MD_SHA1;
            }
            else if (apdu.nc == 28) {
                md = MBEDTLS_MD_SHA224;
            }
            else if (apdu.nc == 48) {
                md = MBEDTLS_MD_SHA384;
            }
            else if (apdu.nc == 64) {
                md = MBEDTLS_MD_SHA512;
            }
        }
        if (p2 == ALGO_EC_SHA1) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (p2 == ALGO_EC_SHA224) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (p2 == ALGO_EC_SHA256) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (p2 == ALGO_EC_SHA384) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (p2 == ALGO_EC_SHA512) {
            md = MBEDTLS_MD_SHA512;
        }
        int r = load_private_key_ecdsa(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_ecdsa_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        uint8_t buf[MBEDTLS_ECDSA_MAX_LEN];
        if (mbedtls_ecdsa_write_signature(&ctx, md, apdu.data, apdu.nc, buf, MBEDTLS_ECDSA_MAX_LEN,
                                          &olen, random_gen, NULL) != 0) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        memcpy(res_APDU, buf, olen);
        res_APDU_size = (uint16_t)olen;
        mbedtls_ecdsa_free(&ctx);
    }
    else if (p2 == ALGO_HD) {
        size_t olen = 0;
        uint8_t buf[MBEDTLS_ECDSA_MAX_LEN];
        if (hd_context.grp.id == MBEDTLS_ECP_DP_NONE) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        if (hd_keytype != 0x1 && hd_keytype != 0x2) {
            return SW_INCORRECT_PARAMS();
        }
        md = MBEDTLS_MD_SHA256;
        if (mbedtls_ecdsa_write_signature(&hd_context, md, apdu.data, apdu.nc, buf,
                                          MBEDTLS_ECDSA_MAX_LEN,
                                          &olen, random_gen, NULL) != 0) {
            mbedtls_ecdsa_free(&hd_context);
            return SW_EXEC_ERROR();
        }
        memcpy(res_APDU, buf, olen);
        res_APDU_size = (uint16_t)olen;
        mbedtls_ecdsa_free(&hd_context);
        hd_keytype = 0;
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    decrement_key_counter(fkey);
    return SW_OK();
}
