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

#include "common.h"
#include "mbedtls/aes.h"
#include "mbedtls/cmac.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/gcm.h"
#include "md_wrap.h"
#include "mbedtls/md.h"
#include "crypto_utils.h"
#include "sc_hsm.h"
#include "kek.h"
#include "asn1.h"
#include "oid.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1.h"
#include "mbedtls/cipher.h"
#include "mbedtls/oid.h"
#include "mbedtls/ccm.h"

extern mbedtls_ecp_keypair hd_context;
extern uint8_t hd_keytype;

/* This is copied from pkcs5.c Mbedtls */
/** Unfortunately it is declared as static, so I cannot call it. **/

static int pkcs5_parse_pbkdf2_params(const mbedtls_asn1_buf *params,
                                     mbedtls_asn1_buf *salt, int *iterations,
                                     uint16_t *keylen, mbedtls_md_type_t *md_type) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf prf_alg_oid;
    unsigned char *p = params->p;
    const unsigned char *end = params->p + params->len;

    if (params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }
    /*
     *  PBKDF2-params ::= SEQUENCE {
     *    salt              OCTET STRING,
     *    iterationCount    INTEGER,
     *    keyLength         INTEGER OPTIONAL
     *    prf               AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
     *  }
     *
     */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &salt->len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    salt->p = p;
    p += salt->len;

    if ((ret = mbedtls_asn1_get_int(&p, end, iterations)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_int(&p, end, (int *)keylen)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
        }
    }

    if (p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_alg_null(&p, end, &prf_alg_oid)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (mbedtls_oid_get_md_hmac(&prf_alg_oid, md_type) != 0) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    if (p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

/* Taken from https://github.com/Mbed-TLS/mbedtls/issues/2335 */
int mbedtls_ansi_x963_kdf(mbedtls_md_type_t md_type,
                          uint16_t input_len,
                          uint8_t *input,
                          uint16_t shared_info_len,
                          uint8_t *shared_info,
                          uint16_t output_len,
                          uint8_t *output) {
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info = NULL;
    int hashlen = 0, exit_code = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    uint8_t counter_buf[4], tmp_output[64]; //worst case

    mbedtls_md_init(&md_ctx);

    md_info = mbedtls_md_info_from_type(md_type);

    if (md_info == NULL) {
        return exit_code;
    }

    if (mbedtls_md_setup(&md_ctx, md_info, 0)) {
        return exit_code;
    }

    if (input_len + shared_info_len + 4 >= (1ULL << 61) - 1) {
        return exit_code;
    }

    // keydatalen equals output_len
    hashlen = md_info->size;
    if (output_len >= hashlen * ((1ULL << 32) - 1)) {
        return exit_code;
    }

    for (int i = 0, counter = 1; i < output_len; counter++) {
        mbedtls_md_starts(&md_ctx);
        mbedtls_md_update(&md_ctx, input, input_len);

        //TODO: be careful with architecture little vs. big
        counter_buf[0] = (uint8_t) ((counter >> 24) & 0xff);
        counter_buf[1] = (uint8_t) ((counter >> 16) & 0xff);
        counter_buf[2] = (uint8_t) ((counter >> 8) & 0xff);
        counter_buf[3] = (uint8_t) ((counter >> 0) & 0xff);

        mbedtls_md_update(&md_ctx, counter_buf, 4);

        if (shared_info_len > 0 && shared_info != NULL) {
            mbedtls_md_update(&md_ctx, shared_info, shared_info_len);
        }
        mbedtls_md_finish(&md_ctx, tmp_output);
        memcpy(&output[i], tmp_output, (output_len - i < hashlen) ? output_len - i : hashlen);
        i += hashlen;
    }
    mbedtls_md_free(&md_ctx);
    return 0;
}

int cmd_cipher_sym() {
    uint8_t key_id = P1(apdu), algo = P2(apdu);
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (wait_button_pressed() == true) { // timeout
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (hd_keytype == 0) {
        if (!ef) {
            return SW_FILE_NOT_FOUND();
        }
        if (key_has_purpose(ef, algo) == false) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
    }
    uint16_t key_size = file_get_size(ef);
    uint8_t kdata[64]; //maximum AES key size
    memcpy(kdata, file_get_data(ef), key_size);
    if (hd_keytype == 0 && mkek_decrypt(kdata, key_size) != 0) {
        return SW_EXEC_ERROR();
    }
    if (algo == ALGO_AES_CBC_ENCRYPT || algo == ALGO_AES_CBC_DECRYPT) {
        if ((apdu.nc % 16) != 0) {
            return SW_WRONG_LENGTH();
        }
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        uint8_t tmp_iv[IV_SIZE];
        memset(tmp_iv, 0, sizeof(tmp_iv));
        if (algo == ALGO_AES_CBC_ENCRYPT) {
            int r = mbedtls_aes_setkey_enc(&aes, kdata, key_size * 8);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes,
                                      MBEDTLS_AES_ENCRYPT,
                                      apdu.nc,
                                      tmp_iv,
                                      apdu.data,
                                      res_APDU);
            mbedtls_aes_free(&aes);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
        }
        else if (algo == ALGO_AES_CBC_DECRYPT) {
            int r = mbedtls_aes_setkey_dec(&aes, kdata, key_size * 8);
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes,
                                      MBEDTLS_AES_DECRYPT,
                                      apdu.nc,
                                      tmp_iv,
                                      apdu.data,
                                      res_APDU);
            mbedtls_aes_free(&aes);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
        }
        res_APDU_size = (uint16_t)apdu.nc;
    }
    else if (algo == ALGO_AES_CMAC) {
        const mbedtls_cipher_info_t *cipher_info;
        if (key_size == 16) {
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        }
        else if (key_size == 24) {
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
        }
        else if (key_size == 32) {
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        }
        else {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return SW_WRONG_DATA();
        }
        int r = mbedtls_cipher_cmac(cipher_info, kdata, key_size * 8, apdu.data, apdu.nc, res_APDU);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = 16;
    }
    else if (algo == ALGO_AES_DERIVE) {
        int r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                             NULL,
                             0,
                             kdata,
                             key_size,
                             apdu.data,
                             apdu.nc,
                             res_APDU,
                             apdu.nc);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = (uint16_t)apdu.nc;
    }
    else if (algo == ALGO_EXT_CIPHER_ENCRYPT || algo == ALGO_EXT_CIPHER_DECRYPT) {
        asn1_ctx_t ctxi, oid = {0}, enc = {0}, iv = {0}, aad = {0};
        asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
        if (!asn1_find_tag(&ctxi, 0x6, &oid) || asn1_len(&oid) == 0) {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return SW_WRONG_DATA();
        }
        asn1_find_tag(&ctxi, 0x81, &enc);
        asn1_find_tag(&ctxi, 0x82, &iv);
        asn1_find_tag(&ctxi, 0x83, &aad);
        uint8_t tmp_iv[16];
        memset(tmp_iv, 0, sizeof(tmp_iv));
        if (memcmp(oid.data, OID_CHACHA20_POLY1305, oid.len) == 0) {
            if (algo == ALGO_EXT_CIPHER_DECRYPT && enc.len < 16) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                return SW_WRONG_DATA();
            }
            int r = 0;
            mbedtls_chachapoly_context ctx;
            mbedtls_chachapoly_init(&ctx);
            mbedtls_chachapoly_setkey(&ctx, kdata);
            if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                r = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                                                       enc.len,
                                                       asn1_len(&iv) > 0 ? iv.data : tmp_iv,
                                                       aad.data,
                                                       aad.len,
                                                       enc.data,
                                                       res_APDU,
                                                       res_APDU + enc.len);
            }
            else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                r = mbedtls_chachapoly_auth_decrypt(&ctx,
                                                    enc.len - 16,
                                                    asn1_len(&iv) > 0 ? iv.data : tmp_iv,
                                                    aad.data,
                                                    aad.len,
                                                    enc.data + enc.len - 16,
                                                    enc.data,
                                                    res_APDU);
            }
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            mbedtls_chachapoly_free(&ctx);
            if (r != 0) {
                if (r == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
                    return SW_WRONG_DATA();
                }
                return SW_EXEC_ERROR();
            }
            if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                res_APDU_size = enc.len + 16;
            }
            else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                res_APDU_size = enc.len - 16;
            }
        }
        else if (memcmp(oid.data, OID_DIGEST, 7) == 0) {
            const mbedtls_md_info_t *md_info = NULL;
            if (memcmp(oid.data, OID_HMAC_SHA1, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            }
            else if (memcmp(oid.data, OID_HMAC_SHA224, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA224);
            }
            else if (memcmp(oid.data, OID_HMAC_SHA256, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            }
            else if (memcmp(oid.data, OID_HMAC_SHA384, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            }
            else if (memcmp(oid.data, OID_HMAC_SHA512, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            }
            if (md_info == NULL) {
                return SW_WRONG_DATA();
            }
            int r = mbedtls_md_hmac(md_info, kdata, key_size, enc.data, enc.len, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = md_info->size;
        }
        else if (memcmp(oid.data, OID_HKDF_SHA256,
                        oid.len) == 0 ||
                 memcmp(oid.data, OID_HKDF_SHA384,
                        oid.len) == 0 || memcmp(oid.data, OID_HKDF_SHA512, oid.len) == 0) {
            const mbedtls_md_info_t *md_info = NULL;
            if (memcmp(oid.data, OID_HKDF_SHA256, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            }
            else if (memcmp(oid.data, OID_HKDF_SHA384, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            }
            else if (memcmp(oid.data, OID_HKDF_SHA512, oid.len) == 0) {
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            }
            int r = mbedtls_hkdf(md_info,
                                 iv.data,
                                 iv.len,
                                 kdata,
                                 key_size,
                                 enc.data,
                                 enc.len,
                                 res_APDU,
                                 apdu.ne > 0 &&
                                 apdu.ne < 65536 ? apdu.ne : mbedtls_md_get_size(md_info));
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = apdu.ne > 0 && apdu.ne < 65536 ? (uint16_t)apdu.ne : (uint16_t)mbedtls_md_get_size(md_info);
        }
        else if (memcmp(oid.data, OID_PKCS5_PBKDF2, oid.len) == 0) {
            int iterations = 0;
            uint16_t keylen = 0;
            mbedtls_asn1_buf salt,
                             params =
            { .p = enc.data, .len = enc.len, .tag = (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) };
            mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;

            int r = pkcs5_parse_pbkdf2_params(&params, &salt, &iterations, &keylen, &md_type);
            if (r != 0) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                return SW_WRONG_DATA();
            }

            r = mbedtls_pkcs5_pbkdf2_hmac_ext(md_type,
                                              kdata,
                                              key_size,
                                              salt.p,
                                              salt.len,
                                              iterations,
                                              keylen ? keylen : (apdu.ne > 0 &&
                                                                 apdu.ne < 65536 ? apdu.ne : 32),
                                              res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = keylen ? keylen : (apdu.ne > 0 && apdu.ne < 65536 ? (uint16_t)apdu.ne : 32);
        }
        else if (memcmp(oid.data, OID_PKCS5_PBES2, oid.len) == 0) {
            size_t olen = 0;
            mbedtls_asn1_buf params =
                {.p = aad.data, .len = aad.len, .tag = (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)};
            int r = mbedtls_pkcs5_pbes2_ext(&params,
                                        algo == ALGO_EXT_CIPHER_ENCRYPT ? MBEDTLS_PKCS5_ENCRYPT : MBEDTLS_PKCS5_DECRYPT,
                                        kdata,
                                        key_size,
                                        enc.data,
                                        enc.len,
                                        res_APDU, 4096, &olen);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_WRONG_DATA();
            }
            res_APDU_size = (uint16_t)olen;
        }
        else if (memcmp(oid.data, OID_KDF_X963, oid.len) == 0) {
            mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
            if (memcmp(enc.data, OID_HMAC_SHA1, enc.len) == 0) {
                md_type = MBEDTLS_MD_SHA1;
            }
            else if (memcmp(enc.data, OID_HMAC_SHA224, enc.len) == 0) {
                md_type = MBEDTLS_MD_SHA224;
            }
            else if (memcmp(enc.data, OID_HMAC_SHA256, enc.len) == 0) {
                md_type = MBEDTLS_MD_SHA256;
            }
            else if (memcmp(enc.data, OID_HMAC_SHA384, enc.len) == 0) {
                md_type = MBEDTLS_MD_SHA384;
            }
            else if (memcmp(enc.data, OID_HMAC_SHA512, enc.len) == 0) {
                md_type = MBEDTLS_MD_SHA512;
            }
            int r = mbedtls_ansi_x963_kdf(md_type,
                                          key_size,
                                          kdata,
                                          aad.len,
                                          aad.data,
                                          apdu.ne > 0 && apdu.ne < 65536 ? (uint16_t)apdu.ne : 32,
                                          res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_WRONG_DATA();
            }
            res_APDU_size = apdu.ne > 0 && apdu.ne < 65536 ? (uint16_t)apdu.ne : 32;
        }
        else if (memcmp(oid.data, OID_NIST_AES, 8) == 0) {
            if (oid.len != 9) {
                return SW_WRONG_DATA();
            }
            uint8_t aes_algo = oid.data[8],
                    mode =
                (algo == ALGO_EXT_CIPHER_ENCRYPT ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT);
            if ((aes_algo >= 0x01 && aes_algo <= 0x09 && key_size != 16) ||
                (aes_algo >= 0x15 && aes_algo <= 0x1D && key_size != 24) ||
                (aes_algo >= 0x29 && aes_algo <= 0x31 && key_size != 32)) {
                return SW_WRONG_DATA();
            }
            mbedtls_aes_context ctx;
            int r = 0;
            mbedtls_aes_init(&ctx);
            if (asn1_len(&iv) == 0) {
                iv.data = tmp_iv;
                iv.len = sizeof(tmp_iv);
            }
            if (aes_algo == 0x01 || aes_algo == 0x15 || aes_algo == 0x29) { /* ECB */
                if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                    r = mbedtls_aes_setkey_enc(&ctx, kdata, key_size * 8);
                }
                else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                    r = mbedtls_aes_setkey_dec(&ctx, kdata, key_size * 8);
                }
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                r = mbedtls_aes_crypt_ecb(&ctx, mode, enc.data, res_APDU);
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                res_APDU_size = MIN(enc.len, 16); // ECB operates with 16-byte blocks
            }
            else if (aes_algo == 0x02 || aes_algo == 0x16 || aes_algo == 0x2A) { /* CBC */
                if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                    r = mbedtls_aes_setkey_enc(&ctx, kdata, key_size * 8);
                }
                else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                    r = mbedtls_aes_setkey_dec(&ctx, kdata, key_size * 8);
                }
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                r = mbedtls_aes_crypt_cbc(&ctx, mode, enc.len, iv.data, enc.data, res_APDU);
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                res_APDU_size = enc.len;
            }
            else if (aes_algo == 0x03 || aes_algo == 0x17 || aes_algo == 0x2B) { /* OFB */
                size_t iv_off = 0;
                r = mbedtls_aes_setkey_enc(&ctx, kdata, key_size * 8);
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                r = mbedtls_aes_crypt_ofb(&ctx, enc.len, &iv_off, iv.data, enc.data, res_APDU);
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                res_APDU_size = enc.len;
            }
            else if (aes_algo == 0x04 || aes_algo == 0x18 || aes_algo == 0x2C) { /* CFB */
                size_t iv_off = 0;
                r = mbedtls_aes_setkey_enc(&ctx, kdata, key_size * 8);
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                r = mbedtls_aes_crypt_cfb128(&ctx, mode, enc.len, &iv_off, iv.data, enc.data, res_APDU);
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                res_APDU_size = enc.len;
            }
            else if (aes_algo == 0x06 || aes_algo == 0x1A || aes_algo == 0x2E) { /* GCM */
                mbedtls_aes_free(&ctx); // No AES ctx used
                mbedtls_gcm_context gctx;
                mbedtls_gcm_init(&gctx);
                r = mbedtls_gcm_setkey(&gctx, MBEDTLS_CIPHER_ID_AES, kdata, key_size * 8);
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                    r = mbedtls_gcm_crypt_and_tag(&gctx,
                                                  MBEDTLS_GCM_ENCRYPT,
                                                  enc.len,
                                                  iv.data,
                                                  iv.len,
                                                  aad.data,
                                                  aad.len,
                                                  enc.data,
                                                  res_APDU,
                                                  16,
                                                  res_APDU + enc.len);
                    res_APDU_size = enc.len + 16;
                }
                else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                    r = mbedtls_gcm_auth_decrypt(&gctx,
                                                 enc.len - 16,
                                                 iv.data,
                                                 iv.len,
                                                 aad.data,
                                                 aad.len,
                                                 enc.data + enc.len - 16,
                                                 16,
                                                 enc.data,
                                                 res_APDU);
                    res_APDU_size = enc.len - 16;
                }
                mbedtls_gcm_free(&gctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
            else if (aes_algo == 0x09 || aes_algo == 0x1D || aes_algo == 0x31) { /* CTR */
                size_t iv_off = 0;
                uint8_t stream_block[16];
                r = mbedtls_aes_setkey_enc(&ctx, kdata, key_size * 8);
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                r = mbedtls_aes_crypt_ctr(&ctx, enc.len, &iv_off, iv.data, stream_block, enc.data, res_APDU);
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                res_APDU_size = enc.len;
            }
            else if (aes_algo == 0x07 || aes_algo == 0x1B || aes_algo == 0x2F) { /* CCM */
                mbedtls_aes_free(&ctx); // No AES ctx used
                mbedtls_ccm_context gctx;
                mbedtls_ccm_init(&gctx);
                r = mbedtls_ccm_setkey(&gctx, MBEDTLS_CIPHER_ID_AES, kdata, key_size * 8);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                if (iv.len == 16) {
                    iv.len = 12;
                }
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                    r = mbedtls_ccm_encrypt_and_tag(&gctx,
                                                    enc.len,
                                                    iv.data,
                                                    iv.len,
                                                    aad.data,
                                                    aad.len,
                                                    enc.data,
                                                    res_APDU,
                                                    res_APDU + enc.len,
                                                    16);
                    res_APDU_size = enc.len + 16;
                }
                else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                    r = mbedtls_ccm_auth_decrypt(&gctx,
                                                 enc.len - 16,
                                                 iv.data,
                                                 iv.len,
                                                 aad.data,
                                                 aad.len,
                                                 enc.data,
                                                 res_APDU,
                                                 enc.data + enc.len - 16,
                                                 16);
                    res_APDU_size = enc.len - 16;
                }
                mbedtls_ccm_free(&gctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
        }
        else if (memcmp(oid.data, OID_IEEE_ALG, 8) == 0) {
            if (oid.len != 9) {
                return SW_WRONG_DATA();
            }
            uint8_t aes_algo = oid.data[8],
                    mode =
                (algo == ALGO_EXT_CIPHER_ENCRYPT ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT);
            int r = 0;
            memset(tmp_iv, 0, sizeof(tmp_iv));
            if (asn1_len(&iv) == 0) {
                iv.data = tmp_iv;
                iv.len = sizeof(tmp_iv);
            }
            if ((aes_algo == 0x01 && key_size != 32) || (aes_algo == 0x02 && key_size != 64)) {
                return SW_WRONG_DATA();
            }
            mbedtls_aes_xts_context ctx;
            mbedtls_aes_xts_init(&ctx);
            if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                r = mbedtls_aes_xts_setkey_enc(&ctx, kdata, key_size * 8);
            }
            else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                r = mbedtls_aes_xts_setkey_dec(&ctx, kdata, key_size * 8);
            }
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            r = mbedtls_aes_crypt_xts(&ctx, mode, enc.len, iv.data, enc.data, res_APDU);
            mbedtls_aes_xts_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = enc.len;
        }
        else if (memcmp(oid.data, OID_HD, 11) == 0) {
            mbedtls_aes_context ctx;
            int r = 0;
            uint8_t mode =
                (algo == ALGO_EXT_CIPHER_ENCRYPT ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT),
                    secret[64] = { 0 };
            mbedtls_aes_init(&ctx);
            if (hd_keytype != 0x3) {
                return SW_INCORRECT_PARAMS();
            }
            key_size = 32;
            mbedtls_mpi_write_binary(&hd_context.d, kdata, key_size);
            r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                                kdata,
                                key_size,
                                aad.data,
                                aad.len,
                                secret);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            if (iv.data == tmp_iv || iv.len == 0) {
                iv.data = secret + 32;
                iv.len = 16;
            }
            if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                r = mbedtls_aes_setkey_enc(&ctx, secret, key_size * 8);
            }
            else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                r = mbedtls_aes_setkey_dec(&ctx, secret, key_size * 8);
            }
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&ctx, mode, enc.len, iv.data, enc.data, res_APDU);
            mbedtls_aes_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = enc.len;
            mbedtls_ecdsa_free(&hd_context);
            hd_keytype = 0;
        }
        else {
            return SW_WRONG_DATA();
        }
    }
    else {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return SW_WRONG_P1P2();
    }
    return SW_OK();
}
