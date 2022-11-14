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

/* This is copied from pkcs5.c Mbedtls */
/** Unfortunately it is declared as static, so I cannot call it. **/

static int pkcs5_parse_pbkdf2_params( const mbedtls_asn1_buf *params,
                                      mbedtls_asn1_buf *salt, int *iterations,
                                      int *keylen, mbedtls_md_type_t *md_type )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf prf_alg_oid;
    unsigned char *p = params->p;
    const unsigned char *end = params->p + params->len;

    if( params->tag != ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) );
    /*
     *  PBKDF2-params ::= SEQUENCE {
     *    salt              OCTET STRING,
     *    iterationCount    INTEGER,
     *    keyLength         INTEGER OPTIONAL
     *    prf               AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
     *  }
     *
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &salt->len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret ) );

    salt->p = p;
    p += salt->len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, iterations ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret ) );

    if( p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_int( &p, end, keylen ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret ) );
    }

    if( p == end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_alg_null( &p, end, &prf_alg_oid ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret ) );

    if( mbedtls_oid_get_md_hmac( &prf_alg_oid, md_type ) != 0 )
        return( MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE );

    if( p != end )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );

    return( 0 );
}

/* Taken from https://github.com/Mbed-TLS/mbedtls/issues/2335 */
int mbedtls_ansi_x936_kdf(mbedtls_md_type_t md_type, size_t input_len, uint8_t *input, size_t shared_info_len, uint8_t *shared_info, size_t output_len, uint8_t *output) {
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

    if (input_len + shared_info_len + 4 >= (1ULL<<61)-1) {
        return exit_code;
    }

    // keydatalen equals output_len
    hashlen = md_info->size;
    if (output_len >= hashlen * ((1ULL<<32)-1)) {
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
        counter++;
    }
    mbedtls_md_free(&md_ctx);
    return 0;
}

int cmd_cipher_sym() {
    int key_id = P1(apdu);
    int algo = P2(apdu);
    if (!isUserAuthenticated)
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    file_t *ef = search_dynamic_file((KEY_PREFIX << 8) | key_id);
    if (!ef)
        return SW_FILE_NOT_FOUND();
    if (key_has_purpose(ef, algo) == false)
        return SW_CONDITIONS_NOT_SATISFIED();
    if (wait_button_pressed() == true) // timeout
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    int key_size = file_get_size(ef);
    uint8_t kdata[32]; //maximum AES key size
    memcpy(kdata, file_get_data(ef), key_size);
    if (mkek_decrypt(kdata, key_size) != 0) {
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
            int r = mbedtls_aes_setkey_enc(&aes, kdata, key_size*8);
            if (r != 0) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, apdu.nc, tmp_iv, apdu.data, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
        }
        else if (algo == ALGO_AES_CBC_DECRYPT) {
            int r = mbedtls_aes_setkey_dec(&aes, kdata, key_size*8);
            if (r != 0) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, apdu.nc, tmp_iv, apdu.data, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                mbedtls_aes_free(&aes);
                return SW_EXEC_ERROR();
            }
        }
        res_APDU_size = apdu.nc;
        mbedtls_aes_free(&aes);
    }
    else if (algo == ALGO_AES_CMAC) {
        const mbedtls_cipher_info_t *cipher_info;
        if (key_size == 16)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        else if (key_size == 24)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
        else if (key_size == 32)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        else {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return SW_WRONG_DATA();
        }
        int r = mbedtls_cipher_cmac(cipher_info, kdata, key_size*8, apdu.data, apdu.nc, res_APDU);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        if (r != 0)
            return SW_EXEC_ERROR();
        res_APDU_size = 16;
    }
    else if (algo == ALGO_AES_DERIVE) {
        int r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, file_get_data(ef), key_size, apdu.data, apdu.nc, res_APDU, apdu.nc);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        if (r != 0)
            return SW_EXEC_ERROR();
        res_APDU_size = apdu.nc;
    }
    else if (algo == ALGO_EXT_CIPHER_ENCRYPT || algo == ALGO_EXT_CIPHER_DECRYPT) {
        size_t oid_len = 0, aad_len = 0, iv_len = 0, enc_len = 0;
        uint8_t *oid = NULL, *aad = NULL, *iv = NULL, *enc = NULL;
        if (!asn1_find_tag(apdu.data, apdu.nc, 0x6, &oid_len, &oid) || oid_len == 0 || oid == NULL) {
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            return SW_WRONG_DATA();
        }
        asn1_find_tag(apdu.data, apdu.nc, 0x81, &enc_len, &enc);
        asn1_find_tag(apdu.data, apdu.nc, 0x82, &iv_len, &iv);
        asn1_find_tag(apdu.data, apdu.nc, 0x83, &aad_len, &aad);
        uint8_t tmp_iv[16];
        memset(tmp_iv, 0, sizeof(tmp_iv));
        if (memcmp(oid, OID_CHACHA20_POLY1305, oid_len) == 0) {
            if (algo == ALGO_EXT_CIPHER_DECRYPT && enc_len < 16) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                return SW_WRONG_DATA();
            }
            int r = 0;
            mbedtls_chachapoly_context ctx;
            mbedtls_chachapoly_init(&ctx);
            if (algo == ALGO_EXT_CIPHER_ENCRYPT) {
                r = mbedtls_chachapoly_encrypt_and_tag(&ctx, enc_len, iv ? iv : tmp_iv, aad, aad_len, enc, res_APDU, res_APDU + enc_len);
            }
            else if (algo == ALGO_EXT_CIPHER_DECRYPT) {
                r = mbedtls_chachapoly_auth_decrypt(&ctx, enc_len - 16, iv ? iv : tmp_iv, aad, aad_len, enc + enc_len - 16, enc, res_APDU);
            }
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            mbedtls_chachapoly_free(&ctx);
            if (r != 0)
                return SW_EXEC_ERROR();
            if (algo == ALGO_EXT_CIPHER_ENCRYPT)
                res_APDU_size = enc_len + 16;
            else if (algo == ALGO_EXT_CIPHER_DECRYPT)
                res_APDU_size = enc_len - 16;
        }
        else if (memcmp(oid, OID_DIGEST, 7) == 0) {
            const mbedtls_md_info_t *md_info = NULL;
            if (memcmp(oid, OID_HMAC_SHA1, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            else if (memcmp(oid, OID_HMAC_SHA224, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA224);
            else if (memcmp(oid, OID_HMAC_SHA256, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            else if (memcmp(oid, OID_HMAC_SHA384, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            else if (memcmp(oid, OID_HMAC_SHA512, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            if (md_info == NULL)
                return SW_WRONG_DATA();
            int r = mbedtls_md_hmac(md_info, kdata, key_size, apdu.data, apdu.nc, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0)
                return SW_EXEC_ERROR();
            res_APDU_size = md_info->size;
        }
        else if (memcmp(oid, OID_HKDF_SHA256, oid_len) == 0 || memcmp(oid, OID_HKDF_SHA384, oid_len) == 0 || memcmp(oid, OID_HKDF_SHA512, oid_len) == 0) {
            const mbedtls_md_info_t *md_info = NULL;
            if (memcmp(oid, OID_HKDF_SHA256, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            else if (memcmp(oid, OID_HKDF_SHA384, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA384);
            else if (memcmp(oid, OID_HKDF_SHA512, oid_len) == 0)
                md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            int r = mbedtls_hkdf(md_info, iv, iv_len, kdata, key_size, enc, enc_len, res_APDU, apdu.ne > 0 ? apdu.ne : md_info->size);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0)
                return SW_EXEC_ERROR();
            res_APDU_size = apdu.ne > 0 ? apdu.ne : md_info->size;
        }
        else if (memcmp(oid, OID_PKCS5_PBKDF2, oid_len) == 0) {
            int iterations = 0, keylen = 0;
            mbedtls_asn1_buf salt, params = { .p = enc, .len = enc_len };
            mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
            mbedtls_md_context_t md_ctx;

            int r = pkcs5_parse_pbkdf2_params(&params, &salt, &iterations, &keylen, &md_type);
            if (r != 0) {
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                return SW_WRONG_DATA();
            }

            mbedtls_md_init(&md_ctx);
            if (mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1) != 0) {
                mbedtls_md_free(&md_ctx);
                mbedtls_platform_zeroize(kdata, sizeof(kdata));
                return SW_WRONG_DATA();
            }
            r = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, kdata, key_size, salt.p, salt.len, iterations, keylen ? keylen : (apdu.ne ? apdu.ne : 32), res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            mbedtls_md_free(&md_ctx);
            if (r != 0)
                return SW_EXEC_ERROR();
            res_APDU_size = keylen ? keylen : (apdu.ne ? apdu.ne : 32);
        }
        else if (memcmp(oid, OID_PKCS5_PBES2, oid_len) == 0) {
            mbedtls_asn1_buf params = { .p = aad, .len = aad_len };
            int r = mbedtls_pkcs5_pbes2(&params, algo == ALGO_EXT_CIPHER_ENCRYPT ? MBEDTLS_PKCS5_ENCRYPT : MBEDTLS_PKCS5_DECRYPT, kdata, key_size, enc, enc_len, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_WRONG_DATA();
            }
            res_APDU_size = enc_len;
        }
        else if (memcmp(oid, OID_KDF_X963, oid_len) == 0) {
            mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
            if (memcmp(enc, OID_ECKA_DH_X963KDF_SHA1, enc_len) == 0)
                md_type = MBEDTLS_MD_SHA1;
            else if (memcmp(enc, OID_ECKA_DH_X963KDF_SHA224, enc_len) == 0)
                md_type = MBEDTLS_MD_SHA224;
            else if (memcmp(enc, OID_ECKA_DH_X963KDF_SHA256, enc_len) == 0)
                md_type = MBEDTLS_MD_SHA256;
            else if (memcmp(enc, OID_ECKA_DH_X963KDF_SHA384, enc_len) == 0)
                md_type = MBEDTLS_MD_SHA384;
            else if (memcmp(enc, OID_ECKA_DH_X963KDF_SHA512, enc_len) == 0)
                md_type = MBEDTLS_MD_SHA512;
            int r = mbedtls_ansi_x936_kdf(md_type, key_size, kdata, aad_len, aad, apdu.ne > 0 ? apdu.ne : 32, res_APDU);
            mbedtls_platform_zeroize(kdata, sizeof(kdata));
            if (r != 0) {
                return SW_WRONG_DATA();
            }
            res_APDU_size = apdu.ne > 0 ? apdu.ne : 32;
        }
    }
    else {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return SW_WRONG_P1P2();
    }
    return SW_OK();
}
