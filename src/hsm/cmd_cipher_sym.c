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
        else if (memcmp(oid, OID_HMAC, 7) == 0) {
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
            if (r != 0)
                return SW_EXEC_ERROR();
            res_APDU_size = md_info->size;
        }
    }
    else {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return SW_WRONG_P1P2();
    }
    return SW_OK();
}
