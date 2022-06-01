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

#include "cvc.h"
#include "common.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "cvcerts.h"
#include <string.h>
#include "asn1.h"
#include "ccid2040.h"
#include "crypto_utils.h"
#include "random.h"

size_t asn1_cvc_public_key_rsa(mbedtls_rsa_context *rsa, uint8_t *buf, size_t buf_len) {
    const uint8_t oid_rsa[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02 };
    size_t n_size = mbedtls_mpi_size(&rsa->N), e_size = mbedtls_mpi_size(&rsa->E);
    size_t ntot_size = asn1_len_tag(0x81, n_size), etot_size = asn1_len_tag(0x82, e_size);
    size_t oid_len = asn1_len_tag(0x6, sizeof(oid_rsa));
    size_t tot_len = asn1_len_tag(0x7f49, oid_len+ntot_size+etot_size);
    if (buf == NULL || buf_len == 0)
        return tot_len;
    if (buf_len < tot_len)
        return 0;
    uint8_t *p = buf;
    memcpy(p, "\x7f\x49", 2); p += 2;
    p += format_tlv_len(oid_len+ntot_size+etot_size, p);
    //oid
    *p++ = 0x6; p += format_tlv_len(sizeof(oid_rsa), p); memcpy(p, oid_rsa, sizeof(oid_rsa)); p += sizeof(oid_rsa);
    //n
    *p++ = 0x81; p += format_tlv_len(n_size, p); mbedtls_mpi_write_binary(&rsa->N, p, n_size); p += n_size;
    //n
    *p++ = 0x82; p += format_tlv_len(e_size, p); mbedtls_mpi_write_binary(&rsa->E, p, e_size); p += e_size;
    return tot_len;
}

const uint8_t *pointA[] = {
    NULL,
    (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
    (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE"
    (uint8_t *)"\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
    (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC",
    (uint8_t *)"\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
};

size_t asn1_cvc_public_key_ecdsa(mbedtls_ecdsa_context *ecdsa, uint8_t *buf, size_t buf_len) {
    const uint8_t oid_ecdsa[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03 };
    size_t p_size = mbedtls_mpi_size(&ecdsa->grp.P), a_size = mbedtls_mpi_size(&ecdsa->grp.A);
    size_t b_size = mbedtls_mpi_size(&ecdsa->grp.B), g_size = 1+mbedtls_mpi_size(&ecdsa->grp.G.X)+mbedtls_mpi_size(&ecdsa->grp.G.X);
    size_t o_size = mbedtls_mpi_size(&ecdsa->grp.N), y_size = 1+mbedtls_mpi_size(&ecdsa->Q.X)+mbedtls_mpi_size(&ecdsa->Q.X);
    size_t c_size = 1;
    size_t ptot_size = asn1_len_tag(0x81, p_size), atot_size = asn1_len_tag(0x82, a_size ? a_size : (pointA[ecdsa->grp.id] ? p_size : 0));
    size_t btot_size = asn1_len_tag(0x83, b_size), gtot_size = asn1_len_tag(0x84, g_size);
    size_t otot_size = asn1_len_tag(0x85, o_size), ytot_size = asn1_len_tag(0x86, y_size);
    size_t ctot_size = asn1_len_tag(0x87, c_size);
    size_t oid_len = asn1_len_tag(0x6, sizeof(oid_ecdsa));
    size_t tot_len = asn1_len_tag(0x7f49, oid_len+ptot_size+atot_size+btot_size+gtot_size+otot_size+ytot_size+ctot_size);
    if (buf == NULL || buf_len == 0)
        return tot_len;
    if (buf_len < tot_len)
        return 0;
    uint8_t *p = buf;
    memcpy(p, "\x7f\x49", 2); p += 2;
    p += format_tlv_len(oid_len+ptot_size+atot_size+btot_size+gtot_size+otot_size+ytot_size+ctot_size, p);
    //oid
    *p++ = 0x6; p += format_tlv_len(sizeof(oid_ecdsa), p); memcpy(p, oid_ecdsa, sizeof(oid_ecdsa)); p += sizeof(oid_ecdsa);
    //p
    *p++ = 0x81; p += format_tlv_len(p_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.P, p, p_size); p += p_size;
    //A
    if (a_size) {
        *p++ = 0x82; p += format_tlv_len(a_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.A, p, a_size); p += a_size;
    }
    else { //mbedtls does not set point A for some curves
        if (pointA[ecdsa->grp.id]) {
            *p++ = 0x82; p += format_tlv_len(p_size, p); memcpy(p, pointA[ecdsa->grp.id], p_size); p += p_size;
        }
        else {
            *p++ = 0x82; p += format_tlv_len(0, p);
        }
    }
    //B
    *p++ = 0x83; p += format_tlv_len(b_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.B, p, b_size); p += b_size;
    //G
    size_t g_new_size = 0;
    *p++ = 0x84; p += format_tlv_len(g_size, p); mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &g_new_size, p, g_size); p += g_size;
    //order
    *p++ = 0x85; p += format_tlv_len(o_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.N, p, o_size); p += o_size;
    //Y
    size_t y_new_size = 0;
    *p++ = 0x86; p += format_tlv_len(y_size, p); mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &y_new_size, p, y_size); p += y_size;
    //cofactor
    *p++ = 0x87; p += format_tlv_len(c_size, p); *p++ = 1;
    return tot_len;
}

size_t asn1_cvc_cert_body(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len) {
    size_t pubkey_size = 0;
    if (key_type == HSM_KEY_RSA)
        pubkey_size = asn1_cvc_public_key_rsa(rsa_ecdsa, NULL, 0);
    else if (key_type == HSM_KEY_EC)
        pubkey_size = asn1_cvc_public_key_ecdsa(rsa_ecdsa, NULL, 0);
    size_t cpi_size = 4;
    
    uint8_t *car = NULL, *chr = NULL;
    size_t lencar = 0, lenchr = 0;
    
    if (asn1_find_tag(apdu.data, apdu.nc, 0x42, &lencar, &car) == false || lencar == 0 || car == NULL) {
        car = (uint8_t *)"UTSRCACC100001";
        lencar = strlen((char *)car);
    }
    if (asn1_find_tag(apdu.data, apdu.nc, 0x5f20, &lenchr, &chr) == false || lenchr == 0 || chr == NULL) {
        chr = (uint8_t *)"ESHSMCVCA00001";
        lenchr = strlen((char *)chr);
    }
    size_t car_size = asn1_len_tag(0x42, lencar), chr_size = asn1_len_tag(0x5f20, lenchr);
    
    size_t tot_len = asn1_len_tag(0x7f4e, cpi_size+car_size+pubkey_size+chr_size);
    
    if (buf_len == 0 || buf == NULL)
        return tot_len;
    if (buf_len < tot_len)
        return 0;
    uint8_t *p = buf;
    memcpy(p, "\x7f\x4e", 2); p += 2;
    p += format_tlv_len(cpi_size+car_size+pubkey_size+chr_size, p);
    //cpi
    *p++ = 0x5f; *p++ = 0x29; *p++ = 1; *p++ = 0;
    //car
    *p++ = 0x42; p += format_tlv_len(lencar, p); memcpy(p, car, lencar); p += lencar;
    //pubkey
    if (key_type == HSM_KEY_RSA)
        p += asn1_cvc_public_key_rsa(rsa_ecdsa, p, pubkey_size);
    else if (key_type == HSM_KEY_EC)
        p += asn1_cvc_public_key_ecdsa(rsa_ecdsa, p, pubkey_size);
    //chr
    *p++ = 0x5f; *p++ = 0x20; p += format_tlv_len(lenchr, p); memcpy(p, chr, lenchr); p += lenchr;
    return tot_len;
}

size_t asn1_cvc_cert(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len) {
    size_t key_size = 0;
    if (key_type == HSM_KEY_RSA)
        key_size = mbedtls_mpi_size(&((mbedtls_rsa_context *)rsa_ecdsa)->N);
    else if (key_type == HSM_KEY_EC)
        key_size = 2*mbedtls_mpi_size(&((mbedtls_ecdsa_context *)rsa_ecdsa)->d);
    size_t body_size = asn1_cvc_cert_body(rsa_ecdsa, key_type, NULL, 0), sig_size = asn1_len_tag(0x5f37, key_size);
    size_t tot_len = asn1_len_tag(0x7f21, body_size+sig_size);
    if (buf_len == 0 || buf == NULL)
        return tot_len;
    if (buf_len < tot_len)
        return 0;
    uint8_t *p = buf, *body = NULL;
    memcpy(p, "\x7f\x21", 2); p += 2;
    p += format_tlv_len(body_size+sig_size, p);
    body = p;
    p += asn1_cvc_cert_body(rsa_ecdsa, key_type, p, body_size);
    
    uint8_t hsh[32];
    hash256(body, body_size, hsh);
    memcpy(p, "\x5f\x37", 2); p += 2;
    p += format_tlv_len(key_size, p);
    if (key_type == HSM_KEY_RSA) {
        if (mbedtls_rsa_rsassa_pkcs1_v15_sign(rsa_ecdsa, random_gen, NULL, MBEDTLS_MD_SHA256, 32, hsh, p) != 0)
            return 0;
        p += key_size;
    }
    else if (key_type == HSM_KEY_EC) {
        mbedtls_mpi r, s;
        int ret = 0;
        mbedtls_ecdsa_context *ecdsa = (mbedtls_ecdsa_context *)rsa_ecdsa;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        ret = mbedtls_ecdsa_sign(&ecdsa->grp, &r, &s, &ecdsa->d, hsh, sizeof(hsh), random_gen, NULL);
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            return 0;
        }
        mbedtls_mpi_write_binary(&r, p, mbedtls_mpi_size(&r)); p += mbedtls_mpi_size(&r);
        mbedtls_mpi_write_binary(&s, p, mbedtls_mpi_size(&s)); p += mbedtls_mpi_size(&s);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    }
    return p-buf;
}

size_t asn1_cvc_aut(void *rsa_ecdsa, uint8_t key_type, uint8_t *buf, size_t buf_len) {
    size_t cvcert_size = asn1_cvc_cert(rsa_ecdsa, key_type, NULL, 0);
    uint8_t *outcar = (uint8_t *)"ESHSM00001";
    size_t lenoutcar = strlen((char *)outcar), outcar_size = asn1_len_tag(0x42, lenoutcar);
    int key_size = 2*file_read_uint16(termca_pk), ret = 0;
    size_t outsig_size = asn1_len_tag(0x5f37, key_size), tot_len = asn1_len_tag(0x67, cvcert_size+outcar_size+outsig_size);
    if (buf_len == 0 || buf == NULL)
        return tot_len;
    if (buf_len < tot_len)
        return 0;
    uint8_t *p = buf;
    *p++ = 0x67;
    p += format_tlv_len(cvcert_size+outcar_size+outsig_size, p);
    uint8_t *body = p;
    //cvcert
    p += asn1_cvc_cert(rsa_ecdsa, key_type, p, cvcert_size);
    //outcar
    *p++ = 0x42; p += format_tlv_len(lenoutcar, p); memcpy(p, outcar, lenoutcar); p += lenoutcar;
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP192R1, &ctx, termca_pk+2, file_read_uint16(termca_pk)) != 0)
        return 0;
    uint8_t hsh[32];
    memcpy(p, "\x5f\x37", 2); p += 2;
    p += format_tlv_len(key_size, p);
    hash256(body, cvcert_size+outcar_size, hsh);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = mbedtls_ecdsa_sign(&ctx.grp, &r, &s, &ctx.d, hsh, sizeof(hsh), random_gen, NULL);
    mbedtls_ecdsa_free(&ctx);
    if (ret != 0) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return 0;
    }
    mbedtls_mpi_write_binary(&r, p, mbedtls_mpi_size(&r)); p += mbedtls_mpi_size(&r);
    mbedtls_mpi_write_binary(&s, p, mbedtls_mpi_size(&s)); p += mbedtls_mpi_size(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return p-buf;
}
