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
#include "cvc.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include <string.h>
#include "asn1.h"
#include "crypto_utils.h"
#include "random.h"
#include "oid.h"
#include "mbedtls/md.h"
#include "files.h"
#include "mbedtls/eddsa.h"

extern const uint8_t *dev_name;
extern uint16_t dev_name_len;

uint16_t asn1_cvc_public_key_rsa(mbedtls_rsa_context *rsa, uint8_t *buf, uint16_t buf_len) {
    const uint8_t oid_rsa[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02 };
    uint16_t n_size = (uint16_t)mbedtls_mpi_size(&rsa->N), e_size = (uint16_t)mbedtls_mpi_size(&rsa->E);
    uint16_t ntot_size = asn1_len_tag(0x81, n_size), etot_size = asn1_len_tag(0x82, e_size);
    uint16_t oid_len = asn1_len_tag(0x6, sizeof(oid_rsa));
    uint16_t tot_len = asn1_len_tag(0x7f49, oid_len + ntot_size + etot_size);
    if (buf == NULL || buf_len == 0) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    memcpy(p, "\x7F\x49", 2); p += 2;
    p += format_tlv_len(oid_len + ntot_size + etot_size, p);
    //oid
    *p++ = 0x6; p += format_tlv_len(sizeof(oid_rsa), p); memcpy(p, oid_rsa, sizeof(oid_rsa));
    p += sizeof(oid_rsa);
    //n
    *p++ = 0x81; p += format_tlv_len(n_size, p); mbedtls_mpi_write_binary(&rsa->N, p, n_size);
    p += n_size;
    //n
    *p++ = 0x82; p += format_tlv_len(e_size, p); mbedtls_mpi_write_binary(&rsa->E, p, e_size);
    p += e_size;
    return tot_len;
}

const uint8_t *pointA[] = {
    NULL,
    (uint8_t *)
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
    (uint8_t *)
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE",
    (uint8_t *)
    "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
    (uint8_t *)
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC",
    (uint8_t *)
    "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC",
};

uint16_t asn1_cvc_public_key_ecdsa(mbedtls_ecp_keypair *ecdsa, uint8_t *buf, uint16_t buf_len) {
    uint8_t Y_buf[MBEDTLS_ECP_MAX_PT_LEN], G_buf[MBEDTLS_ECP_MAX_PT_LEN];
    const uint8_t oid_ecdsa[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03 };
    const uint8_t oid_ri[]    = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x05, 0x02, 0x03 };
    const uint8_t *oid = oid_ecdsa;
    size_t p_size = mbedtls_mpi_size(&ecdsa->grp.P), a_size = mbedtls_mpi_size(&ecdsa->grp.A);
    size_t b_size = mbedtls_mpi_size(&ecdsa->grp.B), g_size = 0;
    size_t o_size = mbedtls_mpi_size(&ecdsa->grp.N), y_size = 0;
    mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->grp.G, MBEDTLS_ECP_PF_UNCOMPRESSED, &g_size, G_buf, sizeof(G_buf));
    mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &y_size, Y_buf, sizeof(Y_buf));
    uint16_t c_size = 1;
    uint16_t ptot_size = asn1_len_tag(0x81, (uint16_t)p_size), atot_size = asn1_len_tag(0x82, a_size ? (uint16_t)a_size : (pointA[ecdsa->grp.id] && ecdsa->grp.id < 6 ? (uint16_t)p_size : 1));
    uint16_t btot_size = asn1_len_tag(0x83, (uint16_t)b_size), gtot_size = asn1_len_tag(0x84, (uint16_t)g_size);
    uint16_t otot_size = asn1_len_tag(0x85, (uint16_t)o_size), ytot_size = asn1_len_tag(0x86, (uint16_t)y_size);
    uint16_t ctot_size = asn1_len_tag(0x87, (uint16_t)c_size);
    uint16_t oid_len = asn1_len_tag(0x6, sizeof(oid_ecdsa));
    uint16_t tot_len = 0, tot_data_len = 0;
    if (mbedtls_ecp_get_type(&ecdsa->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY || mbedtls_ecp_get_type(&ecdsa->grp) == MBEDTLS_ECP_TYPE_EDWARDS) {
        tot_data_len = oid_len + ptot_size + otot_size + gtot_size + ytot_size;
        oid = oid_ri;
    }
    else {
        tot_data_len = oid_len + ptot_size + atot_size + btot_size + gtot_size + otot_size + ytot_size +
                                  ctot_size;
    }
    tot_len = asn1_len_tag(0x7f49, tot_data_len);
    if (buf == NULL || buf_len == 0) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    memcpy(p, "\x7F\x49", 2); p += 2;
    p += format_tlv_len(tot_data_len, p);
    //oid
    *p++ = 0x6; p += format_tlv_len(sizeof(oid_ecdsa), p); memcpy(p, oid, sizeof(oid_ecdsa));
    p += sizeof(oid_ecdsa);
    if (mbedtls_ecp_get_type(&ecdsa->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY || mbedtls_ecp_get_type(&ecdsa->grp) == MBEDTLS_ECP_TYPE_EDWARDS) {
        //p
        *p++ = 0x81; p += format_tlv_len((uint16_t)p_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.P, p, p_size);
        p += p_size;
        //order
        *p++ = 0x82; p += format_tlv_len((uint16_t)o_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.N, p, o_size);
        p += o_size;
         //G
        *p++ = 0x83; p += format_tlv_len((uint16_t)g_size, p); memcpy(p, G_buf, g_size); p += g_size;
        //Y
        *p++ = 0x84; p += format_tlv_len((uint16_t)y_size, p); memcpy(p, Y_buf, y_size); p += y_size;
    }
    else {
        //p
        *p++ = 0x81; p += format_tlv_len((uint16_t)p_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.P, p, p_size);
        p += p_size;
        //A
        if (a_size) {
            *p++ = 0x82; p += format_tlv_len((uint16_t)a_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.A, p, a_size); p += a_size;
        }
        else {   //mbedtls does not set point A for some curves
            if (pointA[ecdsa->grp.id] && ecdsa->grp.id < 6) {
                *p++ = 0x82; p += format_tlv_len((uint16_t)p_size, p); memcpy(p, pointA[ecdsa->grp.id], p_size);
                p += p_size;
            }
            else {
                *p++ = 0x82; p += format_tlv_len(1, p);
                *p++ = 0x0;
            }
        }
        //B
        *p++ = 0x83; p += format_tlv_len((uint16_t)b_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.B, p, b_size);
        p += b_size;
        //G
        *p++ = 0x84; p += format_tlv_len((uint16_t)g_size, p); memcpy(p, G_buf, g_size); p += g_size;
        //order
        *p++ = 0x85; p += format_tlv_len((uint16_t)o_size, p); mbedtls_mpi_write_binary(&ecdsa->grp.N, p, o_size);
        p += o_size;
        //Y
        *p++ = 0x86; p += format_tlv_len((uint16_t)y_size, p); memcpy(p, Y_buf, y_size); p += y_size;
        //cofactor
        *p++ = 0x87; p += format_tlv_len(c_size, p);
        *p++ = 1;
    }
    return tot_len;
}

uint16_t asn1_cvc_cert_body(void *rsa_ecdsa,
                          uint8_t key_type,
                          uint8_t *buf,
                          uint16_t buf_len,
                          const uint8_t *ext,
                          uint16_t ext_len,
                          bool full) {
    uint16_t pubkey_size = 0;
    if (key_type & PICO_KEYS_KEY_RSA) {
        pubkey_size = asn1_cvc_public_key_rsa(rsa_ecdsa, NULL, 0);
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        pubkey_size = asn1_cvc_public_key_ecdsa(rsa_ecdsa, NULL, 0);
    }
    uint16_t cpi_size = 4, ext_size = 0, role_size = 0, valid_size = 0;
    if (ext && ext_len > 0) {
        ext_size = asn1_len_tag(0x65, ext_len);
    }
    const uint8_t *role = (const uint8_t *)"\x06\x09\x04\x00\x7F\x00\x07\x03\x01\x02\x02\x53\x01\x00";
    uint16_t rolelen = 14;
    if (full) {
        role_size = asn1_len_tag(0x7f4c, rolelen);
        valid_size = asn1_len_tag(0x5f24, 6) + asn1_len_tag(0x5f25, 6);
    }

    asn1_ctx_t ctxi, car = {0}, chr = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (asn1_find_tag(&ctxi, 0x42, &car) == false || asn1_len(&car) == 0) {
        car.data = (uint8_t *) dev_name;
        car.len = dev_name_len;
        if (dev_name == NULL) {
            car.data = (uint8_t *)"ESPICOHSMTR00001";
            car.len = (uint16_t)strlen((const char *)car.data);
        }
    }
    if (asn1_find_tag(&ctxi, 0x5f20, &chr) == false || asn1_len(&chr) == 0) {
        chr.data = (uint8_t *) dev_name;
        chr.len = dev_name_len;
        if (chr.data == NULL) {
            chr.data = car.data;
            chr.len = car.len;
        }
    }
    uint16_t car_size = asn1_len_tag(0x42, car.len), chr_size = asn1_len_tag(0x5f20, chr.len);

    uint16_t tot_len = asn1_len_tag(0x7f4e, cpi_size + car_size + pubkey_size + chr_size + ext_size + role_size + valid_size);

    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    memcpy(p, "\x7F\x4E", 2); p += 2;
    p += format_tlv_len(cpi_size + car_size + pubkey_size + chr_size + role_size + valid_size + ext_size, p);
    //cpi
    *p++ = 0x5f; *p++ = 0x29; *p++ = 1; *p++ = 0;
    //car
    *p++ = 0x42; p += format_tlv_len(car.len, p); memcpy(p, car.data, car.len); p += car.len;
    //pubkey
    if (key_type & PICO_KEYS_KEY_RSA) {
        p += asn1_cvc_public_key_rsa(rsa_ecdsa, p, pubkey_size);
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        p += asn1_cvc_public_key_ecdsa(rsa_ecdsa, p, pubkey_size);
    }
    //chr
    *p++ = 0x5f; *p++ = 0x20; p += format_tlv_len(chr.len, p); memcpy(p, chr.data, chr.len); p += chr.len;
    if (full) {
        *p++ = 0x7f;
        *p++ = 0x4c;
        p += format_tlv_len(rolelen, p);
        memcpy(p, role, rolelen);
        p += rolelen;

        *p++ = 0x5f;
        *p++ = 0x25;
        p += format_tlv_len(6, p);
        memcpy(p, "\x02\x03\x00\x03\x02\x01", 6);
        p += 6;

        *p++ = 0x5f;
        *p++ = 0x24;
        p += format_tlv_len(6, p);
        memcpy(p, "\x07\x00\x01\x02\x03\x01", 6);
        p += 6;
    }
    if (ext && ext_len > 0) {
        *p++ = 0x65;
        p += format_tlv_len(ext_len, p);
        memcpy(p, ext, ext_len);
        p += ext_len;
    }
    return tot_len;
}

uint16_t asn1_cvc_cert(void *rsa_ecdsa,
                     uint8_t key_type,
                     uint8_t *buf,
                     uint16_t buf_len,
                     const uint8_t *ext,
                     uint16_t ext_len,
                     bool full) {
    uint16_t key_size = 0;
    if (key_type & PICO_KEYS_KEY_RSA) {
        key_size = (uint16_t)mbedtls_mpi_size(&((mbedtls_rsa_context *) rsa_ecdsa)->N);
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        key_size = 2 * (int)((mbedtls_ecp_curve_info_from_grp_id(((mbedtls_ecdsa_context *) rsa_ecdsa)->grp.id)->bit_size + 7) / 8);
    }
    uint16_t body_size = asn1_cvc_cert_body(rsa_ecdsa, key_type, NULL, 0, ext, ext_len, full), sig_size = asn1_len_tag(0x5f37, key_size);
    uint16_t tot_len = asn1_len_tag(0x7f21, body_size + sig_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf, *body = NULL;
    memcpy(p, "\x7F\x21", 2); p += 2;
    p += format_tlv_len(body_size + sig_size, p);
    body = p;
    p += asn1_cvc_cert_body(rsa_ecdsa, key_type, p, body_size, ext, ext_len, full);
    uint8_t hsh[32];
    hash256(body, body_size, hsh);
    memcpy(p, "\x5F\x37", 2); p += 2;
    p += format_tlv_len(key_size, p);
    if (key_type & PICO_KEYS_KEY_RSA) {
        if (mbedtls_rsa_rsassa_pkcs1_v15_sign(rsa_ecdsa, random_gen, NULL, MBEDTLS_MD_SHA256, 32, hsh, p) != 0) {
            memset(p, 0, key_size);
        }
        p += key_size;
    }
    else if (key_type & PICO_KEYS_KEY_EC) {
        mbedtls_mpi r, s;
        int ret = 0;
        mbedtls_ecp_keypair *ecdsa = (mbedtls_ecp_keypair *) rsa_ecdsa;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        if (ecdsa->grp.id == MBEDTLS_ECP_DP_ED25519 || ecdsa->grp.id == MBEDTLS_ECP_DP_ED448) {
            ret = mbedtls_eddsa_sign(&ecdsa->grp, &r, &s, &ecdsa->d, body, body_size, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
        }
        else {
            ret = mbedtls_ecdsa_sign(&ecdsa->grp, &r, &s, &ecdsa->d, hsh, sizeof(hsh), random_gen, NULL);
        }
        if (ret == 0) {
            mbedtls_mpi_write_binary(&r, p, key_size / 2); p += key_size / 2;
            mbedtls_mpi_write_binary(&s, p, key_size / 2); p += key_size / 2;
        }
        else {
            memset(p, 0, key_size);
            p += key_size;
        }
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    }
    return (uint16_t)(p - buf);
}

uint16_t asn1_cvc_aut(void *rsa_ecdsa,
                    uint8_t key_type,
                    uint8_t *buf,
                    uint16_t buf_len,
                    const uint8_t *ext,
                    uint16_t ext_len) {
    uint16_t cvcert_size = asn1_cvc_cert(rsa_ecdsa, key_type, NULL, 0, ext, ext_len, false);
    uint16_t outcar_len = dev_name_len;
    const uint8_t *outcar = dev_name;
    uint16_t outcar_size = asn1_len_tag(0x42, outcar_len);
    file_t *fkey = search_file(EF_KEY_DEV);
    if (!fkey) {
        return 0;
    }
    mbedtls_ecp_keypair ectx;
    mbedtls_ecp_keypair_init(&ectx);
    if (load_private_key_ec(&ectx, fkey) != PICOKEY_OK) {
        mbedtls_ecp_keypair_free(&ectx);
        return 0;
    }
    int ret = 0;
    uint16_t key_size = 2 * (uint16_t)mbedtls_mpi_size(&ectx.d);
    uint16_t outsig_size = asn1_len_tag(0x5f37, key_size), tot_len = asn1_len_tag(0x67, cvcert_size + outcar_size + outsig_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    *p++ = 0x67;
    p += format_tlv_len(cvcert_size + outcar_size + outsig_size, p);
    uint8_t *body = p;
    //cvcert
    p += asn1_cvc_cert(rsa_ecdsa, key_type, p, cvcert_size, ext, ext_len, false);
    //outcar
    *p++ = 0x42; p += format_tlv_len(outcar_len, p); memcpy(p, outcar, outcar_len); p += outcar_len;
    memcpy(p, "\x5f\x37", 2); p += 2;
    p += format_tlv_len(key_size, p);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (ectx.grp.id == MBEDTLS_ECP_DP_ED25519 || ectx.grp.id == MBEDTLS_ECP_DP_ED448) {
        ret = mbedtls_eddsa_sign(&ectx.grp, &r, &s, &ectx.d, body, cvcert_size + outcar_size, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
    }
    else {
        uint8_t hsh[32];
        hash256(body, cvcert_size + outcar_size, hsh);
        ret = mbedtls_ecdsa_sign(&ectx.grp, &r, &s, &ectx.d, hsh, sizeof(hsh), random_gen, NULL);
    }
    mbedtls_ecp_keypair_free(&ectx);
    if (ret != 0) {
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return 0;
    }
    mbedtls_mpi_write_binary(&r, p, key_size / 2); p += key_size / 2;
    mbedtls_mpi_write_binary(&s, p, key_size / 2); p += key_size / 2;
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return (uint16_t)(p - buf);
}

uint16_t asn1_build_cert_description(const uint8_t *label,
                                   uint16_t label_len,
                                   const uint8_t *puk,
                                   uint16_t puk_len,
                                   uint16_t fid,
                                   uint8_t *buf,
                                   uint16_t buf_len) {
    uint16_t opt_len = 2;
    uint16_t seq1_size =
        asn1_len_tag(0x30, asn1_len_tag(0xC, label_len) + asn1_len_tag(0x3, opt_len));
    uint16_t seq2_size = asn1_len_tag(0x30, asn1_len_tag(0x4, 20)); /* SHA1 is 20 bytes length */
    uint16_t seq3_size =
        asn1_len_tag(0xA1,
                     asn1_len_tag(0x30, asn1_len_tag(0x30, asn1_len_tag(0x4, sizeof(uint16_t)))));
    uint16_t tot_len = asn1_len_tag(0x30, seq1_size + seq2_size + seq3_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    *p++ = 0x30;
    p += format_tlv_len(seq1_size + seq2_size + seq3_size, p);
    //Seq 1
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0xC, label_len) + asn1_len_tag(0x3, opt_len), p);
    *p++ = 0xC;
    p += format_tlv_len(label_len, p);
    memcpy(p, label, label_len); p += label_len;
    *p++ = 0x3;
    p += format_tlv_len(opt_len, p);
    memcpy(p, "\x06\x40", 2); p += 2;

    //Seq 2
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0x4, 20), p);
    *p++ = 0x4;
    p += format_tlv_len(20, p);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), puk, puk_len, p);  p += 20;

    //Seq 3
    *p++ = 0xA1;
    p += format_tlv_len(asn1_len_tag(0x30, asn1_len_tag(0x30, asn1_len_tag(0x4, sizeof(uint16_t)))),
                        p);
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0x30, asn1_len_tag(0x4, sizeof(uint16_t))), p);
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0x4, sizeof(uint16_t)), p);
    *p++ = 0x4;
    p += format_tlv_len(sizeof(uint16_t), p);
    put_uint16_t_be(fid, p); p += sizeof(uint16_t);
    return (uint16_t)(p - buf);
}

uint16_t asn1_build_prkd_generic(const uint8_t *label,
                               uint16_t label_len,
                               const uint8_t *keyid,
                               uint16_t keyid_len,
                               uint16_t keysize,
                               int key_type,
                               uint8_t *buf,
                               uint16_t buf_len) {
    uint16_t seq_len = 0;
    const uint8_t *seq = NULL;
    uint8_t first_tag = 0x0;
    if (key_type & PICO_KEYS_KEY_EC) {
        seq = (const uint8_t *)"\x07\x20\x80";
        seq_len = 3;
        first_tag = 0xA0;
    }
    else if (key_type & PICO_KEYS_KEY_RSA) {
        seq = (const uint8_t *)"\x02\x74";
        seq_len = 2;
        first_tag = 0x30;
    }
    else if (key_type & PICO_KEYS_KEY_AES) {
        seq = (const uint8_t *)"\x07\xC0\x10";
        seq_len = 3;
        first_tag = 0xA8;
    }
    uint16_t seq1_size = asn1_len_tag(0x30, asn1_len_tag(0xC, label_len));
    uint16_t seq2_size =
        asn1_len_tag(0x30, asn1_len_tag(0x4, keyid_len) + asn1_len_tag(0x3, seq_len));
    uint16_t seq3_size = 0, seq4_size = 0;
    if (key_type & PICO_KEYS_KEY_EC || key_type & PICO_KEYS_KEY_RSA) {
        seq4_size = asn1_len_tag(0xA1, asn1_len_tag(0x30, asn1_len_tag(0x30, asn1_len_tag(0x4, 0)) + asn1_len_tag(0x2, 2)));
    }
    else if (key_type & PICO_KEYS_KEY_AES) {
        seq3_size = asn1_len_tag(0xA0, asn1_len_tag(0x30, asn1_len_tag(0x2, 2)));
        seq4_size = asn1_len_tag(0xA1, asn1_len_tag(0x30, asn1_len_tag(0x30, asn1_len_tag(0x4, 0))));
    }
    uint16_t tot_len = asn1_len_tag(first_tag, seq1_size + seq2_size + seq4_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    *p++ = first_tag;
    p += format_tlv_len(seq1_size + seq2_size + seq3_size + seq4_size, p);
    //Seq 1
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0xC, label_len), p);
    *p++ = 0xC;
    p += format_tlv_len(label_len, p);
    memcpy(p, label, label_len); p += label_len;

    //Seq 2
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0x4, keyid_len) + asn1_len_tag(0x3, seq_len), p);
    *p++ = 0x4;
    p += format_tlv_len(keyid_len, p);
    memcpy(p, keyid, keyid_len); p += keyid_len;
    *p++ = 0x3;
    p += format_tlv_len(seq_len, p);
    memcpy(p, seq, seq_len); p += seq_len;

    //Seq 3
    if (key_type & PICO_KEYS_KEY_AES) {
        *p++ = 0xA0;
        p += format_tlv_len(asn1_len_tag(0x30, asn1_len_tag(0x2, 2)), p);
        *p++ = 0x30;
        p += format_tlv_len(asn1_len_tag(0x2, 2), p);
        *p++ = 0x2;
        p += format_tlv_len(2, p);
        p += put_uint16_t_be(keysize, p);
    }

    //Seq 4
    *p++ = 0xA1;
    uint16_t inseq4_len = asn1_len_tag(0x30, asn1_len_tag(0x4, 0));
    if (key_type & PICO_KEYS_KEY_EC || key_type & PICO_KEYS_KEY_RSA) {
        inseq4_len += asn1_len_tag(0x2, 2);
    }
    p += format_tlv_len(asn1_len_tag(0x30, inseq4_len), p);
    *p++ = 0x30;
    p += format_tlv_len(inseq4_len, p);
    *p++ = 0x30;
    p += format_tlv_len(asn1_len_tag(0x4, 0), p);
    *p++ = 0x4;
    p += format_tlv_len(0, p);
    if (key_type & PICO_KEYS_KEY_EC || key_type & PICO_KEYS_KEY_RSA) {
        *p++ = 0x2;
        p += format_tlv_len(2, p);
        p += put_uint16_t_be(keysize, p);
    }
    return (uint16_t)(p - buf);
}

uint16_t asn1_build_prkd_ecc(const uint8_t *label,
                           uint16_t label_len,
                           const uint8_t *keyid,
                           uint16_t keyid_len,
                           uint16_t keysize,
                           uint8_t *buf,
                           uint16_t buf_len) {
    return asn1_build_prkd_generic(label,
                                   label_len,
                                   keyid,
                                   keyid_len,
                                   keysize,
                                   PICO_KEYS_KEY_EC,
                                   buf,
                                   buf_len);
}

uint16_t asn1_build_prkd_rsa(const uint8_t *label,
                           uint16_t label_len,
                           const uint8_t *keyid,
                           uint16_t keyid_len,
                           uint16_t keysize,
                           uint8_t *buf,
                           uint16_t buf_len) {
    return asn1_build_prkd_generic(label,
                                   label_len,
                                   keyid,
                                   keyid_len,
                                   keysize,
                                   PICO_KEYS_KEY_RSA,
                                   buf,
                                   buf_len);
}

uint16_t asn1_build_prkd_aes(const uint8_t *label,
                           uint16_t label_len,
                           const uint8_t *keyid,
                           uint16_t keyid_len,
                           uint16_t keysize,
                           uint8_t *buf,
                           uint16_t buf_len) {
    return asn1_build_prkd_generic(label,
                                   label_len,
                                   keyid,
                                   keyid_len,
                                   keysize,
                                   PICO_KEYS_KEY_AES,
                                   buf,
                                   buf_len);
}

const uint8_t *cvc_get_field(const uint8_t *data, uint16_t len, uint16_t *olen, uint16_t tag) {
    asn1_ctx_t ctxi, ctxo = { 0 };
    asn1_ctx_init((uint8_t *)data, len, &ctxi);
    if (asn1_len(&ctxi) == 0) {
        return NULL;
    }
    if (asn1_find_tag(&ctxi, tag, &ctxo) == false) {
        return NULL;
    }
    *olen = ctxo.len;
    return ctxo.data;
}

const uint8_t *cvc_get_body(const uint8_t *data, uint16_t len, uint16_t *olen) {
    const uint8_t *bkdata = data;
    if ((data = cvc_get_field(data, len, olen, 0x67)) == NULL) { /* Check for CSR */
        data = bkdata;
    }
    if ((data = cvc_get_field(data, len, olen, 0x7F21)) != NULL) {
        return cvc_get_field(data, len, olen, 0x7F4E);
    }
    return NULL;
}

const uint8_t *cvc_get_sig(const uint8_t *data, uint16_t len, uint16_t *olen) {
    const uint8_t *bkdata = data;
    if ((data = cvc_get_field(data, len, olen, 0x67)) == NULL) { /* Check for CSR */
        data = bkdata;
    }
    if ((data = cvc_get_field(data, len, olen, 0x7F21)) != NULL) {
        return cvc_get_field(data, len, olen, 0x5F37);
    }
    return NULL;
}

const uint8_t *cvc_get_car(const uint8_t *data, uint16_t len, uint16_t *olen) {
    if ((data = cvc_get_body(data, len, olen)) != NULL) {
        return cvc_get_field(data, len, olen, 0x42);
    }
    return NULL;
}

const uint8_t *cvc_get_chr(const uint8_t *data, uint16_t len, uint16_t *olen) {
    if ((data = cvc_get_body(data, len, olen)) != NULL) {
        return cvc_get_field(data, len, olen, 0x5F20);
    }
    return NULL;
}

const uint8_t *cvc_get_pub(const uint8_t *data, uint16_t len, uint16_t *olen) {
    if ((data = cvc_get_body(data, len, olen)) != NULL) {
        return cvc_get_field(data, len, olen, 0x7F49);
    }
    return NULL;
}

const uint8_t *cvc_get_ext(const uint8_t *data, uint16_t len, uint16_t *olen) {
    if ((data = cvc_get_body(data, len, olen)) != NULL) {
        return cvc_get_field(data, len, olen, 0x65);
    }
    return NULL;
}

extern PUK puk_store[MAX_PUK_STORE_ENTRIES];
extern int puk_store_entries;

int puk_store_index(const uint8_t *chr, uint16_t chr_len) {
    for (int i = 0; i < puk_store_entries; i++) {
        if (memcmp(puk_store[i].chr, chr, chr_len) == 0) {
            return i;
        }
    }
    return -1;
}

mbedtls_ecp_group_id cvc_inherite_ec_group(const uint8_t *ca, uint16_t ca_len) {
    uint16_t chr_len = 0, car_len = 0;
    const uint8_t *chr = NULL, *car = NULL;
    int eq = -1;
    do {
        chr = cvc_get_chr(ca, ca_len, &chr_len);
        car = cvc_get_car(ca, ca_len, &car_len);
        eq = memcmp(car, chr, MAX(car_len, chr_len));
        if (car && eq != 0) {
            int idx = puk_store_index(car, car_len);
            if (idx != -1) {
                ca = puk_store[idx].cvcert;
                ca_len = puk_store[idx].cvcert_len;
            }
            else {
                ca = NULL;
            }
        }
    } while (car && chr && eq != 0);
    uint16_t ca_puk_len = 0;
    const uint8_t *ca_puk = cvc_get_pub(ca, ca_len, &ca_puk_len);
    if (!ca_puk) {
        return MBEDTLS_ECP_DP_NONE;
    }
    uint16_t t81_len = 0;
    const uint8_t *t81 = cvc_get_field(ca_puk, ca_puk_len, &t81_len, 0x81);
    if (!t81) {
        return MBEDTLS_ECP_DP_NONE;
    }

    return ec_get_curve_from_prime(t81, t81_len);
}

int puk_verify(const uint8_t *sig,
               uint16_t sig_len,
               const uint8_t *hash,
               uint16_t hash_len,
               const uint8_t *ca,
               uint16_t ca_len) {
    uint16_t puk_len = 0;
    const uint8_t *puk = cvc_get_pub(ca, ca_len, &puk_len);
    if (!puk) {
        return PICOKEY_WRONG_DATA;
    }
    uint16_t oid_len = 0;
    const uint8_t *oid = cvc_get_field(puk, puk_len, &oid_len, 0x6);
    if (!oid) {
        return PICOKEY_WRONG_DATA;
    }
    if (memcmp(oid, OID_ID_TA_RSA, 9) == 0) { //RSA
        uint16_t t81_len = 0, t82_len = 0;
        const uint8_t *t81 = cvc_get_field(puk, puk_len, &t81_len, 0x81), *t82 = cvc_get_field(puk,
                                                                                               puk_len,
                                                                                               &t81_len,
                                                                                               0x82);
        if (!t81 || !t82) {
            return PICOKEY_WRONG_DATA;
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        mbedtls_md_type_t md = MBEDTLS_MD_NONE;
        if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
            mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
            mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
            mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
        }
        if (md == MBEDTLS_MD_NONE) {
            mbedtls_rsa_free(&rsa);
            return PICOKEY_WRONG_DATA;
        }
        int r = mbedtls_mpi_read_binary(&rsa.N, t81, t81_len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEY_EXEC_ERROR;
        }
        r = mbedtls_mpi_read_binary(&rsa.E, t82, t82_len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEY_EXEC_ERROR;
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEY_EXEC_ERROR;
        }
        r = mbedtls_rsa_check_pubkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEY_EXEC_ERROR;
        }
        r = mbedtls_rsa_pkcs1_verify(&rsa, md, (unsigned int)hash_len, hash, sig);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return PICOKEY_WRONG_SIGNATURE;
        }
    }
    else if (memcmp(oid, OID_ID_TA_ECDSA, 9) == 0) {   //ECC
        mbedtls_md_type_t md = MBEDTLS_MD_NONE;
        if (memcmp(oid, OID_ID_TA_ECDSA_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_224, oid_len) == 0) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_384, oid_len) == 0) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
        }
        if (md == MBEDTLS_MD_NONE) {
            return PICOKEY_WRONG_DATA;
        }

        uint16_t t86_len = 0;
        const uint8_t *t86 = cvc_get_field(puk, puk_len, &t86_len, 0x86);
        if (!t86) {
            return PICOKEY_WRONG_DATA;
        }
        mbedtls_ecp_group_id ec_id = cvc_inherite_ec_group(ca, ca_len);
        if (ec_id == MBEDTLS_ECP_DP_NONE) {
            return PICOKEY_WRONG_DATA;
        }
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int ret = mbedtls_ecp_group_load(&ecdsa.grp, ec_id);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEY_WRONG_DATA;
        }
        ret = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, t86, t86_len);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
        ret = mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        ret = mbedtls_mpi_read_binary(&r, sig, sig_len / 2);
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
        ret = mbedtls_mpi_read_binary(&s, sig + sig_len / 2, sig_len / 2);
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEY_EXEC_ERROR;
        }
        ret = mbedtls_ecdsa_verify(&ecdsa.grp, hash, hash_len, &ecdsa.Q, &r, &s);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ecdsa);
        if (ret != 0) {
            return PICOKEY_WRONG_SIGNATURE;
        }
    }
    return PICOKEY_OK;
}

int cvc_verify(const uint8_t *cert, uint16_t cert_len, const uint8_t *ca, uint16_t ca_len) {
    uint16_t puk_len = 0;
    const uint8_t *puk = cvc_get_pub(ca, ca_len, &puk_len);
    if (!puk) {
        return PICOKEY_WRONG_DATA;
    }
    uint16_t oid_len = 0, cv_body_len = 0, sig_len = 0;
    const uint8_t *oid = cvc_get_field(puk, puk_len, &oid_len, 0x6);
    const uint8_t *cv_body = cvc_get_body(cert, cert_len, &cv_body_len);
    const uint8_t *sig = cvc_get_sig(cert, cert_len, &sig_len);
    if (!sig) {
        return PICOKEY_WRONG_DATA;
    }
    if (!cv_body) {
        return PICOKEY_WRONG_DATA;
    }
    if (!oid) {
        return PICOKEY_WRONG_DATA;
    }
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    if (memcmp(oid, OID_ID_TA_RSA, 9) == 0) { //RSA
        if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_V1_5_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (memcmp(oid, OID_ID_TA_RSA_PSS_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
        }
    }
    else if (memcmp(oid, OID_ID_TA_ECDSA, 9) == 0) {   //ECC
        if (memcmp(oid, OID_ID_TA_ECDSA_SHA_1, oid_len) == 0) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_224, oid_len) == 0) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_256, oid_len) == 0) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_384, oid_len) == 0) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (memcmp(oid, OID_ID_TA_ECDSA_SHA_512, oid_len) == 0) {
            md = MBEDTLS_MD_SHA512;
        }
    }
    if (md == MBEDTLS_MD_NONE) {
        return PICOKEY_WRONG_DATA;
    }
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md);
    uint8_t hash[64], hash_len = mbedtls_md_get_size(md_info);
    uint8_t tlv_body = 2 + format_tlv_len(cv_body_len, NULL);
    int r = mbedtls_md(md_info, cv_body - tlv_body, cv_body_len + tlv_body, hash);
    if (r != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    r = puk_verify(sig, sig_len, hash, hash_len, ca, ca_len);
    if (r != 0) {
        return PICOKEY_WRONG_SIGNATURE;
    }
    return PICOKEY_OK;
}
