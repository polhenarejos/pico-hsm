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

#include "sc_hsm.h"
#include "cvc.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include <string.h>
#include "tlv.h"
#include "crypto_utils.h"
#include "random.h"
#include "oid.h"
#include "mbedtls/md.h"
#include "files.h"

static const uint8_t cvc_valid_from[] = { 0x02, 0x03, 0x00, 0x03, 0x02, 0x01 };
static const uint8_t cvc_valid_to[] = { 0x07, 0x00, 0x01, 0x02, 0x03, 0x01 };

static int cvc_configure_cert(cvc_write_cert *ctx, const mbedtls_pk_context *subject, bool full, const uint8_t *ext, uint16_t ext_len) {
    const uint8_t *car = NULL, *chr = NULL, *oid = NULL;
    uint16_t car_len = 0, chr_len = 0, oid_len = 0;
    bool allow_zero_signature_on_unsupported = false;

    if (!ctx || !subject) {
        return -1;
    }
    car = cvc_get_field(apdu.data, (uint16_t)apdu.nc, &car_len, 0x42);
    if (!car || !car_len) {
        car = dev_name ? dev_name : (const uint8_t *)"ESPICOHSMTR00001";
        car_len = dev_name ? dev_name_len : (uint16_t)strlen((const char *)car);
    }
    chr = cvc_get_field(apdu.data, (uint16_t)apdu.nc, &chr_len, 0x5F20);
    if (!chr || !chr_len) {
        chr = dev_name ? dev_name : car;
        chr_len = dev_name ? dev_name_len : car_len;
    }
    if (!car_len || !chr_len) {
        return -1;
    }

    if (cvc_default_algorithm_oid(subject, &oid, &oid_len) != LIBCVC_OK) {
        return -1;
    }
    if (mbedtls_pk_get_type((mbedtls_pk_context *)subject) != MBEDTLS_PK_RSA) {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*subject);
        mbedtls_ecp_curve_type curve_type;
        if (!ec) {
            return -1;
        }
        curve_type = mbedtls_ecp_get_type(&ec->grp);
        allow_zero_signature_on_unsupported = curve_type == MBEDTLS_ECP_TYPE_MONTGOMERY;
    }

    cvc_write_cert_init(ctx);
    if (cvc_write_set_subject_key(ctx, subject) != LIBCVC_OK || cvc_write_set_issuer_key(ctx, subject) != LIBCVC_OK || cvc_write_set_algorithm_oid(ctx, oid, oid_len) != LIBCVC_OK || cvc_write_set_md(ctx, MBEDTLS_MD_SHA256) != LIBCVC_OK || cvc_write_set_include_ec_domain_parameters(ctx, true) != LIBCVC_OK || cvc_write_set_allow_zero_signature_on_unsupported(ctx, allow_zero_signature_on_unsupported) != LIBCVC_OK || cvc_write_set_car(ctx, car, car_len) != LIBCVC_OK || cvc_write_set_chr(ctx, chr, chr_len) != LIBCVC_OK || cvc_write_set_extensions(ctx, ext, ext_len) != LIBCVC_OK || cvc_write_set_include_role_and_validity(ctx, full) != LIBCVC_OK) {
        return -1;
    }
    if (full && cvc_write_set_validity(ctx, cvc_valid_from, sizeof(cvc_valid_from), cvc_valid_to, sizeof(cvc_valid_to)) != LIBCVC_OK) {
        return -1;
    }
    return 0;
}

static uint16_t cvc_cert_size(const cvc_write_cert *ctx) {
    uint8_t pub_tmpl[768], body[1024], sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    uint16_t pub_tmpl_len, body_len;
    size_t sig_len;

    if (!ctx || !ctx->subject_pk || !ctx->alg_oid || !ctx->alg_oid_len) {
        return 0;
    }
    pub_tmpl_len = cvc_build_pubkey_template_ex(ctx->subject_pk, ctx->alg_oid, ctx->alg_oid_len, ctx->include_ec_domain_parameters, pub_tmpl, sizeof(pub_tmpl));
    if (!pub_tmpl_len) {
        return 0;
    }
    body_len = cvc_build_cert_body(&ctx->meta, pub_tmpl, pub_tmpl_len, body, sizeof(body));
    if (!body_len) {
        return 0;
    }
    sig_len = mbedtls_pk_get_len(ctx->issuer_pk);
    if (mbedtls_pk_get_type((mbedtls_pk_context *)ctx->issuer_pk) != MBEDTLS_PK_RSA) {
#if defined(MBEDTLS_EDDSA_C)
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*(mbedtls_pk_context *)ctx->issuer_pk);
        if (ec && mbedtls_ecp_get_type(&ec->MBEDTLS_PRIVATE(grp)) == MBEDTLS_ECP_TYPE_EDWARDS) {
            const mbedtls_ecp_curve_info *curve = mbedtls_ecp_curve_info_from_grp_id(ec->MBEDTLS_PRIVATE(grp).id);
            if (curve) {
                sig_len = (curve->bit_size + 7u) / 8u;
            }
        }
#endif
        sig_len *= 2;
    }
    if (!sig_len || sig_len > sizeof(sig)) {
        return 0;
    }
    return cvc_build_cert(body, body_len, sig, (uint16_t)sig_len, NULL, 0);
}

uint16_t asn1_cvc_cert(const mbedtls_pk_context *subject, uint8_t *buf, uint16_t buf_len, const uint8_t *ext, uint16_t ext_len, bool full) {
    cvc_write_cert ctx;
    uint16_t cert_len, out_len = 0;

    if (!subject || cvc_configure_cert(&ctx, subject, full, ext, ext_len) != 0) {
        return 0;
    }
    cert_len = cvc_cert_size(&ctx);
    if (!cert_len || !buf || !buf_len) {
        return cert_len;
    }
    if (buf_len < cert_len || cvc_write_cert_der(&ctx, buf, buf_len, &out_len, random_fill_iterator, NULL) != 0) {
        return 0;
    }
    return out_len;
}

uint16_t asn1_cvc_aut(const mbedtls_pk_context *subject, uint8_t *buf, uint16_t buf_len, const uint8_t *ext, uint16_t ext_len) {
    file_t *fkey = hsm_key_search(0);
    mbedtls_ecp_keypair device_key;
    mbedtls_pk_context outer;
    cvc_write_req ctx;
    uint16_t cert_len, request_len, out_len = 0;
    size_t outer_sig_len;
    uint8_t placeholder = 0;

    if (!subject || !fkey || !dev_name || !dev_name_len) {
        return 0;
    }
    mbedtls_ecp_keypair_init(&device_key);
    if (load_private_key_ec(&device_key, fkey, FILE_OBJECT_OPERATION_SIGN, true) != PICOKEYS_OK) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }
    if (cvc_pk_wrap_ec(&outer, &device_key) != LIBCVC_OK) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }
    cvc_write_req_init(&ctx);
    if (cvc_configure_cert(&ctx.cert, subject, false, ext, ext_len) != 0 || dev_name_len > sizeof(ctx.outer_car_buf)) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }
    if (cvc_req_set_outer_signing_key(&ctx, &outer) != LIBCVC_OK || cvc_req_set_outer_car(&ctx, dev_name, dev_name_len) != LIBCVC_OK) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }

    cert_len = cvc_cert_size(&ctx.cert);
    outer_sig_len = mbedtls_pk_get_len(&outer) * 2;
    if (!cert_len || !outer_sig_len || outer_sig_len > MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }
    request_len = cvc_build_request(&placeholder, cert_len, ctx.outer_car_buf, ctx.outer_car_len, &placeholder, (uint16_t)outer_sig_len, NULL, 0);
    if (!request_len || !buf || !buf_len) {
        mbedtls_ecp_keypair_free(&device_key);
        return request_len;
    }
    if (buf_len < request_len || cvc_write_req_der(&ctx, buf, buf_len, &out_len, random_fill_iterator, NULL) != 0) {
        mbedtls_ecp_keypair_free(&device_key);
        return 0;
    }
    mbedtls_ecp_keypair_free(&device_key);
    return out_len;
}

uint16_t asn1_build_cert_description(const uint8_t *label, uint16_t label_len, const uint8_t *puk, uint16_t puk_len, uint16_t fid, uint8_t *buf, uint16_t buf_len) {
    uint16_t opt_len = 2;
    uint16_t seq1_size = tlv_len_tag(0x30, tlv_len_tag(0xC, label_len) + tlv_len_tag(0x3, opt_len));
    uint16_t seq2_size = tlv_len_tag(0x30, tlv_len_tag(0x4, 20)); /* SHA1 is 20 bytes length */
    uint16_t seq3_size = tlv_len_tag(0xA1, tlv_len_tag(0x30, tlv_len_tag(0x30, tlv_len_tag(0x4, sizeof(uint16_t)))));
    uint16_t tot_len = tlv_len_tag(0x30, seq1_size + seq2_size + seq3_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    *p++ = 0x30;
    p += tlv_format_len(seq1_size + seq2_size + seq3_size, p);
    //Seq 1
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0xC, label_len) + tlv_len_tag(0x3, opt_len), p);
    *p++ = 0xC;
    p += tlv_format_len(label_len, p);
    memcpy(p, label, label_len); p += label_len;
    *p++ = 0x3;
    p += tlv_format_len(opt_len, p);
    memcpy(p, "\x06\x40", 2); p += 2;

    //Seq 2
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0x4, 20), p);
    *p++ = 0x4;
    p += tlv_format_len(20, p);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), puk, puk_len, p);  p += 20;

    //Seq 3
    *p++ = 0xA1;
    p += tlv_format_len(tlv_len_tag(0x30, tlv_len_tag(0x30, tlv_len_tag(0x4, sizeof(uint16_t)))),
                        p);
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0x30, tlv_len_tag(0x4, sizeof(uint16_t))), p);
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0x4, sizeof(uint16_t)), p);
    *p++ = 0x4;
    p += tlv_format_len(sizeof(uint16_t), p);
    put_uint16_be(fid, p); p += sizeof(uint16_t);
    return (uint16_t)(p - buf);
}

uint16_t asn1_build_prkd_generic(const uint8_t *label, uint16_t label_len, const uint8_t *keyid, uint16_t keyid_len, uint16_t keysize, int key_type, uint8_t *buf, uint16_t buf_len) {
    uint16_t seq_len = 0;
    const uint8_t *seq = NULL;
    uint8_t first_tag = 0x0;
    if (key_type & PICOKEYS_KEY_EC) {
        seq = (const uint8_t *)"\x07\x20\x80";
        seq_len = 3;
        first_tag = 0xA0;
    }
    else if (key_type & PICOKEYS_KEY_RSA) {
        seq = (const uint8_t *)"\x02\x74";
        seq_len = 2;
        first_tag = 0x30;
    }
    else if (key_type & PICOKEYS_KEY_AES) {
        seq = (const uint8_t *)"\x07\xC0\x10";
        seq_len = 3;
        first_tag = 0xA8;
    }
    uint16_t seq1_size = tlv_len_tag(0x30, tlv_len_tag(0xC, label_len));
    uint16_t seq2_size = tlv_len_tag(0x30, tlv_len_tag(0x4, keyid_len) + tlv_len_tag(0x3, seq_len));
    uint16_t seq3_size = 0, seq4_size = 0;
    if (key_type & PICOKEYS_KEY_EC || key_type & PICOKEYS_KEY_RSA) {
        seq4_size = tlv_len_tag(0xA1, tlv_len_tag(0x30, tlv_len_tag(0x30, tlv_len_tag(0x4, 0)) + tlv_len_tag(0x2, 2)));
    }
    else if (key_type & PICOKEYS_KEY_AES) {
        seq3_size = tlv_len_tag(0xA0, tlv_len_tag(0x30, tlv_len_tag(0x2, 2)));
        seq4_size = tlv_len_tag(0xA1, tlv_len_tag(0x30, tlv_len_tag(0x30, tlv_len_tag(0x4, 0))));
    }
    uint16_t tot_len = tlv_len_tag(first_tag, seq1_size + seq2_size + seq4_size);
    if (buf_len == 0 || buf == NULL) {
        return tot_len;
    }
    if (buf_len < tot_len) {
        return 0;
    }
    uint8_t *p = buf;
    *p++ = first_tag;
    p += tlv_format_len(seq1_size + seq2_size + seq3_size + seq4_size, p);
    //Seq 1
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0xC, label_len), p);
    *p++ = 0xC;
    p += tlv_format_len(label_len, p);
    memcpy(p, label, label_len); p += label_len;

    //Seq 2
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0x4, keyid_len) + tlv_len_tag(0x3, seq_len), p);
    *p++ = 0x4;
    p += tlv_format_len(keyid_len, p);
    memcpy(p, keyid, keyid_len); p += keyid_len;
    *p++ = 0x3;
    p += tlv_format_len(seq_len, p);
    memcpy(p, seq, seq_len); p += seq_len;

    //Seq 3
    if (key_type & PICOKEYS_KEY_AES) {
        *p++ = 0xA0;
        p += tlv_format_len(tlv_len_tag(0x30, tlv_len_tag(0x2, 2)), p);
        *p++ = 0x30;
        p += tlv_format_len(tlv_len_tag(0x2, 2), p);
        *p++ = 0x2;
        p += tlv_format_len(2, p);
        p += put_uint16_be(keysize, p);
    }

    //Seq 4
    *p++ = 0xA1;
    uint16_t inseq4_len = tlv_len_tag(0x30, tlv_len_tag(0x4, 0));
    if (key_type & PICOKEYS_KEY_EC || key_type & PICOKEYS_KEY_RSA) {
        inseq4_len += tlv_len_tag(0x2, 2);
    }
    p += tlv_format_len(tlv_len_tag(0x30, inseq4_len), p);
    *p++ = 0x30;
    p += tlv_format_len(inseq4_len, p);
    *p++ = 0x30;
    p += tlv_format_len(tlv_len_tag(0x4, 0), p);
    *p++ = 0x4;
    p += tlv_format_len(0, p);
    if (key_type & PICOKEYS_KEY_EC || key_type & PICOKEYS_KEY_RSA) {
        *p++ = 0x2;
        p += tlv_format_len(2, p);
        p += put_uint16_be(keysize, p);
    }
    return (uint16_t)(p - buf);
}

uint16_t asn1_build_prkd_ecc(const uint8_t *label, uint16_t label_len, const uint8_t *keyid, uint16_t keyid_len, uint16_t keysize, uint8_t *buf, uint16_t buf_len) {
    return asn1_build_prkd_generic(label, label_len, keyid, keyid_len, keysize, PICOKEYS_KEY_EC, buf, buf_len);
}

uint16_t asn1_build_prkd_rsa(const uint8_t *label, uint16_t label_len, const uint8_t *keyid, uint16_t keyid_len, uint16_t keysize, uint8_t *buf, uint16_t buf_len) {
    return asn1_build_prkd_generic(label, label_len, keyid, keyid_len, keysize, PICOKEYS_KEY_RSA, buf, buf_len);
}

uint16_t asn1_build_prkd_aes(const uint8_t *label, uint16_t label_len, const uint8_t *keyid, uint16_t keyid_len, uint16_t keysize, uint8_t *buf, uint16_t buf_len) {
    return asn1_build_prkd_generic(label, label_len, keyid, keyid_len, keysize, PICOKEYS_KEY_AES, buf, buf_len);
}

extern PUK puk_store[MAX_PUK_STORE_ENTRIES];
extern int puk_store_entries;

static int puk_store_index(const uint8_t *chr, uint16_t chr_len) {
    for (int i = 0; i < puk_store_entries; i++) {
        if (puk_store[i].chr && puk_store[i].chr_len == chr_len && memcmp(puk_store[i].chr, chr, chr_len) == 0) {
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
        eq = car_len == chr_len ? memcmp(car, chr, chr_len) : -1;
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

int puk_verify(const uint8_t *sig, uint16_t sig_len, const uint8_t *hash, uint16_t hash_len, const uint8_t *ca, uint16_t ca_len) {
    cvc_pubkey_t signer;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;

    if (cvc_extract_pubkey(ca, ca_len, &signer) != LIBCVC_OK || cvc_algorithm_oid_to_md(signer.alg_oid, signer.alg_oid_len, &md) != LIBCVC_OK) {
        return PICOKEYS_WRONG_DATA;
    }

    if (signer.kind == CVC_KEY_KIND_RSA) {
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        if (cvc_algorithm_oid_is_rsa_pss(signer.alg_oid, signer.alg_oid_len)) {
            mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
        }
        int r = mbedtls_mpi_read_binary(&rsa.N, signer.n, signer.n_len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEYS_EXEC_ERROR;
        }
        r = mbedtls_mpi_read_binary(&rsa.E, signer.e, signer.e_len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEYS_EXEC_ERROR;
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEYS_EXEC_ERROR;
        }
        r = mbedtls_rsa_check_pubkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return PICOKEYS_EXEC_ERROR;
        }
        r = mbedtls_rsa_pkcs1_verify(&rsa, md, (unsigned int)hash_len, hash, sig);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return PICOKEYS_WRONG_SIGNATURE;
        }
    }
    else if (signer.kind == CVC_KEY_KIND_EC) {
        mbedtls_ecp_group_id ec_id = cvc_inherite_ec_group(ca, ca_len);
        if (ec_id == MBEDTLS_ECP_DP_NONE) {
            return PICOKEYS_WRONG_DATA;
        }
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int ret = mbedtls_ecp_group_load(&ecdsa.grp, ec_id);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_WRONG_DATA;
        }
        ret = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, signer.q, signer.q_len);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_EXEC_ERROR;
        }
        ret = mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q);
        if (ret != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_EXEC_ERROR;
        }
        mbedtls_mpi r, s;
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        ret = mbedtls_mpi_read_binary(&r, sig, sig_len / 2);
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_EXEC_ERROR;
        }
        ret = mbedtls_mpi_read_binary(&s, sig + sig_len / 2, sig_len / 2);
        if (ret != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_EXEC_ERROR;
        }
        ret = mbedtls_ecdsa_verify(&ecdsa.grp, hash, hash_len, &ecdsa.Q, &r, &s);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ecdsa);
        if (ret != 0) {
            return PICOKEYS_WRONG_SIGNATURE;
        }
    }
    return PICOKEYS_OK;
}

int cvc_verify(const uint8_t *cert, uint16_t cert_len, const uint8_t *ca, uint16_t ca_len) {
    cvc_pubkey_t signer;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;

    if (cvc_extract_pubkey(ca, ca_len, &signer) != LIBCVC_OK || signer.alg_oid == NULL || signer.alg_oid_len == 0) {
        return PICOKEYS_WRONG_DATA;
    }

    if (cvc_algorithm_oid_to_md(signer.alg_oid, signer.alg_oid_len, &md) != LIBCVC_OK) {
        return PICOKEYS_WRONG_DATA;
    }

    if (signer.kind == CVC_KEY_KIND_RSA) {
        mbedtls_rsa_context rsa;
        mbedtls_pk_context signer_pk;
        int rc;

        mbedtls_rsa_init(&rsa);
        if (mbedtls_mpi_read_binary(&rsa.N, signer.n, signer.n_len) != 0 || mbedtls_mpi_read_binary(&rsa.E, signer.e, signer.e_len) != 0 || mbedtls_rsa_complete(&rsa) != 0 || mbedtls_rsa_check_pubkey(&rsa) != 0 || cvc_pk_wrap_rsa(&signer_pk, &rsa) != LIBCVC_OK) {
            mbedtls_rsa_free(&rsa);
            return PICOKEYS_WRONG_DATA;
        }
        if (cvc_algorithm_oid_is_rsa_pss(signer.alg_oid, signer.alg_oid_len)) {
            mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, md);
        }
        rc = cvc_verify_cert_signature(cert, cert_len, &signer_pk, md);
        mbedtls_rsa_free(&rsa);
        return rc == LIBCVC_OK ? PICOKEYS_OK : PICOKEYS_WRONG_SIGNATURE;
    }

    if (signer.kind == CVC_KEY_KIND_EC) {
        mbedtls_ecdsa_context ecdsa;
        mbedtls_pk_context signer_pk;
        mbedtls_ecp_group_id ec_id = cvc_inherite_ec_group(ca, ca_len);
        int rc;

        if (ec_id == MBEDTLS_ECP_DP_NONE) {
            return PICOKEYS_WRONG_DATA;
        }
        mbedtls_ecdsa_init(&ecdsa);
        if (mbedtls_ecp_group_load(&ecdsa.grp, ec_id) != 0 || mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, signer.q, signer.q_len) != 0 || mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q) != 0 || cvc_pk_wrap_ec(&signer_pk, &ecdsa) != LIBCVC_OK) {
            mbedtls_ecdsa_free(&ecdsa);
            return PICOKEYS_WRONG_DATA;
        }
        rc = cvc_verify_cert_signature(cert, cert_len, &signer_pk, md);
        mbedtls_ecdsa_free(&ecdsa);
        return rc == LIBCVC_OK ? PICOKEYS_OK : PICOKEYS_WRONG_SIGNATURE;
    }

    return PICOKEYS_WRONG_DATA;
}
