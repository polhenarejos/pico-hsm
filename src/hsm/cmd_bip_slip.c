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
#include "files.h"
#include "random.h"
#include "kek.h"
#include "asn1.h"

const uint8_t *k1_seed = (const uint8_t *) "Bitcoin seed";
const uint8_t *p1_seed = (const uint8_t *) "Nist256p1 seed";
const uint8_t *sym_seed = (const uint8_t *) "Symmetric key seed";
mbedtls_ecp_keypair hd_context = { 0 };
uint8_t hd_keytype = 0;

int node_derive_bip_child(const mbedtls_ecp_keypair *parent,
                          const uint8_t cpar[32],
                          const uint8_t *i,
                          mbedtls_ecp_keypair *child,
                          uint8_t cchild[32]) {
    uint8_t data[1 + 32 + 4], I[64], *iL = I, *iR = I + 32;
    mbedtls_mpi il, kchild;
    mbedtls_mpi_init(&il);
    mbedtls_mpi_init(&kchild);
    if (i[0] >= 0x80) {
        if (mbedtls_mpi_cmp_int(&parent->d, 0) == 0) {
            return CCID_ERR_NULL_PARAM;
        }
        data[0] = 0x00;
        mbedtls_mpi_write_binary(&parent->d, data + 1, 32);
    }
    else {
        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&parent->grp,
                                       &parent->Q,
                                       MBEDTLS_ECP_PF_COMPRESSED,
                                       &olen,
                                       data,
                                       33);
    }
    do {
        memcpy(data + 33, i, 4);
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                        cpar,
                        32,
                        data,
                        sizeof(data),
                        I);
        mbedtls_mpi_read_binary(&il, iL, 32);
        mbedtls_mpi_add_mpi(&kchild, &il, &parent->d);
        mbedtls_mpi_mod_mpi(&kchild, &kchild, &parent->grp.N);
        data[0] = 0x01;
        memcpy(data + 1, iR, 32);
    } while (mbedtls_mpi_cmp_mpi(&il,
                                 &parent->grp.N) != -1 || mbedtls_mpi_cmp_int(&kchild, 0) == 0);
    mbedtls_mpi_copy(&child->d, &kchild);
    mbedtls_ecp_mul(&child->grp, &child->Q, &child->d, &child->grp.G, random_gen, NULL);
    memcpy(cchild, iR, 32);
    mbedtls_mpi_free(&il);
    mbedtls_mpi_free(&kchild);
    return CCID_OK;
}

int sha256_ripemd160(const uint8_t *buffer, size_t buffer_len, uint8_t *output) {
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buffer, buffer_len, output);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_RIPEMD160), output, 32, output);
    return CCID_OK;
}

int sha256_sha256(const uint8_t *buffer, size_t buffer_len, uint8_t *output) {
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buffer, buffer_len, output);
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), output, 32, output);
    return CCID_OK;
}

int node_fingerprint_bip(mbedtls_ecp_keypair *ctx, uint8_t fingerprint[4]) {
    size_t olen = 0;
    uint8_t buffer[33];
    mbedtls_ecp_point_write_binary(&ctx->grp,
                                   &ctx->Q,
                                   MBEDTLS_ECP_PF_COMPRESSED,
                                   &olen,
                                   buffer,
                                   sizeof(buffer));
    sha256_ripemd160(buffer, sizeof(buffer), buffer);
    memcpy(fingerprint, buffer, 4);
    return CCID_OK;
}

int node_fingerprint_slip(mbedtls_ecp_keypair *ctx, uint8_t fingerprint[4]) {
    uint8_t buffer[32];
    mbedtls_mpi_write_binary(&ctx->d, buffer, sizeof(buffer));
    sha256_ripemd160(buffer, sizeof(buffer), buffer);
    memcpy(fingerprint, buffer, 4);
    return CCID_OK;
}

int load_master_bip(uint16_t mid, mbedtls_ecp_keypair *ctx, uint8_t chain[32],
                    uint8_t key_type[1]) {
    uint8_t mkey[65];
    mbedtls_ecp_keypair_init(ctx);
    file_t *ef = search_dynamic_file(EF_MASTER_SEED | mid);
    if (!file_has_data(ef)) {
        return CCID_ERR_FILE_NOT_FOUND;
    }
    memcpy(mkey, file_get_data(ef), sizeof(mkey));
    int r = mkek_decrypt(mkey + 1,
                         sizeof(mkey) - 1);
    if (r != CCID_OK) {
        return CCID_EXEC_ERROR;
    }
    if (mkey[0] == 0x1 || mkey[0] == 0x2) {
        if (mkey[0] == 0x1) {
            mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256K1);
        }
        else if (mkey[0] == 0x2) {
            mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1);
        }
        else {
            return CCID_WRONG_DATA;
        }

        mbedtls_mpi_read_binary(&ctx->d, mkey + 1, 32);
        memcpy(chain, mkey + 33, 32);
        mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, random_gen, NULL);
    }
    else if (mkey[0] == 0x3) {
        mbedtls_mpi_read_binary(&ctx->d, mkey + 33, 32);
        memcpy(chain, mkey + 1, 32);
    }
    key_type[0] = mkey[0];
    return CCID_OK;
}

int node_derive_path(const uint8_t *path,
                     uint16_t path_len,
                     mbedtls_ecp_keypair *ctx,
                     uint8_t chain[32],
                     uint8_t fingerprint[4],
                     uint8_t *nodes,
                     uint8_t last_node[4],
                     uint8_t key_type[1]) {
    uint8_t *tag_data = NULL, *p = NULL;
    uint16_t tag_len = 0, tag = 0x0;
    uint8_t node = 0, N[64] = { 0 };
    int r = 0;
    memset(last_node, 0, 4);
    memset(fingerprint, 0, 4);
    for (; walk_tlv(path, path_len, &p, &tag, &tag_len, &tag_data); node++) {
        if (tag == 0x02) {
            if ((node == 0 && tag_len != 1) || (node != 0 && tag_len != 4)) {
                return CCID_WRONG_DATA;
            }
            if (node == 0) {
                if ((r = load_master_bip(tag_data[0], ctx, chain, key_type)) != CCID_OK) {
                    return r;
                }
            }
            else if (node > 0) {
                node_fingerprint_bip(ctx, fingerprint);
                if ((r = node_derive_bip_child(ctx, chain, tag_data, ctx, chain)) != CCID_OK) {
                    return r;
                }
                memcpy(last_node, tag_data, 4);
            }
        }
        else if (tag == 0x04) {
            if (node == 0) {
                return CCID_WRONG_DATA;
            }
            else if (node > 0) {
                node_fingerprint_slip(ctx, fingerprint);
                *(tag_data - 1) = 0;
                mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                                chain,
                                32,
                                tag_data - 1,
                                tag_len + 1,
                                N);
                memcpy(chain, N, 32);
                mbedtls_mpi_read_binary(&ctx->d, N + 32, 32);
            }
        }
    }
    if (nodes) {
        *nodes = node;
    }
    return CCID_OK;
}

int cmd_bip_slip() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p1 == 0x1 || p1 == 0x2 || p1 == 0x3) { // Master generation (K1 and P1)
        if (p2 >= 10) {
            return SW_INCORRECT_P1P2();
        }
        uint8_t mkey[65], *seed = mkey + 1, seed_len = 64;
        const uint8_t *key_seed = NULL;
        mbedtls_mpi il;
        mbedtls_mpi_init(&il);
        mbedtls_ecp_group grp;
        mbedtls_ecp_group_init(&grp);
        if (p1 == 0x1) {
            mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
            key_seed = k1_seed;
        }
        else if (p1 == 0x2) {
            mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
            key_seed = p1_seed;
        }
        else if (p1 == 0x3) {
            key_seed = sym_seed;
        }
        if (apdu.nc == 0) {
            seed_len = 64;
            random_gen(NULL, seed, seed_len);
        }
        else {
            seed_len = MIN((uint8_t)apdu.nc, 64);
            memcpy(seed, apdu.data, seed_len);
        }
        if (p1 == 0x1 || p1 == 0x2) {
            do {
                mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), key_seed,
                                strlen((char *) key_seed), seed, seed_len, seed);
                mbedtls_mpi_read_binary(&il, seed, 32);
                seed_len = 64;
            } while (mbedtls_mpi_cmp_int(&il, 0) == 0 || mbedtls_mpi_cmp_mpi(&il, &grp.N) != -1);
            mbedtls_ecp_group_free(&grp);
            mbedtls_mpi_free(&il);
        }
        else if (p1 == 0x3) {
            mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), key_seed,
                            strlen((char *) key_seed), seed, seed_len, seed);
        }
        mkey[0] = p1;
        file_t *ef = file_new(EF_MASTER_SEED | p2);
        int r = mkek_encrypt(mkey + 1, sizeof(mkey) - 1);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        r = flash_write_data_to_file(ef, mkey, sizeof(mkey));
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
        low_flash_available();
    }
    else if (p1 == 0xA) {
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
        mbedtls_ecp_keypair ctx;
        uint8_t chain[32] = { 0 }, fgpt[4] = { 0 }, last_node[4] = { 0 }, key_type = 0, nodes = 0;
        uint16_t olen = 0;
        int r =
            node_derive_path(apdu.data, apdu.nc, &ctx, chain, fgpt, &nodes, last_node, &key_type);
        if (r != CCID_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        uint8_t pubkey[33];
        res_APDU_size = 0;
        memcpy(res_APDU, "\x04\x88\xB2\x1E", 4);
        res_APDU_size += 4;
        res_APDU[res_APDU_size++] = nodes - 1;
        memcpy(res_APDU + res_APDU_size, fgpt, 4);
        res_APDU_size += 4;
        memcpy(res_APDU + res_APDU_size, last_node, 4);
        res_APDU_size += 4;
        if (key_type == 0x1 || key_type == 0x2) {
            memcpy(res_APDU + res_APDU_size, chain, 32);
            res_APDU_size += 32;
            mbedtls_ecp_point_write_binary(&ctx.grp,
                                           &ctx.Q,
                                           MBEDTLS_ECP_PF_COMPRESSED,
                                           (size_t *)&olen,
                                           pubkey,
                                           sizeof(pubkey));
            memcpy(res_APDU + res_APDU_size, pubkey, olen);
            res_APDU_size += olen;
        }
        else if (key_type == 0x3) {
            sha256_sha256(chain, 32, chain);
            memcpy(res_APDU + res_APDU_size, chain, 32);
            res_APDU_size += 32;
            mbedtls_mpi_write_binary(&ctx.d, pubkey, 32);
            sha256_sha256(pubkey, 32, pubkey);
            memcpy(res_APDU + res_APDU_size, pubkey, 32);
            res_APDU_size += 32;
        }
        mbedtls_ecp_keypair_free(&ctx);
    }
    else if (p1 == 0x10) {
        uint8_t chain[32] = { 0 }, fgpt[4] = { 0 }, last_node[4] = { 0 }, nodes = 0;
        int r = node_derive_path(apdu.data,
                                 apdu.nc,
                                 &hd_context,
                                 chain,
                                 fgpt,
                                 &nodes,
                                 last_node,
                                 &hd_keytype);
        if (r != CCID_OK) {
            mbedtls_ecp_keypair_free(&hd_context);
            return SW_EXEC_ERROR();
        }
    }
    return SW_OK();
}
