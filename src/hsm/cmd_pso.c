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
#include "oid.h"
#include "asn1.h"
#include "cvc.h"

extern int add_cert_puk_store(const uint8_t *data, uint16_t data_len, bool copy);
extern PUK *current_puk;

int cmd_pso() {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p1 == 0x0 && (p2 == 0x92 || p2 == 0xAE || p2 == 0xBE)) { /* Verify certificate */
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
        if (current_puk == NULL) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (apdu.data[0] != 0x7F || apdu.data[1] != 0x21) {
            uint8_t tlv_len = 2 + format_tlv_len(apdu.nc, NULL);
            memmove(apdu.data + tlv_len, apdu.data, apdu.nc);
            memcpy(apdu.data, "\x7F\x21", 2);
            format_tlv_len(apdu.nc, apdu.data + 2);
            apdu.nc += tlv_len;
        }
        int r = cvc_verify(apdu.data, apdu.nc, current_puk->cvcert, current_puk->cvcert_len);
        if (r != CCID_OK) {
            if (r == CCID_WRONG_DATA) {
                return SW_DATA_INVALID();
            }
            else if (r == CCID_WRONG_SIGNATURE) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            return SW_EXEC_ERROR();
        }
        for (uint8_t i = 0; i < 0xfe; i++) {
            uint16_t fid = (CA_CERTIFICATE_PREFIX << 8) | i;
            file_t *ca_ef = search_dynamic_file(fid);
            if (!ca_ef) {
                ca_ef = file_new(fid);
                flash_write_data_to_file(ca_ef, apdu.data, apdu.nc);
                if (add_cert_puk_store(file_get_data(ca_ef), file_get_size(ca_ef),
                                       false) != CCID_OK) {
                    return SW_FILE_FULL();
                }

                uint16_t chr_len = 0;
                const uint8_t *chr = cvc_get_chr(apdu.data, apdu.nc, &chr_len);
                if (chr == NULL) {
                    return SW_WRONG_DATA();
                }
                uint16_t puk_len = 0, puk_bin_len = 0;
                const uint8_t *puk = cvc_get_pub(apdu.data, apdu.nc, &puk_len), *puk_bin = NULL;
                if (puk == NULL) {
                    return SW_WRONG_DATA();
                }
                uint16_t oid_len = 0;
                const uint8_t *oid = cvc_get_field(puk, puk_len, &oid_len, 0x6);
                if (oid == NULL) {
                    return SW_WRONG_DATA();
                }
                if (memcmp(oid, OID_ID_TA_RSA, 9) == 0) { //RSA
                    puk_bin = cvc_get_field(puk, puk_len, &puk_bin_len, 0x81);
                    if (!puk_bin) {
                        return SW_WRONG_DATA();
                    }
                }
                else if (memcmp(oid, OID_ID_TA_ECDSA, 9) == 0) {   //ECC
                    mbedtls_ecp_group_id ec_id = cvc_inherite_ec_group(apdu.data, apdu.nc);
                    mbedtls_ecp_group grp;
                    mbedtls_ecp_group_init(&grp);
                    if (mbedtls_ecp_group_load(&grp, ec_id) != 0) {
                        mbedtls_ecp_group_free(&grp);
                        return SW_WRONG_DATA();
                    }
                    uint16_t plen = (uint16_t)mbedtls_mpi_size(&grp.P);
                    uint16_t t86_len = 0;
                    const uint8_t *t86 = cvc_get_field(puk, puk_len, &t86_len, 0x86);
                    if (mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
                        if (plen != t86_len) {
                            mbedtls_ecp_group_free(&grp);
                            return SW_WRONG_DATA();
                        }
                        puk_bin = t86;
                        puk_bin_len = t86_len;
                    }
                    else if (mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
                        if (t86[0] == 0x2 || t86[0] == 0x3) {
                            if (t86_len != plen + 1) {
                                mbedtls_ecp_group_free(&grp);
                                return SW_WRONG_DATA();
                            }
                        }
                        else if (t86[0] == 0x4) {
                            if (t86_len != 2 * plen + 1) {
                                mbedtls_ecp_group_free(&grp);
                                return SW_WRONG_DATA();
                            }
                        }
                        else {
                            mbedtls_ecp_group_free(&grp);
                            return SW_WRONG_DATA();
                        }
                        puk_bin = t86 + 1;
                        puk_bin_len = plen;
                    }
                    mbedtls_ecp_group_free(&grp);
                    if (!puk_bin) {
                        return SW_WRONG_DATA();
                    }
                }
                file_t *cd_ef = file_new((CD_PREFIX << 8) | i);
                uint16_t cd_len = (uint16_t)asn1_build_cert_description(chr,
                                                            chr_len,
                                                            puk_bin,
                                                            puk_bin_len,
                                                            fid,
                                                            NULL,
                                                            0);
                if (cd_len == 0) {
                    return SW_EXEC_ERROR();
                }
                uint8_t *buf = (uint8_t *) calloc(cd_len, sizeof(uint8_t));
                r = (int)asn1_build_cert_description(chr,
                                                    chr_len,
                                                    puk_bin,
                                                    puk_bin_len,
                                                    fid,
                                                    buf,
                                                    cd_len);
                flash_write_data_to_file(cd_ef, buf, cd_len);
                free(buf);
                if (r == 0) {
                    return SW_EXEC_ERROR();
                }
                low_flash_available();
                break;
            }
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    return SW_OK();
}
