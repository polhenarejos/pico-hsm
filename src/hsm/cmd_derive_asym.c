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
#include "mbedtls/ecdsa.h"
#include "crypto_utils.h"
#include "sc_hsm.h"
#include "cvc.h"

#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
#define MOD_ADD(N)                                                    \
    while (mbedtls_mpi_cmp_mpi(&(N), &grp->P) >= 0)                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(&(N), &(N), &grp->P))
static inline int mbedtls_mpi_add_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B) {
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X, A, B));
    MOD_ADD(*X);
cleanup:
    return ret;
}

int cmd_derive_asym() {
    uint8_t key_id = P1(apdu);
    uint8_t dest_id = P2(apdu);
    file_t *fkey;
    if (!isUserAuthenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!(fkey = search_dynamic_file((KEY_PREFIX << 8) | key_id)) || !file_has_data(fkey)) {
        return SW_FILE_NOT_FOUND();
    }
    if (key_has_purpose(fkey, ALGO_EC_DERIVE) == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] == ALGO_EC_DERIVE) {
        mbedtls_ecp_keypair ctx;
        mbedtls_ecp_keypair_init(&ctx);

        int r;
        r = load_private_key_ec(&ctx, fkey);
        if (r != CCID_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            if (r == CCID_VERIFICATION_FAILED) {
                return SW_SECURE_MESSAGE_EXEC_ERROR();
            }
            return SW_EXEC_ERROR();
        }
        mbedtls_mpi a, nd;
        mbedtls_mpi_init(&a);
        mbedtls_mpi_init(&nd);
        r = mbedtls_mpi_read_binary(&a, apdu.data + 1, apdu.nc - 1);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ctx);
            mbedtls_mpi_free(&a);
            mbedtls_mpi_free(&nd);
            return SW_DATA_INVALID();
        }
        r = mbedtls_mpi_add_mod(&ctx.grp, &nd, &ctx.d, &a);
        mbedtls_mpi_free(&a);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ctx);
            mbedtls_mpi_free(&nd);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_copy(&ctx.d, &nd);
        mbedtls_mpi_free(&nd);
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ctx, HSM_KEY_EC, dest_id);
        if (r != CCID_OK) {
            mbedtls_ecp_keypair_free(&ctx);
            return SW_EXEC_ERROR();
        }
        mbedtls_ecp_keypair_free(&ctx);
    }
    else {
        return SW_WRONG_DATA();
    }
    return SW_OK();
}
