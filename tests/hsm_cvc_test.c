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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hsm_cvc_test_vectors.h"

/* cvc.c reads these; the remaining externals belong to code paths this test
 * does not exercise (certificate writing and signing). */
struct apdu apdu;
PUK puk_store[MAX_PUK_STORE_ENTRIES];
int puk_store_entries = 0;
const uint8_t *dev_name = NULL;
uint16_t dev_name_len = 0;

file_t *hsm_key_search(uint8_t key_id) {
    (void) key_id;
    return NULL;
}

int load_private_key_ec(mbedtls_ecp_keypair *ctx, file_t *fkey, uint16_t operation,
                        bool internal_firmware) {
    (void) ctx; (void) fkey; (void) operation; (void) internal_firmware;
    return -1;
}

int random_fill_iterator(void *arg, unsigned char *output, size_t output_len) {
    (void) arg;
    memset(output, 0x5A, output_len);
    return 0;
}

/* crypto_utils.c is linked for ec_get_curve_from_prime(); its key-derivation
 * paths are not reachable from this test. */
uint8_t pico_serial_hash[32];
const uint8_t *otp_key_1 = NULL;

int random_fill_buffer(byte_array_t buffer) {
    memset(buffer.data, 0x5A, buffer.len);
    return 0;
}

static const uint8_t car_utca00001[] = { 'U', 'T', 'C', 'A', '0', '0', '0', '0', '1' };

static void puk_store_clear(void) {
    memset(puk_store, 0, sizeof(puk_store));
    puk_store_entries = 0;
}

static void puk_store_add(const uint8_t *chr, uint16_t chr_len,
                          const uint8_t *cvcert, uint16_t cvcert_len) {
    assert(puk_store_entries < MAX_PUK_STORE_ENTRIES);
    puk_store[puk_store_entries].chr = chr;
    puk_store[puk_store_entries].chr_len = chr_len;
    puk_store[puk_store_entries].cvcert = cvcert;
    puk_store[puk_store_entries].cvcert_len = cvcert_len;
    puk_store_entries++;
}

/* A certificate carrying its own EC domain parameters must resolve even when
 * the CA named in its CAR is unknown. Every key generated through OpenSC hits
 * this: pkcs15init stamps CAR = "UTCA00001", for which no certificate exists.
 * Before the parameters are consulted directly, the walk up to a self-signed
 * ancestor dead-ends and the curve resolves to DP_NONE -- which makes
 * puk_verify() reject every signature and EXTERNAL AUTHENTICATE return 6985. */
static void test_explicit_params_with_unresolvable_car(void) {
    puk_store_clear();
    mbedtls_ecp_group_id id = cvc_inherite_ec_group(
        CONST_BYTE_ARRAY(cvc_explicit_unresolvable_car, sizeof(cvc_explicit_unresolvable_car)));
    assert(id == MBEDTLS_ECP_DP_SECP256R1);
    printf("  explicit params, unresolvable CAR ... ok\n");
}

/* A certificate that genuinely omits the parameters must still inherit them
 * from its CA via the puk store. */
static void test_inherited_params_resolve_via_ca(void) {
    puk_store_clear();
    puk_store_add(car_utca00001, sizeof(car_utca00001),
                  cvc_ca_utca00001, sizeof(cvc_ca_utca00001));
    mbedtls_ecp_group_id id = cvc_inherite_ec_group(
        CONST_BYTE_ARRAY(cvc_inherited_params, sizeof(cvc_inherited_params)));
    assert(id == MBEDTLS_ECP_DP_SECP256R1);
    printf("  inherited params, CA in puk store ... ok\n");
}

/* ... and must still fail when the parameters are absent and no CA can
 * supply them, rather than silently guessing a curve. */
static void test_inherited_params_without_ca_fails(void) {
    puk_store_clear();
    mbedtls_ecp_group_id id = cvc_inherite_ec_group(
        CONST_BYTE_ARRAY(cvc_inherited_params, sizeof(cvc_inherited_params)));
    assert(id == MBEDTLS_ECP_DP_NONE);
    printf("  inherited params, no CA ............. ok (DP_NONE)\n");
}

/* The self-signed case, which resolved correctly before and after. */
static void test_selfsigned_with_explicit_params(void) {
    puk_store_clear();
    mbedtls_ecp_group_id id = cvc_inherite_ec_group(
        CONST_BYTE_ARRAY(cvc_selfsigned_explicit, sizeof(cvc_selfsigned_explicit)));
    assert(id == MBEDTLS_ECP_DP_SECP256R1);
    printf("  self-signed, explicit params ....... ok\n");
}

int main(void) {
    printf("cvc_inherite_ec_group:\n");
    /* Behaviour that must be unchanged, first; the regression case last, so a
     * failure there does not mask whether inheritance still works. */
    test_inherited_params_resolve_via_ca();
    test_inherited_params_without_ca_fails();
    test_selfsigned_with_explicit_params();
    test_explicit_params_with_unresolvable_car();
    printf("all passed\n");
    return 0;
}
