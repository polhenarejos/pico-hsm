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

#include "picokeys.h"
#include "object_provider.h"
#include "crypto_utils.h"
#include "kek.h"
#include "sc_hsm.h"

#include "object_crypto_provider.h"

static file_object_crypto_provider_t hsm_object_crypto_provider;
static bool hsm_object_crypto_provider_initialized;

static int hsm_object_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    (void)ctx;
    uint8_t mkek[MKEK_SIZE] = { 0 };
    int r = load_mkek(mkek);
    if (r == PICOKEYS_OK) {
        memcpy(root, MKEK_KEY(mkek), FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    }
    release_mkek(mkek);
    return r;
}

static int hsm_object_public_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    (void)ctx;
    derive_kbase(root);
    return PICOKEYS_OK;
}

static bool hsm_object_identity_valid(void *ctx, const file_object_record_identity_t *identity) {
    (void)ctx;
    return identity->key_domain < MAX_KEY_DOMAINS;
}

static int hsm_object_crypto_provider_init(void) {
    if (hsm_object_crypto_provider_initialized) {
        return PICOKEYS_OK;
    }

    const file_object_crypto_provider_config_t config = {
        .namespace_id = HSM_OBJECT_NAMESPACE,
        .load_root = hsm_object_root_load,
        .load_public_root = hsm_object_public_root_load,
        .identity_valid = hsm_object_identity_valid
    };
    int r = file_object_crypto_provider_init(&hsm_object_crypto_provider, &config);
    if (r == PICOKEYS_OK) {
        hsm_object_crypto_provider_initialized = true;
    }
    return r;
}

const file_object_authenticator_t *hsm_object_manifest_authenticator(void) {
    if (hsm_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_manifest_authenticator(&hsm_object_crypto_provider);
}

const file_object_record_protector_t *hsm_object_record_protector(void) {
    if (hsm_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_record_protector(&hsm_object_crypto_provider);
}
