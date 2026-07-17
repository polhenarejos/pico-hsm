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
#include "key_container.h"
#include "object_authorization.h"
#include "object_provider.h"
#include "sc_hsm.h"

#include <assert.h>
#include <stdio.h>

#define TEST_FILE_COUNT 64u
#define TEST_FILE_CAPACITY 1024u

typedef struct test_file {
    file_t file;
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    bool allocated;
} test_file_t;

typedef struct test_file_image {
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    uint16_t fid;
    bool allocated;
} test_file_image_t;

typedef struct test_auth_context {
    uint32_t state[4];
    bool active;
} test_auth_context_t;

typedef struct test_protector_context {
    uint8_t key;
} test_protector_context_t;

static test_file_t test_files[TEST_FILE_COUNT];
static test_file_image_t test_durable_files[TEST_FILE_COUNT];
static test_auth_context_t test_auth_context;
static test_protector_context_t test_protector_context = { .key = 0x5a };
static bool test_authorized = true;
static uint16_t test_last_operation;
static bool test_last_internal;

static const uint8_t test_key_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x0f, 0x7c, 0x00, 0x00, 0x04, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static test_file_t *test_file_from_handle(const file_t *file) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (&test_files[i].file == file) {
            return &test_files[i];
        }
    }
    return NULL;
}

static void test_persist(void) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_durable_files[i].storage, test_files[i].storage, sizeof(test_durable_files[i].storage));
        test_durable_files[i].size = test_files[i].size;
        test_durable_files[i].fid = test_files[i].file.fid;
        test_durable_files[i].allocated = test_files[i].allocated;
    }
}

static void test_reset(void) {
    memset(test_files, 0, sizeof(test_files));
    memset(test_durable_files, 0, sizeof(test_durable_files));
    memset(&test_auth_context, 0, sizeof(test_auth_context));
    test_authorized = true;
    test_last_operation = 0;
    test_last_internal = false;
}

static void test_reboot(void) {
    memset(test_files, 0, sizeof(test_files));
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_files[i].storage, test_durable_files[i].storage, sizeof(test_files[i].storage));
        test_files[i].size = test_durable_files[i].size;
        test_files[i].file.fid = test_durable_files[i].fid;
        test_files[i].allocated = test_durable_files[i].allocated;
        test_files[i].file.data = test_files[i].size > 0 ? test_files[i].storage : NULL;
    }
    memset(&test_auth_context, 0, sizeof(test_auth_context));
}

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (test_files[i].allocated && test_files[i].file.fid == fid) {
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_new(uint16_t fid) {
    file_t *existing = file_search(fid);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (!test_files[i].allocated) {
            test_files[i].allocated = true;
            test_files[i].file.fid = fid;
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    (void)fid;
    (void)parent;
    (void)sp;
    return NULL;
}

bool file_has_data(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file && test_file->allocated && test_file->file.data && test_file->size > 0;
}

uint8_t *file_get_data(const file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    return file_has_data(file) ? test_file->storage : NULL;
}

uint32_t file_get_size(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file ? test_file->size : 0;
}

int file_read_at(const file_t *file, uint32_t offset, uint8_t *data, size_t len) {
    const test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || offset > test_file->size || len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (len > 0) {
        memcpy(data, test_file->storage + offset, len);
    }
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const uint8_t *data, uint32_t len) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (len > 0) {
        memcpy(test_file->storage, data, len);
    }
    test_file->size = len;
    test_file->file.data = len > 0 ? test_file->storage : NULL;
    return PICOKEYS_OK;
}

int file_delete_no_commit(file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || !test_file->allocated) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    memset(test_file->storage, 0, sizeof(test_file->storage));
    test_file->size = 0;
    test_file->file.data = NULL;
    return PICOKEYS_OK;
}

void flash_commit(void) {
    test_persist();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    test_persist();
    return true;
}

static int test_auth_start(void *ctx) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    auth->state[0] = 0x811c9dc5u;
    auth->state[1] = 0x9e3779b9u;
    auth->state[2] = 0x85ebca6bu;
    auth->state[3] = 0xc2b2ae35u;
    auth->active = true;
    return PICOKEYS_OK;
}

static int test_auth_update(void *ctx, const uint8_t *data, size_t len) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || (!data && len > 0)) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < len; i++) {
        for (size_t word = 0; word < 4; word++) {
            auth->state[word] ^= data[i] + (uint8_t)word;
            auth->state[word] *= 0x01000193u + (uint32_t)(word * 2u);
            auth->state[word] = (auth->state[word] << 5) | (auth->state[word] >> 27);
        }
    }
    return PICOKEYS_OK;
}

static int test_auth_finish(void *ctx, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || !tag) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < 4; i++) {
        put_uint32_be(auth->state[i], tag + i * sizeof(uint32_t));
    }
    memset(auth, 0, sizeof(*auth));
    return PICOKEYS_OK;
}

static void test_auth_abort(void *ctx) {
    memset(ctx, 0, sizeof(test_auth_context_t));
}

static const file_object_authenticator_t test_auth = {
    .ctx = &test_auth_context,
    .start = test_auth_start,
    .update = test_auth_update,
    .finish = test_auth_finish,
    .abort = test_auth_abort
};

static int test_record_tag(const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = test_auth_start(&test_auth_context);
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, &test_protector_context.key, sizeof(test_protector_context.key));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, nonce, FILE_OBJECT_RECORD_NONCE_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, aad, FILE_OBJECT_RECORD_AAD_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, stored, len);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_finish(&test_auth_context, tag);
    }
    return r;
}

static int test_record_seal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *plaintext, size_t len, uint8_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    for (size_t i = 0; i < len; i++) {
        stored[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? plaintext[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : plaintext[i];
    }
    return test_record_tag(nonce, aad, stored, len, tag);
}

static int test_record_unseal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], uint8_t *plaintext) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    uint8_t calculated[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = test_record_tag(nonce, aad, stored, len, calculated);
    if (r == PICOKEYS_OK && memcmp(calculated, tag, sizeof(calculated)) != 0) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    if (r == PICOKEYS_OK) {
        for (size_t i = 0; i < len; i++) {
            plaintext[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? stored[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : stored[i];
        }
    }
    memset(calculated, 0, sizeof(calculated));
    return r;
}

static const file_object_record_protector_t test_protector = {
    .ctx = &test_protector_context,
    .seal = test_record_seal,
    .unseal = test_record_unseal
};

const file_object_authenticator_t *hsm_object_manifest_authenticator(void) {
    return &test_auth;
}

const file_object_record_protector_t *hsm_object_record_protector(void) {
    return &test_protector;
}

const uint8_t *hsm_object_authorization_key_policy(size_t *policy_size) {
    if (policy_size) {
        *policy_size = sizeof(test_key_policy);
    }
    return test_key_policy;
}

bool hsm_object_authorization_key_operation(uint16_t operation, bool internal_firmware) {
    test_last_operation = operation;
    test_last_internal = internal_firmware;
    return test_authorized;
}

static hsm_key_container_write_t test_write(uint16_t object_type, const uint8_t *data, uint32_t data_size) {
    hsm_key_container_write_t write = {
        .object_type = object_type,
        .data = data,
        .data_size = data_size,
        .policy_id = object_type == HSM_KEY_OBJECT_PRIVATE ? HSM_OBJECT_KEY_POLICY_ID : HSM_KEY_INTERNAL_POLICY_ID,
        .protection = object_type == HSM_KEY_OBJECT_PRIVATE ? FILE_OBJECT_PROTECTION_AEAD_SECRET : FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
    };
    if (object_type == HSM_KEY_OBJECT_PRKD || object_type == HSM_KEY_OBJECT_CERTIFICATE) {
        write.flags = FILE_OBJECT_FLAG_GENERIC_READABLE;
    }
    return write;
}

static void test_read(uint8_t key_id, uint16_t object_type, const uint8_t *expected, size_t expected_size) {
    uint8_t output[128] = { 0 };
    size_t written = 0;
    bool internal = object_type != HSM_KEY_OBJECT_PRIVATE;
    assert(expected_size <= sizeof(output));
    assert(hsm_key_container_read(key_id, object_type, FILE_OBJECT_OPERATION_SIGN, internal, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == expected_size);
    assert(memcmp(output, expected, expected_size) == 0);
}

static void test_compound_persistence_and_recovery(void) {
    static const uint8_t private_first[] = { 1, 2, 3, 4, 5 };
    static const uint8_t private_second[] = { 6, 7, 8, 9 };
    static const uint8_t prkd[] = { 0x30, 0x03, 0x01, 0x02, 0x03 };
    static const uint8_t metadata[] = { 0x90, 0x01, 0x7f };
    const uint8_t key_id = 0x2a;
    hsm_key_container_write_t initial[] = {
        test_write(HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first)),
        test_write(HSM_KEY_OBJECT_PRKD, prkd, sizeof(prkd)),
        test_write(HSM_KEY_OBJECT_POLICY, test_key_policy, sizeof(test_key_policy))
    };

    test_reset();
    assert(hsm_key_container_can_create(key_id));
    assert(hsm_key_container_update(key_id, initial, sizeof(initial) / sizeof(initial[0])) == PICOKEYS_OK);
    assert(hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first));
    assert(test_last_operation == FILE_OBJECT_OPERATION_SIGN);
    assert(!test_last_internal);
    test_read(key_id, HSM_KEY_OBJECT_PRKD, prkd, sizeof(prkd));
    uint8_t public_output[sizeof(prkd)] = { 0 };
    size_t public_written = 0;
    uint32_t public_size = 0;
    assert(hsm_key_container_object_size(key_id, HSM_KEY_OBJECT_PRKD, false, &public_size) == PICOKEYS_OK);
    assert(public_size == sizeof(prkd));
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRKD, FILE_OBJECT_OPERATION_READ, false, public_output, sizeof(public_output), &public_written) == PICOKEYS_OK);
    assert(public_written == sizeof(prkd));
    assert(memcmp(public_output, prkd, sizeof(prkd)) == 0);

    test_reboot();
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first));

    hsm_key_container_write_t replacement = test_write(HSM_KEY_OBJECT_PRIVATE, private_second, sizeof(private_second));
    assert(hsm_key_container_update(key_id, &replacement, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_second, sizeof(private_second));
    test_read(key_id, HSM_KEY_OBJECT_PRKD, prkd, sizeof(prkd));

    test_file_t *new_record = test_file_from_handle(file_search(0xe004));
    assert(new_record && new_record->size > FILE_OBJECT_RECORD_HEADER_SIZE);
    new_record->storage[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x80;
    test_persist();
    test_reboot();
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first));

    hsm_key_container_write_t metadata_write = test_write(HSM_KEY_OBJECT_METADATA, metadata, sizeof(metadata));
    assert(hsm_key_container_update(key_id, &metadata_write, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first));
    test_read(key_id, HSM_KEY_OBJECT_METADATA, metadata, sizeof(metadata));
    assert(hsm_key_container_object_size(key_id, HSM_KEY_OBJECT_METADATA, false, &public_size) == PICOKEYS_NO_LOGIN);
    assert(hsm_key_container_remove_object(key_id, HSM_KEY_OBJECT_PRKD) == PICOKEYS_OK);
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRKD, FILE_OBJECT_OPERATION_READ, true, public_output, sizeof(public_output), &public_written) == PICOKEYS_ERR_FILE_NOT_FOUND);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_first, sizeof(private_first));
}

static void test_orphan_manifest_resume(void) {
    static const uint8_t private_data[] = { 0x11, 0x22, 0x33 };
    static const uint8_t certificate[] = { 0x30, 0x01, 0x42 };
    const uint8_t key_id = 0x3b;
    hsm_key_container_write_t private_write = test_write(HSM_KEY_OBJECT_PRIVATE, private_data, sizeof(private_data));

    test_reset();
    assert(hsm_key_container_update(key_id, &private_write, 1) == PICOKEYS_OK);
    assert(file_delete_no_commit(file_search((HSM_OBJECT_PREFIX << 8) | key_id)) == PICOKEYS_OK);
    flash_commit();
    test_reboot();
    assert(hsm_key_container_can_resume(key_id));

    hsm_key_container_write_t certificate_write = test_write(HSM_KEY_OBJECT_CERTIFICATE, certificate, sizeof(certificate));
    assert(hsm_key_container_update(key_id, &certificate_write, 1) == PICOKEYS_OK);
    assert(hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_data, sizeof(private_data));
    test_read(key_id, HSM_KEY_OBJECT_CERTIFICATE, certificate, sizeof(certificate));
}

static void test_policy_and_delete(void) {
    static const uint8_t private_data[] = { 0xaa, 0xbb };
    const uint8_t key_id = 0x4c;
    hsm_key_container_write_t write = test_write(HSM_KEY_OBJECT_PRIVATE, private_data, sizeof(private_data));
    uint8_t output[8];
    size_t written = 0;

    test_reset();
    test_authorized = false;
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_UPDATE);

    test_authorized = true;
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_OK);
    test_authorized = false;
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRIVATE, FILE_OBJECT_OPERATION_EXPORT, false, output, sizeof(output), &written) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_EXPORT);
    assert(hsm_key_container_delete(key_id) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_DELETE);

    test_authorized = true;
    assert(hsm_key_container_delete(key_id) == PICOKEYS_OK);
    assert(!file_has_data(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRIVATE, FILE_OBJECT_OPERATION_USE, false, output, sizeof(output), &written) == PICOKEYS_ERR_FILE_NOT_FOUND);
}

static void test_sidecar_detach(void) {
    static const uint8_t private_data[] = { 0x31, 0x32, 0x33 };
    static const uint8_t prkd[] = { 0xa0, 0x01, 0x01 };
    static const uint8_t certificate[] = { 0x7f, 0x21, 0x01, 0x42 };
    const uint8_t key_id = 0x4d;
    hsm_key_container_write_t writes[] = {
        test_write(HSM_KEY_OBJECT_PRIVATE, private_data, sizeof(private_data)),
        test_write(HSM_KEY_OBJECT_PRKD, prkd, sizeof(prkd)),
        test_write(HSM_KEY_OBJECT_CERTIFICATE, certificate, sizeof(certificate))
    };

    test_reset();
    assert(hsm_key_container_update(key_id, writes, sizeof(writes) / sizeof(writes[0])) == PICOKEYS_OK);
    assert(!file_search((PRKD_PREFIX << 8) | key_id));
    assert(!file_search((EE_CERTIFICATE_PREFIX << 8) | key_id));
    assert(hsm_key_container_detach_sidecars(key_id) == PICOKEYS_OK);
    assert(file_get_size(file_search((PRKD_PREFIX << 8) | key_id)) == sizeof(prkd));
    assert(memcmp(file_get_data(file_search((PRKD_PREFIX << 8) | key_id)), prkd, sizeof(prkd)) == 0);
    assert(file_get_size(file_search((EE_CERTIFICATE_PREFIX << 8) | key_id)) == sizeof(certificate));
    assert(memcmp(file_get_data(file_search((EE_CERTIFICATE_PREFIX << 8) | key_id)), certificate, sizeof(certificate)) == 0);
    assert(hsm_key_container_delete(key_id) == PICOKEYS_OK);
    assert(file_has_data(file_search((PRKD_PREFIX << 8) | key_id)));
    assert(file_has_data(file_search((EE_CERTIFICATE_PREFIX << 8) | key_id)));
}

static void test_existing_fid_collision(void) {
    static const uint8_t collision[] = { 0xde, 0xad };
    const uint8_t key_id = 0x5d;

    test_reset();
    assert(file_put_data(file_new(0xd000 | key_id), collision, sizeof(collision)) == PICOKEYS_OK);
    assert(!hsm_key_container_can_create(key_id));
    assert(!hsm_key_container_can_resume(key_id));
    assert(!hsm_key_container_physical_fid((KEY_PREFIX << 8) | key_id));
    assert(!hsm_key_container_physical_fid(0xd000 | key_id));
    assert(!hsm_key_container_physical_fid(0xe000));
    assert(file_put_data(file_new(0xe000), (const uint8_t *)"PKOR", 4) == PICOKEYS_OK);
    assert(hsm_key_container_physical_fid(0xe000));
}

int main(void) {
    test_compound_persistence_and_recovery();
    test_orphan_manifest_resume();
    test_policy_and_delete();
    test_sidecar_detach();
    test_existing_fid_collision();
    puts("hsm_key_container_test: OK");
    return 0;
}
