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
#include "object_policy.h"
#include "object_provider.h"
#include "sc_hsm.h"

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#define TEST_FILE_COUNT 64u
#define TEST_FILE_CAPACITY 1024u
#define TEST_MANIFEST_CAPACITY (FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_MANIFEST_MAX_OBJECTS * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)

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
static jmp_buf test_power_loss_env;
static size_t test_power_loss_event;
static size_t test_power_loss_at = SIZE_MAX;
static bool test_power_loss_armed;

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
    test_power_loss_event = 0;
    test_power_loss_at = SIZE_MAX;
    test_power_loss_armed = false;
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
    test_power_loss_armed = false;
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

int file_read_at(const file_t *file, uint32_t offset, byte_array_t data) {
    const test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data.data && data.len > 0) || offset > test_file->size || data.len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (data.len > 0) {
        memcpy(data.data, test_file->storage + offset, data.len);
    }
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const_byte_array_t data) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data.data && data.len > 0) || data.len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (data.len > 0) {
        memcpy(test_file->storage, data.data, data.len);
    }
    test_file->size = data.len;
    test_file->file.data = data.len > 0 ? test_file->storage : NULL;
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
    test_power_loss_event++;
    if (test_power_loss_armed && test_power_loss_event == test_power_loss_at) {
        test_power_loss_armed = false;
        longjmp(test_power_loss_env, 1);
    }
    test_persist();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    test_power_loss_event++;
    if (test_power_loss_armed && test_power_loss_event == test_power_loss_at) {
        test_power_loss_armed = false;
        longjmp(test_power_loss_env, 1);
    }
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

static int test_auth_update(void *ctx, const_byte_array_t data) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || (!data.data && data.len > 0)) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < data.len; i++) {
        for (size_t word = 0; word < 4; word++) {
            auth->state[word] ^= data.data[i] + (uint8_t)word;
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

static int test_record_tag(const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const_byte_array_t stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = test_auth_start(&test_auth_context);
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, CONST_BYTE_ARRAY(&test_protector_context.key, sizeof(test_protector_context.key)));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, CONST_BYTE_ARRAY(nonce, FILE_OBJECT_RECORD_NONCE_SIZE));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, CONST_BYTE_ARRAY(aad, FILE_OBJECT_RECORD_AAD_SIZE));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, stored);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_finish(&test_auth_context, tag);
    }
    return r;
}

static int test_record_seal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const_byte_array_t plaintext, byte_buffer_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    if (!stored || stored->len > stored->capacity || stored->capacity - stored->len < plaintext.len) {
        return PICOKEYS_WRONG_LENGTH;
    }
    for (size_t i = 0; i < plaintext.len; i++) {
        stored->data[stored->len + i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? plaintext.data[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : plaintext.data[i];
    }
    int r = test_record_tag(nonce, aad, CONST_BYTE_ARRAY(stored->data + stored->len, plaintext.len), tag);
    if (r == PICOKEYS_OK) {
        stored->len += plaintext.len;
    }
    return r;
}

static int test_record_unseal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const_byte_array_t stored, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], byte_buffer_t *plaintext) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    if (!plaintext || plaintext->len > plaintext->capacity || plaintext->capacity - plaintext->len < stored.len) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint8_t calculated[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = test_record_tag(nonce, aad, stored, calculated);
    if (r == PICOKEYS_OK && memcmp(calculated, tag, sizeof(calculated)) != 0) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    if (r == PICOKEYS_OK) {
        for (size_t i = 0; i < stored.len; i++) {
            plaintext->data[plaintext->len + i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? stored.data[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : stored.data[i];
        }
        plaintext->len += stored.len;
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

const_byte_array_t hsm_object_authorization_key_policy(void) {
    return CONST_BYTE_ARRAY(test_key_policy, sizeof(test_key_policy));
}

bool hsm_object_authorization_key_operation(uint16_t operation, bool internal_firmware) {
    test_last_operation = operation;
    test_last_internal = internal_firmware;
    return test_authorized;
}

static hsm_key_container_write_t test_write(uint16_t object_type, const_byte_array_t data) {
    hsm_key_container_write_t write = {
        .object_type = object_type,
        .data = data,
        .policy_id = object_type == HSM_KEY_OBJECT_PRIVATE ? HSM_OBJECT_KEY_POLICY_ID : HSM_KEY_INTERNAL_POLICY_ID,
        .protection = object_type == HSM_KEY_OBJECT_PRIVATE ? FILE_OBJECT_PROTECTION_AEAD_SECRET : FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC
    };
    if (object_type == HSM_KEY_OBJECT_PRKD || object_type == HSM_KEY_OBJECT_CERTIFICATE) {
        write.flags = FILE_OBJECT_FLAG_GENERIC_READABLE;
    }
    return write;
}

static void test_read(uint8_t key_id, uint16_t object_type, const_byte_array_t expected) {
    uint8_t output[128] = { 0 };
    byte_buffer_t output_buffer = BYTE_BUFFER(output, sizeof(output));
    bool internal = object_type != HSM_KEY_OBJECT_PRIVATE;
    assert(expected.len <= sizeof(output));
    assert(hsm_key_container_read(key_id, object_type, FILE_OBJECT_OPERATION_SIGN, internal, &output_buffer) == PICOKEYS_OK);
    assert(output_buffer.len == expected.len);
    assert(memcmp(output, expected.data, expected.len) == 0);
}

static void test_compound_persistence_and_recovery(void) {
    static const uint8_t private_first[] = { 1, 2, 3, 4, 5 };
    static const uint8_t private_second[] = { 6, 7, 8, 9 };
    static const uint8_t prkd[] = { 0x30, 0x03, 0x01, 0x02, 0x03 };
    static const uint8_t metadata[] = { 0x90, 0x01, 0x7f };
    const uint8_t key_id = 0x2a;
    hsm_key_container_write_t initial[] = {
        test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first))),
        test_write(HSM_KEY_OBJECT_PRKD, CONST_BYTE_ARRAY(prkd, sizeof(prkd))),
        test_write(HSM_KEY_OBJECT_POLICY, CONST_BYTE_ARRAY(test_key_policy, sizeof(test_key_policy)))
    };

    test_reset();
    assert(hsm_key_container_can_create(key_id));
    assert(hsm_key_container_update(key_id, initial, sizeof(initial) / sizeof(initial[0])) == PICOKEYS_OK);
    assert(hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first)));
    assert(test_last_operation == FILE_OBJECT_OPERATION_SIGN);
    assert(!test_last_internal);
    test_read(key_id, HSM_KEY_OBJECT_PRKD, CONST_BYTE_ARRAY(prkd, sizeof(prkd)));
    uint8_t public_output[sizeof(prkd)] = { 0 };
    byte_buffer_t public_buffer = BYTE_BUFFER(public_output, sizeof(public_output));
    uint32_t public_size = 0;
    assert(hsm_key_container_object_size(key_id, HSM_KEY_OBJECT_PRKD, false, &public_size) == PICOKEYS_OK);
    assert(public_size == sizeof(prkd));
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRKD, FILE_OBJECT_OPERATION_READ, false, &public_buffer) == PICOKEYS_OK);
    assert(public_buffer.len == sizeof(prkd));
    assert(memcmp(public_output, prkd, sizeof(prkd)) == 0);

    test_reboot();
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first)));

    hsm_key_container_write_t replacement = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_second, sizeof(private_second)));
    assert(hsm_key_container_update(key_id, &replacement, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_second, sizeof(private_second)));
    test_read(key_id, HSM_KEY_OBJECT_PRKD, CONST_BYTE_ARRAY(prkd, sizeof(prkd)));

    test_file_t *new_record = test_file_from_handle(file_search(0xe004));
    assert(new_record && new_record->size > FILE_OBJECT_RECORD_HEADER_SIZE);
    new_record->storage[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x80;
    test_persist();
    test_reboot();
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first)));

    hsm_key_container_write_t metadata_write = test_write(HSM_KEY_OBJECT_METADATA, CONST_BYTE_ARRAY(metadata, sizeof(metadata)));
    assert(hsm_key_container_update(key_id, &metadata_write, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first)));
    test_read(key_id, HSM_KEY_OBJECT_METADATA, CONST_BYTE_ARRAY(metadata, sizeof(metadata)));
    assert(hsm_key_container_object_size(key_id, HSM_KEY_OBJECT_METADATA, false, &public_size) == PICOKEYS_NO_LOGIN);
    assert(hsm_key_container_remove_object(key_id, HSM_KEY_OBJECT_PRKD) == PICOKEYS_OK);
    public_buffer = BYTE_BUFFER(public_output, sizeof(public_output));
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRKD, FILE_OBJECT_OPERATION_READ, true, &public_buffer) == PICOKEYS_ERR_FILE_NOT_FOUND);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_first, sizeof(private_first)));
}

static void test_orphan_manifest_resume(void) {
    static const uint8_t private_data[] = { 0x11, 0x22, 0x33 };
    static const uint8_t certificate[] = { 0x30, 0x01, 0x42 };
    const uint8_t key_id = 0x3b;
    hsm_key_container_write_t private_write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data)));

    test_reset();
    assert(hsm_key_container_update(key_id, &private_write, 1) == PICOKEYS_OK);
    assert(file_delete_no_commit(file_search((HSM_OBJECT_PREFIX << 8) | key_id)) == PICOKEYS_OK);
    flash_commit();
    test_reboot();
    assert(hsm_key_container_can_resume(key_id));

    hsm_key_container_write_t certificate_write = test_write(HSM_KEY_OBJECT_CERTIFICATE, CONST_BYTE_ARRAY(certificate, sizeof(certificate)));
    assert(hsm_key_container_update(key_id, &certificate_write, 1) == PICOKEYS_OK);
    assert(hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data)));
    test_read(key_id, HSM_KEY_OBJECT_CERTIFICATE, CONST_BYTE_ARRAY(certificate, sizeof(certificate)));
}

static void test_policy_and_delete(void) {
    static const uint8_t private_data[] = { 0xaa, 0xbb };
    const uint8_t key_id = 0x4c;
    hsm_key_container_write_t write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data)));
    uint8_t output[8];
    byte_buffer_t output_buffer = BYTE_BUFFER(output, sizeof(output));

    test_reset();
    test_authorized = false;
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_UPDATE);

    test_authorized = true;
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_OK);
    test_authorized = false;
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRIVATE, FILE_OBJECT_OPERATION_EXPORT, false, &output_buffer) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_EXPORT);
    assert(hsm_key_container_delete(key_id) == PICOKEYS_NO_LOGIN);
    assert(test_last_operation == FILE_OBJECT_OPERATION_DELETE);

    test_authorized = true;
    assert(hsm_key_container_delete(key_id) == PICOKEYS_OK);
    assert(!file_has_data(file_search((HSM_OBJECT_PREFIX << 8) | key_id)));
    output_buffer = BYTE_BUFFER(output, sizeof(output));
    assert(hsm_key_container_read(key_id, HSM_KEY_OBJECT_PRIVATE, FILE_OBJECT_OPERATION_USE, false, &output_buffer) == PICOKEYS_ERR_FILE_NOT_FOUND);
}

static void test_sidecar_detach(void) {
    static const uint8_t private_data[] = { 0x31, 0x32, 0x33 };
    static const uint8_t prkd[] = { 0xa0, 0x01, 0x01 };
    static const uint8_t certificate[] = { 0x7f, 0x21, 0x01, 0x42 };
    const uint8_t key_id = 0x4d;
    hsm_key_container_write_t writes[] = {
        test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data))),
        test_write(HSM_KEY_OBJECT_PRKD, CONST_BYTE_ARRAY(prkd, sizeof(prkd))),
        test_write(HSM_KEY_OBJECT_CERTIFICATE, CONST_BYTE_ARRAY(certificate, sizeof(certificate)))
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

static void test_existing_container_fixture(void) {
    static const uint8_t private_data[] = { 0x81, 0x82, 0x83, 0x84 };
    static const uint8_t certificate[] = { 0x30, 0x02, 0x01, 0x01 };
    const uint8_t key_id = 0x5a;
    const uint64_t record_id = 0x0321u;
    const uint16_t record_fid = 0xe321u;
    const uint16_t manifest_fid = (uint16_t)(0xd000u | key_id);
    file_object_descriptor_t descriptor = {
        .object_type = HSM_KEY_OBJECT_PRIVATE,
        .generation = 1,
        .logical_size = sizeof(private_data),
        .record_id = record_id,
        .stored_size = sizeof(private_data),
        .policy_id = HSM_OBJECT_KEY_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET
    };
    file_object_manifest_t manifest = {
        .namespace_id = HSM_OBJECT_NAMESPACE,
        .container_kind = HSM_KEY_CONTAINER_KIND,
        .container_id = key_id,
        .generation = 1,
        .object_count = 1,
        .has_object = true,
        .object = descriptor
    };
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    uint8_t record[FILE_OBJECT_RECORD_HEADER_SIZE + sizeof(private_data) + FILE_OBJECT_AUTH_TAG_SIZE];
    uint8_t manifest_data[TEST_MANIFEST_CAPACITY];
    uint8_t marker[] = { 'P', 'K', 'H', '1', 1, key_id, 0, 0 };
    byte_buffer_t record_buffer = BYTE_BUFFER(record, sizeof(record));
    byte_buffer_t manifest_buffer = BYTE_BUFFER(manifest_data, sizeof(manifest_data));

    test_reset();
    assert(file_object_policy_hash(CONST_BYTE_ARRAY(test_key_policy, sizeof(test_key_policy)), policy_hash) == PICOKEYS_OK);
    assert(file_object_record_seal(&manifest, policy_hash, &test_protector, CONST_BYTE_ARRAY(private_data, sizeof(private_data)), &record_buffer) == PICOKEYS_OK);
    assert(file_object_manifest_build(&manifest, CONST_BYTE_ARRAY(NULL, 0), &test_auth, &manifest_buffer) == PICOKEYS_OK);
    assert(file_put_data(file_new(record_fid), CONST_BYTE_ARRAY(record, record_buffer.len)) == PICOKEYS_OK);
    assert(file_put_data(file_new(manifest_fid), CONST_BYTE_ARRAY(manifest_data, manifest_buffer.len)) == PICOKEYS_OK);
    assert(file_put_data(file_new((uint16_t)((HSM_OBJECT_PREFIX << 8) | key_id)), CONST_BYTE_ARRAY(marker, sizeof(marker))) == PICOKEYS_OK);
    test_persist();
    test_reboot();

    assert(hsm_key_container_can_resume(key_id));
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data)));
    assert(file_get_size(file_search(record_fid)) == record_buffer.len);
    assert(memcmp(file_get_data(file_search(record_fid)), record, record_buffer.len) == 0);
    assert(file_get_size(file_search(manifest_fid)) == manifest_buffer.len);
    assert(memcmp(file_get_data(file_search(manifest_fid)), manifest_data, manifest_buffer.len) == 0);

    hsm_key_container_write_t write = test_write(HSM_KEY_OBJECT_CERTIFICATE, CONST_BYTE_ARRAY(certificate, sizeof(certificate)));
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(private_data, sizeof(private_data)));
    test_read(key_id, HSM_KEY_OBJECT_CERTIFICATE, CONST_BYTE_ARRAY(certificate, sizeof(certificate)));
    assert(file_get_size(file_search(record_fid)) == record_buffer.len);
    assert(memcmp(file_get_data(file_search(record_fid)), record, record_buffer.len) == 0);
    assert(file_get_size(file_search(manifest_fid)) == manifest_buffer.len);
    assert(memcmp(file_get_data(file_search(manifest_fid)), manifest_data, manifest_buffer.len) == 0);
}

static bool test_read_matches(uint8_t key_id, uint16_t object_type, const_byte_array_t first, const_byte_array_t second) {
    uint8_t output[32] = { 0 };
    byte_buffer_t output_buffer = BYTE_BUFFER(output, sizeof(output));
    int r = hsm_key_container_read(key_id, object_type, FILE_OBJECT_OPERATION_SIGN, false, &output_buffer);
    if (r != PICOKEYS_OK) {
        return false;
    }
    return (output_buffer.len == first.len && memcmp(output, first.data, first.len) == 0) || (output_buffer.len == second.len && memcmp(output, second.data, second.len) == 0);
}

static void test_power_loss_create_event(size_t failed_event) {
    static const uint8_t private_data[] = { 0x91, 0x92, 0x93 };
    static const const_byte_array_t private_array = {
        .data = private_data,
        .len = sizeof(private_data)
    };
    const uint8_t key_id = 0x61;
    hsm_key_container_write_t write = test_write(HSM_KEY_OBJECT_PRIVATE, private_array);

    test_reset();
    if (setjmp(test_power_loss_env) == 0) {
        test_power_loss_event = 0;
        test_power_loss_at = failed_event;
        test_power_loss_armed = true;
        (void)hsm_key_container_update(key_id, &write, 1);
        assert(false);
    }
    test_reboot();

    bool recoverable = hsm_key_container_can_create(key_id) || hsm_key_container_can_resume(key_id);
    assert(recoverable);
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_array);
}

static void test_power_loss_update_event(size_t failed_event) {
    static const uint8_t first[] = { 0xa1, 0xa2 };
    static const uint8_t second[] = { 0xb1, 0xb2, 0xb3 };
    static const uint8_t final[] = { 0xc1, 0xc2, 0xc3, 0xc4 };
    static const const_byte_array_t second_array = {
        .data = second,
        .len = sizeof(second)
    };
    static const const_byte_array_t final_array = {
        .data = final,
        .len = sizeof(final)
    };
    const uint8_t key_id = 0x62;
    hsm_key_container_write_t first_write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(first, sizeof(first)));
    hsm_key_container_write_t second_write = test_write(HSM_KEY_OBJECT_PRIVATE, second_array);
    hsm_key_container_write_t final_write = test_write(HSM_KEY_OBJECT_PRIVATE, final_array);

    test_reset();
    assert(hsm_key_container_update(key_id, &first_write, 1) == PICOKEYS_OK);
    assert(hsm_key_container_update(key_id, &second_write, 1) == PICOKEYS_OK);
    if (setjmp(test_power_loss_env) == 0) {
        test_power_loss_event = 0;
        test_power_loss_at = failed_event;
        test_power_loss_armed = true;
        (void)hsm_key_container_update(key_id, &final_write, 1);
        assert(false);
    }
    test_reboot();

    assert(test_read_matches(key_id, HSM_KEY_OBJECT_PRIVATE, second_array, final_array));
    assert(hsm_key_container_update(key_id, &final_write, 1) == PICOKEYS_OK);
    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, final_array);
}

static void test_power_loss_delete_event(size_t failed_event) {
    static const uint8_t private_data[] = { 0xd1, 0xd2, 0xd3 };
    static const const_byte_array_t private_array = {
        .data = private_data,
        .len = sizeof(private_data)
    };
    const uint8_t key_id = 0x63;
    hsm_key_container_write_t write = test_write(HSM_KEY_OBJECT_PRIVATE, private_array);

    test_reset();
    assert(hsm_key_container_update(key_id, &write, 1) == PICOKEYS_OK);
    if (setjmp(test_power_loss_env) == 0) {
        test_power_loss_event = 0;
        test_power_loss_at = failed_event;
        test_power_loss_armed = true;
        (void)hsm_key_container_delete(key_id);
        assert(false);
    }
    test_reboot();

    test_read(key_id, HSM_KEY_OBJECT_PRIVATE, private_array);
    assert(hsm_key_container_delete(key_id) == PICOKEYS_OK);
}

static void test_power_loss_boundaries(void) {
    static const uint8_t first[] = { 0xe1 };
    static const uint8_t second[] = { 0xe2 };
    static const uint8_t final[] = { 0xe3 };
    const uint8_t key_id = 0x64;
    hsm_key_container_write_t first_write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(first, sizeof(first)));
    hsm_key_container_write_t second_write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(second, sizeof(second)));
    hsm_key_container_write_t final_write = test_write(HSM_KEY_OBJECT_PRIVATE, CONST_BYTE_ARRAY(final, sizeof(final)));

    test_reset();
    assert(hsm_key_container_update(key_id, &first_write, 1) == PICOKEYS_OK);
    size_t create_events = test_power_loss_event;
    assert(create_events > 0);

    assert(hsm_key_container_update(key_id, &second_write, 1) == PICOKEYS_OK);
    test_power_loss_event = 0;
    assert(hsm_key_container_update(key_id, &final_write, 1) == PICOKEYS_OK);
    size_t update_events = test_power_loss_event;
    assert(update_events > 0);

    test_power_loss_event = 0;
    assert(hsm_key_container_delete(key_id) == PICOKEYS_OK);
    size_t delete_events = test_power_loss_event;
    assert(delete_events > 0);

    for (size_t failed_event = 1; failed_event <= create_events; failed_event++) {
        test_power_loss_create_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= update_events; failed_event++) {
        test_power_loss_update_event(failed_event);
    }
    for (size_t failed_event = 1; failed_event <= delete_events; failed_event++) {
        test_power_loss_delete_event(failed_event);
    }
}

static void test_existing_fid_collision(void) {
    static const uint8_t collision[] = { 0xde, 0xad };
    const uint8_t key_id = 0x5d;

    test_reset();
    assert(file_put_data(file_new(0xd000 | key_id), CONST_BYTE_ARRAY(collision, sizeof(collision))) == PICOKEYS_OK);
    assert(!hsm_key_container_can_create(key_id));
    assert(!hsm_key_container_can_resume(key_id));
    assert(!hsm_key_container_physical_fid((KEY_PREFIX << 8) | key_id));
    assert(!hsm_key_container_physical_fid(0xd000 | key_id));
    assert(!hsm_key_container_physical_fid(0xe000));
    assert(file_put_data(file_new(0xe000), CONST_BYTE_ARRAY((const uint8_t *)"PKOR", 4)) == PICOKEYS_OK);
    assert(hsm_key_container_physical_fid(0xe000));
}

int main(void) {
    test_compound_persistence_and_recovery();
    test_orphan_manifest_resume();
    test_policy_and_delete();
    test_sidecar_detach();
    test_existing_container_fixture();
    test_power_loss_boundaries();
    test_existing_fid_collision();
    puts("hsm_key_container_test: OK");
    return 0;
}
