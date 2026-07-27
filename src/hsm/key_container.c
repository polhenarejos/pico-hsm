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
#include "object_container_store.h"
#include "object_authorization.h"
#include "object_provider.h"
#include "sc_hsm.h"

#define HSM_KEY_MANIFEST_SLOT_0_PREFIX 0xd0u
#define HSM_KEY_MANIFEST_SLOT_1_PREFIX 0xd1u
#define HSM_KEY_ALLOCATOR_MARKER_FID 0xd2efu
#define HSM_KEY_ALLOCATOR_RECORD_0_FID 0xd2f0u
#define HSM_KEY_ALLOCATOR_RECORD_1_FID 0xd2f1u
#define HSM_KEY_ALLOCATOR_COMMIT_0_FID 0xd2f2u
#define HSM_KEY_ALLOCATOR_COMMIT_1_FID 0xd2f3u
#define HSM_KEY_RECORD_FID_MIN 0xe000u
#define HSM_KEY_RECORD_FID_MASK 0x1fffu
#define HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS 5000u
#define HSM_KEY_CONTAINER_MARKER_SIZE 8u

static const uint8_t hsm_key_container_marker_magic[4] = { 'P', 'K', 'H', '1' };
static const uint8_t hsm_key_allocator_marker_magic[4] = { 'P', 'K', 'A', '1' };

static bool hsm_key_allocator_marker_valid(void);

static const uint8_t hsm_key_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static const file_object_txn_layout_t hsm_key_record_id_layout = {
    .namespace_id = HSM_OBJECT_NAMESPACE,
    .object_type = 0xfffeu,
    .object_id = 0,
    .record_fid = { HSM_KEY_ALLOCATOR_RECORD_0_FID, HSM_KEY_ALLOCATOR_RECORD_1_FID },
    .commit_fid = { HSM_KEY_ALLOCATOR_COMMIT_0_FID, HSM_KEY_ALLOCATOR_COMMIT_1_FID }
};

static uint16_t hsm_key_manifest_fid(uint8_t key_id, uint8_t slot) {
    return (uint16_t)(((slot == 0 ? HSM_KEY_MANIFEST_SLOT_0_PREFIX : HSM_KEY_MANIFEST_SLOT_1_PREFIX) << 8) | key_id);
}

static uint16_t hsm_key_record_fid(uint64_t record_id) {
    return (uint16_t)(HSM_KEY_RECORD_FID_MIN | (record_id & HSM_KEY_RECORD_FID_MASK));
}

static bool hsm_key_file_magic(uint16_t fid, const uint8_t magic[4]) {
    file_t *file = file_search(fid);
    return file_has_data(file) && file_get_size(file) >= 4 && memcmp(file_get_data(file), magic, 4) == 0;
}

bool hsm_key_container_physical_fid(uint16_t fid) {
    static const uint8_t manifest_magic[4] = { 'P', 'K', 'O', 'C' };
    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    static const uint8_t txn_record_magic[4] = { 'P', 'K', 'R', '2' };
    static const uint8_t txn_commit_magic[4] = { 'P', 'K', 'C', '2' };
    uint8_t prefix = (uint8_t)(fid >> 8);

    if (prefix == HSM_KEY_MANIFEST_SLOT_0_PREFIX || prefix == HSM_KEY_MANIFEST_SLOT_1_PREFIX) {
        uint8_t key_id = (uint8_t)fid;
        return hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id)) || hsm_key_file_magic(fid, manifest_magic);
    }
    if (fid == HSM_KEY_ALLOCATOR_MARKER_FID) {
        return hsm_key_file_magic(fid, hsm_key_allocator_marker_magic);
    }
    if (fid == HSM_KEY_ALLOCATOR_RECORD_0_FID || fid == HSM_KEY_ALLOCATOR_RECORD_1_FID) {
        return hsm_key_allocator_marker_valid() || hsm_key_file_magic(fid, txn_record_magic);
    }
    if (fid == HSM_KEY_ALLOCATOR_COMMIT_0_FID || fid == HSM_KEY_ALLOCATOR_COMMIT_1_FID) {
        return hsm_key_allocator_marker_valid() || hsm_key_file_magic(fid, txn_commit_magic);
    }
    return fid >= HSM_KEY_RECORD_FID_MIN && hsm_key_file_magic(fid, record_magic);
}

bool hsm_key_container_is_marker(const file_t *file) {
    if (!file_has_data(file) || file_get_size(file) != HSM_KEY_CONTAINER_MARKER_SIZE) {
        return false;
    }
    const uint8_t *data = file_get_data(file);
    return memcmp(data, hsm_key_container_marker_magic, sizeof(hsm_key_container_marker_magic)) == 0 && data[4] == 1 && data[5] == (uint8_t)file->fid && data[6] == 0 && data[7] == 0;
}

bool hsm_key_container_fid_object(uint16_t fid, uint16_t *object_type) {
    if (!object_type) {
        return false;
    }
    if ((fid >> 8) == PRKD_PREFIX) {
        *object_type = HSM_KEY_OBJECT_PRKD;
        return true;
    }
    if ((fid >> 8) == EE_CERTIFICATE_PREFIX) {
        *object_type = HSM_KEY_OBJECT_CERTIFICATE;
        return true;
    }
    return false;
}

static int hsm_key_replace_file(uint16_t fid, const_byte_array_t data) {
    file_t *file = file_search(fid);
    if (file && file_delete_no_commit(file) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    file = file_new(fid);
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    return file_put_data(file, data);
}

static bool hsm_key_allocator_marker_valid(void) {
    file_t *file = file_search(HSM_KEY_ALLOCATOR_MARKER_FID);
    return file_has_data(file) && file_get_size(file) == sizeof(hsm_key_allocator_marker_magic) && memcmp(file_get_data(file), hsm_key_allocator_marker_magic, sizeof(hsm_key_allocator_marker_magic)) == 0;
}

static int hsm_key_allocator_claim(void) {
    if (hsm_key_allocator_marker_valid()) {
        return PICOKEYS_OK;
    }
    if (file_search(HSM_KEY_ALLOCATOR_MARKER_FID) || file_search(HSM_KEY_ALLOCATOR_RECORD_0_FID) || file_search(HSM_KEY_ALLOCATOR_RECORD_1_FID) || file_search(HSM_KEY_ALLOCATOR_COMMIT_0_FID) || file_search(HSM_KEY_ALLOCATOR_COMMIT_1_FID)) {
        return PICOKEYS_WRONG_DATA;
    }
    int r = hsm_key_replace_file(HSM_KEY_ALLOCATOR_MARKER_FID, CONST_BYTE_ARRAY(hsm_key_allocator_marker_magic, sizeof(hsm_key_allocator_marker_magic)));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int hsm_key_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;
    const_byte_array_t policy = CONST_BYTE_ARRAY(NULL, 0);
    if (policy_id == HSM_OBJECT_KEY_POLICY_ID) {
        policy = hsm_object_authorization_key_policy();
    }
    else if (policy_id == HSM_KEY_INTERNAL_POLICY_ID) {
        policy = CONST_BYTE_ARRAY(hsm_key_internal_policy, sizeof(hsm_key_internal_policy));
    }
    else {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(policy, hash);
}

static uint16_t hsm_key_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;
    return hsm_key_manifest_fid((uint8_t)container_id, slot);
}

static int hsm_key_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;
    (void)container_id;
    if (!object || !fid) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = hsm_key_record_fid(object->record_id);
    if (*fid == UINT16_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    return PICOKEYS_OK;
}

bool hsm_key_container_can_create(uint8_t key_id) {
    if (file_search(hsm_key_manifest_fid(key_id, 0)) || file_search(hsm_key_manifest_fid(key_id, 1))) {
        return false;
    }
    if (hsm_key_allocator_marker_valid()) {
        return true;
    }
    return !file_search(HSM_KEY_ALLOCATOR_MARKER_FID) && !file_search(HSM_KEY_ALLOCATOR_RECORD_0_FID) && !file_search(HSM_KEY_ALLOCATOR_RECORD_1_FID) && !file_search(HSM_KEY_ALLOCATOR_COMMIT_0_FID) && !file_search(HSM_KEY_ALLOCATOR_COMMIT_1_FID);
}

static int hsm_key_record_id_allocate(const file_object_authenticator_t *auth, uint64_t *record_id) {
    int r = hsm_key_allocator_claim();
    if (r != PICOKEYS_OK) {
        return r;
    }
    for (uint32_t attempts = 0; attempts <= HSM_KEY_RECORD_FID_MASK; attempts++) {
        r = file_object_record_id_allocate(&hsm_key_record_id_layout, auth, record_id);
        if (r != PICOKEYS_OK) {
            return r;
        }
        uint16_t fid = hsm_key_record_fid(*record_id);
        if (fid != UINT16_MAX && !file_search(fid)) {
            return PICOKEYS_OK;
        }
    }
    *record_id = 0;
    return PICOKEYS_ERR_NO_MEMORY;
}

static int hsm_key_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)container_id;
    (void)target_slot;
    (void)write;
    if (!auth || !record_id || !fid) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    int r = hsm_key_record_id_allocate(auth, record_id);
    if (r != PICOKEYS_OK) {
        return r;
    }
    *fid = hsm_key_record_fid(*record_id);
    return PICOKEYS_OK;
}

static int hsm_key_marker_write(uint8_t key_id) {
    uint8_t marker[HSM_KEY_CONTAINER_MARKER_SIZE] = { 'P', 'K', 'H', '1', 1, key_id, 0, 0 };
    int r = hsm_key_replace_file((HSM_OBJECT_PREFIX << 8) | key_id, CONST_BYTE_ARRAY(marker, sizeof(marker)));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int hsm_key_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;
    uint8_t key_id = (uint8_t)container_id;
    if (hsm_key_container_is_marker(file_search((HSM_OBJECT_PREFIX << 8) | key_id))) {
        return PICOKEYS_OK;
    }
    return hsm_key_marker_write(key_id);
}

static int hsm_key_layout_deactivate(void *ctx, uint32_t container_id) {
    (void)ctx;
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | (uint8_t)container_id);
    if (!marker) {
        return PICOKEYS_OK;
    }
    return file_delete_no_commit(marker);
}

static int hsm_key_layout_retire(void *ctx, uint32_t container_id, const file_object_container_state_t *state, const file_object_manifest_t *next, uint8_t current_slot, uint8_t target_slot) {
    (void)ctx;
    (void)container_id;
    if (!state->candidates[target_slot].valid) {
        return PICOKEYS_OK;
    }
    const file_object_manifest_t *current = current_slot < FILE_OBJECT_CONTAINER_SLOT_COUNT ? &state->candidates[current_slot].manifest : NULL;
    const file_object_manifest_t *overwritten = &state->candidates[target_slot].manifest;
    for (uint16_t i = 0; i < overwritten->object_count; i++) {
        uint64_t record_id = overwritten->objects[i].record_id;
        if (!file_object_container_references(next, record_id) && (!current || !file_object_container_references(current, record_id))) {
            file_t *record = file_search(hsm_key_record_fid(record_id));
            if (record) {
                file_delete_no_commit(record);
            }
        }
    }
    flash_commit();
    return PICOKEYS_OK;
}

static const file_object_container_layout_t hsm_key_container_layout = {
    .namespace_id = HSM_OBJECT_NAMESPACE,
    .container_kind = HSM_KEY_CONTAINER_KIND,
    .commit_timeout_ms = HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS,
    .manifest_fid = hsm_key_layout_manifest_fid,
    .record_fid = hsm_key_layout_record_fid,
    .record_allocate = hsm_key_layout_record_allocate,
    .policy_hash = hsm_key_policy_hash,
    .activate = hsm_key_layout_activate,
    .deactivate = hsm_key_layout_deactivate,
    .retire = hsm_key_layout_retire,
    .rollback_new_records = true
};

static bool hsm_key_crypto(file_object_container_crypto_t *crypto) {
    crypto->auth = hsm_object_manifest_authenticator();
    crypto->protector = hsm_object_record_protector();
    return crypto->auth && crypto->protector;
}

bool hsm_key_container_can_resume(uint8_t key_id) {
    file_object_container_crypto_t crypto;
    file_object_container_state_t state;
    return hsm_key_crypto(&crypto) && file_object_container_load(&hsm_key_container_layout, key_id, &crypto, NULL, &state) == PICOKEYS_OK;
}

int hsm_key_container_update(uint8_t key_id, const hsm_key_container_write_t *writes, size_t write_count) {
    if (!writes || write_count == 0 || write_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!hsm_object_authorization_key_operation(FILE_OBJECT_OPERATION_UPDATE, false)) {
        return PICOKEYS_NO_LOGIN;
    }
    file_object_container_crypto_t crypto;
    if (!hsm_key_crypto(&crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (!file_has_data(file_search(hsm_key_manifest_fid(key_id, 0))) && !file_has_data(file_search(hsm_key_manifest_fid(key_id, 1))) && !hsm_key_container_can_create(key_id)) {
        return PICOKEYS_WRONG_DATA;
    }
    file_object_container_write_t container_writes[FILE_OBJECT_MANIFEST_MAX_OBJECTS];
    for (size_t i = 0; i < write_count; i++) {
        container_writes[i] = (file_object_container_write_t) {
            .object_type = writes[i].object_type,
            .data = writes[i].data,
            .policy_id = writes[i].policy_id,
            .key_domain = writes[i].key_domain,
            .protection = writes[i].protection,
            .flags = writes[i].flags
        };
    }
    return file_object_container_update(&hsm_key_container_layout, key_id, container_writes, write_count, &crypto, NULL);
}

int hsm_key_container_store_object(uint8_t key_id, uint16_t object_type, const_byte_array_t data) {
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | key_id);
    if (!hsm_key_container_is_marker(marker)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (object_type != HSM_KEY_OBJECT_PRKD && object_type != HSM_KEY_OBJECT_CERTIFICATE && object_type != HSM_KEY_OBJECT_METADATA) {
        return PICOKEYS_WRONG_DATA;
    }
    hsm_key_container_write_t write = {
        .object_type = object_type,
        .data = data,
        .policy_id = HSM_KEY_INTERNAL_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
        .flags = FILE_OBJECT_FLAG_MUTABLE
    };
    if (object_type == HSM_KEY_OBJECT_PRKD || object_type == HSM_KEY_OBJECT_CERTIFICATE) {
        write.flags |= FILE_OBJECT_FLAG_GENERIC_READABLE;
    }
    return hsm_key_container_update(key_id, &write, 1);
}

typedef struct hsm_key_access_context {
    uint16_t operation;
    bool internal_firmware;
} hsm_key_access_context_t;

static int hsm_key_object_access(void *ctx, const file_object_descriptor_t *object) {
    const hsm_key_access_context_t *access = (const hsm_key_access_context_t *)ctx;
    if (access->internal_firmware) {
        return PICOKEYS_OK;
    }
    if (object->object_type == HSM_KEY_OBJECT_PRIVATE) {
        return hsm_object_authorization_key_operation(access->operation, false) ? PICOKEYS_OK : PICOKEYS_NO_LOGIN;
    }
    bool readable = access->operation == FILE_OBJECT_OPERATION_READ && object->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && (object->flags & FILE_OBJECT_FLAG_GENERIC_READABLE) != 0;
    return readable ? PICOKEYS_OK : PICOKEYS_NO_LOGIN;
}

int hsm_key_container_object_size(uint8_t key_id, uint16_t object_type, bool internal_firmware, uint32_t *object_size) {
    file_object_container_crypto_t crypto;
    if (!hsm_key_crypto(&crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    hsm_key_access_context_t access = {
        .operation = FILE_OBJECT_OPERATION_READ,
        .internal_firmware = internal_firmware
    };
    return file_object_container_object_size(&hsm_key_container_layout, key_id, object_type, 0, &crypto, NULL, hsm_key_object_access, &access, object_size);
}

int hsm_key_container_read(uint8_t key_id, uint16_t object_type, uint16_t operation, bool internal_firmware, byte_buffer_t *data) {
    file_object_container_crypto_t crypto;
    if (!hsm_key_crypto(&crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    hsm_key_access_context_t access = {
        .operation = operation,
        .internal_firmware = internal_firmware
    };
    return file_object_container_read(&hsm_key_container_layout, key_id, object_type, 0, &crypto, NULL, hsm_key_object_access, &access, data);
}

int hsm_key_container_remove_object(uint8_t key_id, uint16_t object_type) {
    if (object_type != HSM_KEY_OBJECT_PRKD && object_type != HSM_KEY_OBJECT_CERTIFICATE) {
        return PICOKEYS_WRONG_DATA;
    }
    if (!hsm_object_authorization_key_operation(FILE_OBJECT_OPERATION_DELETE, false)) {
        return PICOKEYS_NO_LOGIN;
    }
    file_object_container_crypto_t crypto;
    if (!hsm_key_crypto(&crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_remove(&hsm_key_container_layout, key_id, object_type, 0, &crypto, NULL);
}

int hsm_key_container_detach_sidecars(uint8_t key_id) {
    static const struct {
        uint16_t object_type;
        uint8_t prefix;
    } sidecars[] = {
        { HSM_KEY_OBJECT_PRKD, PRKD_PREFIX },
        { HSM_KEY_OBJECT_CERTIFICATE, EE_CERTIFICATE_PREFIX }
    };

    for (size_t i = 0; i < sizeof(sidecars) / sizeof(sidecars[0]); i++) {
        uint32_t object_size = 0;
        int r = hsm_key_container_object_size(key_id, sidecars[i].object_type, true, &object_size);
        if (r == PICOKEYS_ERR_FILE_NOT_FOUND) {
            continue;
        }
        if (r != PICOKEYS_OK) {
            return r;
        }
        uint8_t *object_data = NULL;
        if (object_size > 0) {
            object_data = (uint8_t *)calloc(1, object_size);
            if (!object_data) {
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
        }
        byte_buffer_t output = BYTE_BUFFER(object_data, object_size);
        r = hsm_key_container_read(key_id, sidecars[i].object_type, FILE_OBJECT_OPERATION_READ, true, &output);
        if (r == PICOKEYS_OK && output.len != object_size) {
            r = PICOKEYS_WRONG_LENGTH;
        }
        if (r == PICOKEYS_OK) {
            r = hsm_key_replace_file((sidecars[i].prefix << 8) | key_id, CONST_BYTE_ARRAY(object_data, object_size));
        }
        free(object_data);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }
    return PICOKEYS_OK;
}

int hsm_key_container_delete(uint8_t key_id) {
    if (!hsm_object_authorization_key_operation(FILE_OBJECT_OPERATION_DELETE, false)) {
        return PICOKEYS_NO_LOGIN;
    }
    file_object_container_crypto_t crypto;
    if (!hsm_key_crypto(&crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_delete(&hsm_key_container_layout, key_id, &crypto, NULL);
}
