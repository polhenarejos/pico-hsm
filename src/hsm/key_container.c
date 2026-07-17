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
#define HSM_KEY_CONTAINER_MAX_MANIFEST_SIZE (FILE_OBJECT_MANIFEST_HEADER_SIZE + FILE_OBJECT_MANIFEST_MAX_OBJECTS * FILE_OBJECT_DESCRIPTOR_SIZE + FILE_OBJECT_AUTH_TAG_SIZE)

typedef struct hsm_key_manifest_candidate {
    file_object_manifest_t manifest;
    uint8_t slot;
    bool valid;
} hsm_key_manifest_candidate_t;

static const uint8_t hsm_key_container_marker_magic[4] = { 'P', 'K', 'H', '1' };
static const uint8_t hsm_key_allocator_marker_magic[4] = { 'P', 'K', 'A', '1' };

static bool hsm_key_allocator_marker_valid(void);
static int hsm_key_container_unseal(const file_object_manifest_t *manifest, const file_object_descriptor_t *object, const file_object_record_protector_t *protector, uint8_t *data, size_t capacity, size_t *written);

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

static int hsm_key_replace_file(uint16_t fid, const uint8_t *data, uint32_t data_size) {
    file_t *file = file_search(fid);
    if (file && file_delete_no_commit(file) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    file = file_new(fid);
    if (!file) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    return file_put_data(file, data, data_size);
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
    int r = hsm_key_replace_file(HSM_KEY_ALLOCATOR_MARKER_FID, hsm_key_allocator_marker_magic, sizeof(hsm_key_allocator_marker_magic));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int hsm_key_policy_hash(uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    const uint8_t *policy = NULL;
    size_t policy_size = 0;
    if (policy_id == HSM_OBJECT_KEY_POLICY_ID) {
        policy = hsm_object_authorization_key_policy(&policy_size);
    }
    else if (policy_id == HSM_KEY_INTERNAL_POLICY_ID) {
        policy = hsm_key_internal_policy;
        policy_size = sizeof(hsm_key_internal_policy);
    }
    else {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(policy, policy_size, hash);
}

static int hsm_key_manifest_parse_slot(uint8_t key_id, uint8_t slot, const file_object_authenticator_t *auth, hsm_key_manifest_candidate_t *candidate) {
    memset(candidate, 0, sizeof(*candidate));
    file_t *file = file_search(hsm_key_manifest_fid(key_id, slot));
    if (!file_has_data(file)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int r = file_object_manifest_parse(file_get_data(file), file_get_size(file), auth, NULL, NULL, &candidate->manifest);
    if (r != PICOKEYS_OK) {
        return r;
    }
    if (candidate->manifest.namespace_id != HSM_OBJECT_NAMESPACE || candidate->manifest.container_kind != HSM_KEY_CONTAINER_KIND || candidate->manifest.container_id != key_id || candidate->manifest.object_count == 0) {
        return PICOKEYS_WRONG_DATA;
    }
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        uint16_t record_fid = hsm_key_record_fid(object->record_id);
        file_t *record = file_search(record_fid);
        file_object_record_info_t info;
        if (record_fid == UINT16_MAX || !file_has_data(record) || file_object_record_header_parse(file_get_data(record), file_get_size(record), object, &info) != PICOKEYS_OK) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    candidate->slot = slot;
    candidate->valid = true;
    return PICOKEYS_OK;
}

static int hsm_key_manifest_load(uint8_t key_id, const file_object_authenticator_t *auth, hsm_key_manifest_candidate_t candidates[2], hsm_key_manifest_candidate_t **current) {
    bool found = false;
    bool storage_present = false;
    *current = NULL;
    for (uint8_t slot = 0; slot < 2; slot++) {
        storage_present |= file_has_data(file_search(hsm_key_manifest_fid(key_id, slot)));
        int r = hsm_key_manifest_parse_slot(key_id, slot, auth, &candidates[slot]);
        if (r == PICOKEYS_OK) {
            if (*current && (*current)->manifest.generation == candidates[slot].manifest.generation) {
                return PICOKEYS_WRONG_DATA;
            }
            if (!*current || candidates[slot].manifest.generation > (*current)->manifest.generation) {
                *current = &candidates[slot];
            }
            found = true;
        }
        else if (r != PICOKEYS_ERR_FILE_NOT_FOUND && r != PICOKEYS_WRONG_DATA && r != PICOKEYS_WRONG_SIGNATURE) {
            return r;
        }
    }
    if (!found) {
        return storage_present ? PICOKEYS_WRONG_DATA : PICOKEYS_ERR_FILE_NOT_FOUND;
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

bool hsm_key_container_can_resume(uint8_t key_id) {
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;

    return auth && hsm_key_manifest_load(key_id, auth, candidates, &current) == PICOKEYS_OK;
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

static int hsm_key_descriptor_compare(const void *left, const void *right) {
    const file_object_descriptor_t *a = (const file_object_descriptor_t *)left;
    const file_object_descriptor_t *b = (const file_object_descriptor_t *)right;
    if (a->object_type != b->object_type) {
        return a->object_type < b->object_type ? -1 : 1;
    }
    if (a->object_tag != b->object_tag) {
        return a->object_tag < b->object_tag ? -1 : 1;
    }
    return 0;
}

static file_object_descriptor_t *hsm_key_manifest_find(file_object_manifest_t *manifest, uint16_t object_type) {
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].object_type == object_type && manifest->objects[i].object_tag == 0) {
            return &manifest->objects[i];
        }
    }
    return NULL;
}

static bool hsm_key_manifest_references(const file_object_manifest_t *manifest, uint64_t record_id) {
    for (uint16_t i = 0; i < manifest->object_count; i++) {
        if (manifest->objects[i].record_id == record_id) {
            return true;
        }
    }
    return false;
}

static int hsm_key_manifest_records_validate(const hsm_key_manifest_candidate_t *candidate, const file_object_record_protector_t *protector) {
    for (uint16_t i = 0; i < candidate->manifest.object_count; i++) {
        const file_object_descriptor_t *object = &candidate->manifest.objects[i];
        uint8_t *plaintext = NULL;
        if (object->logical_size > 0) {
            plaintext = (uint8_t *)calloc(1, object->logical_size);
            if (!plaintext) {
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
        }
        size_t written = 0;
        int r = hsm_key_container_unseal(&candidate->manifest, object, protector, plaintext, object->logical_size, &written);
        if (plaintext) {
            mbedtls_platform_zeroize(plaintext, object->logical_size);
            free(plaintext);
        }
        if (r != PICOKEYS_OK || written != object->logical_size) {
            return r == PICOKEYS_OK ? PICOKEYS_WRONG_LENGTH : r;
        }
    }
    return PICOKEYS_OK;
}

static int hsm_key_record_write(uint8_t key_id, const hsm_key_container_write_t *write, uint32_t generation, const file_object_authenticator_t *auth, const file_object_record_protector_t *protector, file_object_descriptor_t *descriptor) {
    uint64_t record_id = 0;
    int r = hsm_key_record_id_allocate(auth, &record_id);
    if (r != PICOKEYS_OK) {
        return r;
    }
    *descriptor = (file_object_descriptor_t) {
        .object_type = write->object_type,
        .object_tag = 0,
        .generation = generation,
        .logical_size = write->data_size,
        .record_id = record_id,
        .stored_size = write->data_size,
        .policy_id = write->policy_id,
        .key_domain = write->key_domain,
        .protection = write->protection,
        .flags = write->flags
    };

    file_object_manifest_t record_manifest = {
        .namespace_id = HSM_OBJECT_NAMESPACE,
        .container_kind = HSM_KEY_CONTAINER_KIND,
        .container_id = key_id,
        .generation = generation,
        .previous_generation = generation > 1 ? generation - 1 : 0,
        .has_object = true,
        .object = *descriptor
    };
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    r = hsm_key_policy_hash(write->policy_id, policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    size_t record_size = FILE_OBJECT_RECORD_HEADER_SIZE + (size_t)write->data_size + FILE_OBJECT_AUTH_TAG_SIZE;
    uint8_t *record = (uint8_t *)calloc(1, record_size);
    if (!record) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    size_t written = 0;
    r = file_object_record_seal(&record_manifest, policy_hash, protector, write->data, write->data_size, record, record_size, &written);
    if (r == PICOKEYS_OK && written != record_size) {
        r = PICOKEYS_WRONG_LENGTH;
    }
    if (r == PICOKEYS_OK) {
        r = hsm_key_replace_file(hsm_key_record_fid(record_id), record, (uint32_t)record_size);
    }
    mbedtls_platform_zeroize(record, record_size);
    free(record);
    return r;
}

static int hsm_key_marker_write(uint8_t key_id) {
    uint8_t marker[HSM_KEY_CONTAINER_MARKER_SIZE] = { 'P', 'K', 'H', '1', 1, key_id, 0, 0 };
    int r = hsm_key_replace_file((HSM_OBJECT_PREFIX << 8) | key_id, marker, sizeof(marker));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

int hsm_key_container_update(uint8_t key_id, const hsm_key_container_write_t *writes, size_t write_count) {
    if (!writes || write_count == 0 || write_count > FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (!hsm_object_authorization_key_operation(FILE_OBJECT_OPERATION_UPDATE, false)) {
        return PICOKEYS_NO_LOGIN;
    }
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    const file_object_record_protector_t *protector = hsm_object_record_protector();
    if (!auth || !protector) {
        return PICOKEYS_EXEC_ERROR;
    }

    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;
    int r = hsm_key_manifest_load(key_id, auth, candidates, &current);
    if (r != PICOKEYS_OK && r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }
    if (current) {
        int current_status = hsm_key_manifest_records_validate(current, protector);
        hsm_key_manifest_candidate_t *previous = &candidates[current->slot ^ 1u];
        if (current_status != PICOKEYS_OK && previous->valid && hsm_key_manifest_records_validate(previous, protector) == PICOKEYS_OK) {
            current = previous;
        }
        else if (current_status != PICOKEYS_OK) {
            return current_status;
        }
    }
    bool creating = r == PICOKEYS_ERR_FILE_NOT_FOUND;
    if (creating && !hsm_key_container_can_create(key_id)) {
        return PICOKEYS_WRONG_DATA;
    }
    r = PICOKEYS_OK;

    file_object_manifest_t next = { 0 };
    if (current) {
        next = current->manifest;
        if (next.generation == UINT32_MAX || next.extension_size != 0) {
            return PICOKEYS_WRONG_DATA;
        }
        for (uint16_t i = 0; i < next.object_count; i++) {
            if (next.objects[i].extension_size != 0) {
                return PICOKEYS_WRONG_DATA;
            }
        }
        next.previous_generation = next.generation;
        next.generation++;
    }
    else {
        next.namespace_id = HSM_OBJECT_NAMESPACE;
        next.container_kind = HSM_KEY_CONTAINER_KIND;
        next.container_id = key_id;
        next.generation = 1;
    }

    uint64_t new_record_ids[FILE_OBJECT_MANIFEST_MAX_OBJECTS] = { 0 };
    size_t new_record_count = 0;
    for (size_t i = 0; i < write_count; i++) {
        const hsm_key_container_write_t *write = &writes[i];
        if ((!write->data && write->data_size > 0) || write->object_type == 0 || write->object_type == UINT16_MAX || (write->flags & FILE_OBJECT_FLAG_INLINE) != 0) {
            r = PICOKEYS_WRONG_DATA;
            break;
        }
        for (size_t j = 0; j < i; j++) {
            if (writes[j].object_type == write->object_type) {
                r = PICOKEYS_WRONG_DATA;
                break;
            }
        }
        if (r != PICOKEYS_OK) {
            break;
        }
        file_object_descriptor_t *object = hsm_key_manifest_find(&next, write->object_type);
        uint32_t object_generation = object ? object->generation + 1 : 1;
        if (object && object->generation == UINT32_MAX) {
            r = PICOKEYS_WRONG_DATA;
            break;
        }
        file_object_descriptor_t replacement;
        r = hsm_key_record_write(key_id, write, object_generation, auth, protector, &replacement);
        if (r != PICOKEYS_OK) {
            break;
        }
        new_record_ids[new_record_count++] = replacement.record_id;
        if (object) {
            *object = replacement;
        }
        else if (next.object_count < FILE_OBJECT_MANIFEST_MAX_OBJECTS) {
            next.objects[next.object_count++] = replacement;
            next.has_object = true;
        }
        else {
            r = PICOKEYS_ERR_NO_MEMORY;
            break;
        }
    }
    if (r == PICOKEYS_OK && !flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        for (size_t i = 0; i < new_record_count; i++) {
            file_t *record = file_search(hsm_key_record_fid(new_record_ids[i]));
            if (record) {
                file_delete_no_commit(record);
            }
        }
        flash_commit();
        return r;
    }

    qsort(next.objects, next.object_count, sizeof(next.objects[0]), hsm_key_descriptor_compare);
    uint8_t manifest_data[HSM_KEY_CONTAINER_MAX_MANIFEST_SIZE];
    size_t manifest_size = 0;
    r = file_object_manifest_build(&next, NULL, 0, auth, manifest_data, sizeof(manifest_data), &manifest_size);
    uint8_t target_slot = current ? current->slot ^ 1u : 0;
    if (r == PICOKEYS_OK) {
        r = hsm_key_replace_file(hsm_key_manifest_fid(key_id, target_slot), manifest_data, (uint32_t)manifest_size);
    }
    memset(manifest_data, 0, sizeof(manifest_data));
    if (r == PICOKEYS_OK && !flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        for (size_t i = 0; i < new_record_count; i++) {
            file_t *record = file_search(hsm_key_record_fid(new_record_ids[i]));
            if (record) {
                file_delete_no_commit(record);
            }
        }
        flash_commit();
        return r;
    }
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | key_id);
    if (!hsm_key_container_is_marker(marker)) {
        r = hsm_key_marker_write(key_id);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }

    hsm_key_manifest_candidate_t *overwritten = &candidates[target_slot];
    if (overwritten->valid) {
        for (uint16_t i = 0; i < overwritten->manifest.object_count; i++) {
            uint64_t record_id = overwritten->manifest.objects[i].record_id;
            if (!hsm_key_manifest_references(&next, record_id) && (!current || !hsm_key_manifest_references(&current->manifest, record_id))) {
                file_t *record = file_search(hsm_key_record_fid(record_id));
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
        flash_commit();
    }
    return PICOKEYS_OK;
}

int hsm_key_container_store_object(uint8_t key_id, uint16_t object_type, const uint8_t *data, uint32_t data_size) {
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
        .data_size = data_size,
        .policy_id = HSM_KEY_INTERNAL_POLICY_ID,
        .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
        .flags = FILE_OBJECT_FLAG_MUTABLE
    };
    if (object_type == HSM_KEY_OBJECT_PRKD || object_type == HSM_KEY_OBJECT_CERTIFICATE) {
        write.flags |= FILE_OBJECT_FLAG_GENERIC_READABLE;
    }
    return hsm_key_container_update(key_id, &write, 1);
}

static bool hsm_key_object_read_allowed(const file_object_descriptor_t *object, uint16_t operation, bool internal_firmware) {
    if (internal_firmware) {
        return true;
    }
    if (object->object_type == HSM_KEY_OBJECT_PRIVATE) {
        return hsm_object_authorization_key_operation(operation, false);
    }
    return operation == FILE_OBJECT_OPERATION_READ && object->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && (object->flags & FILE_OBJECT_FLAG_GENERIC_READABLE) != 0;
}

int hsm_key_container_object_size(uint8_t key_id, uint16_t object_type, bool internal_firmware, uint32_t *object_size) {
    if (!object_size) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *object_size = 0;
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;
    int r = hsm_key_manifest_load(key_id, auth, candidates, &current);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_object_descriptor_t *object = hsm_key_manifest_find(&current->manifest, object_type);
    if (!object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (!hsm_key_object_read_allowed(object, FILE_OBJECT_OPERATION_READ, internal_firmware)) {
        return PICOKEYS_NO_LOGIN;
    }
    *object_size = object->logical_size;
    return PICOKEYS_OK;
}

static int hsm_key_container_unseal(const file_object_manifest_t *manifest, const file_object_descriptor_t *object, const file_object_record_protector_t *protector, uint8_t *data, size_t capacity, size_t *written) {
    file_object_manifest_t record_manifest = *manifest;
    record_manifest.object_count = 1;
    record_manifest.has_object = true;
    record_manifest.object = *object;
    uint8_t policy_hash[FILE_OBJECT_POLICY_HASH_SIZE];
    int r = hsm_key_policy_hash(object->policy_id, policy_hash);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_t *record = file_search(hsm_key_record_fid(object->record_id));
    if (!file_has_data(record)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return file_object_record_unseal(&record_manifest, policy_hash, protector, file_get_data(record), file_get_size(record), data, capacity, written);
}

int hsm_key_container_read(uint8_t key_id, uint16_t object_type, uint16_t operation, bool internal_firmware, uint8_t *data, size_t capacity, size_t *written) {
    if ((!data && capacity > 0) || !written) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *written = 0;
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    const file_object_record_protector_t *protector = hsm_object_record_protector();
    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;
    int r = hsm_key_manifest_load(key_id, auth, candidates, &current);
    if (r != PICOKEYS_OK) {
        return r;
    }
    file_object_descriptor_t *current_object = hsm_key_manifest_find(&current->manifest, object_type);
    if (!current_object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    for (uint8_t attempt = 0; attempt < 2; attempt++) {
        hsm_key_manifest_candidate_t *candidate = attempt == 0 ? current : &candidates[current->slot ^ 1u];
        if (!candidate || !candidate->valid) {
            continue;
        }
        file_object_descriptor_t *object = attempt == 0 ? current_object : hsm_key_manifest_find(&candidate->manifest, object_type);
        if (!object) {
            continue;
        }
        if (!hsm_key_object_read_allowed(object, operation, internal_firmware)) {
            return PICOKEYS_NO_LOGIN;
        }
        r = hsm_key_container_unseal(&candidate->manifest, object, protector, data, capacity, written);
        if (r == PICOKEYS_OK) {
            return PICOKEYS_OK;
        }
    }
    if (data && capacity > 0) {
        memset(data, 0, capacity);
    }
    return r;
}

int hsm_key_container_remove_object(uint8_t key_id, uint16_t object_type) {
    if (object_type != HSM_KEY_OBJECT_PRKD && object_type != HSM_KEY_OBJECT_CERTIFICATE) {
        return PICOKEYS_WRONG_DATA;
    }
    if (!hsm_object_authorization_key_operation(FILE_OBJECT_OPERATION_DELETE, false)) {
        return PICOKEYS_NO_LOGIN;
    }
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    const file_object_record_protector_t *protector = hsm_object_record_protector();
    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;
    int r = hsm_key_manifest_load(key_id, auth, candidates, &current);
    if (r != PICOKEYS_OK) {
        return r;
    }
    int current_status = hsm_key_manifest_records_validate(current, protector);
    hsm_key_manifest_candidate_t *previous = &candidates[current->slot ^ 1u];
    if (current_status != PICOKEYS_OK && previous->valid && hsm_key_manifest_records_validate(previous, protector) == PICOKEYS_OK) {
        current = previous;
    }
    else if (current_status != PICOKEYS_OK) {
        return current_status;
    }

    file_object_manifest_t next = current->manifest;
    file_object_descriptor_t *object = hsm_key_manifest_find(&next, object_type);
    if (!object) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (next.generation == UINT32_MAX || next.object_count <= 1 || next.extension_size != 0 || object->extension_size != 0) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t object_index = (size_t)(object - next.objects);
    memmove(&next.objects[object_index], &next.objects[object_index + 1], (next.object_count - object_index - 1u) * sizeof(next.objects[0]));
    memset(&next.objects[next.object_count - 1u], 0, sizeof(next.objects[0]));
    next.object_count--;
    next.previous_generation = next.generation;
    next.generation++;

    uint8_t manifest_data[HSM_KEY_CONTAINER_MAX_MANIFEST_SIZE];
    size_t manifest_size = 0;
    r = file_object_manifest_build(&next, NULL, 0, auth, manifest_data, sizeof(manifest_data), &manifest_size);
    uint8_t target_slot = current->slot ^ 1u;
    if (r == PICOKEYS_OK) {
        r = hsm_key_replace_file(hsm_key_manifest_fid(key_id, target_slot), manifest_data, (uint32_t)manifest_size);
    }
    memset(manifest_data, 0, sizeof(manifest_data));
    if (r == PICOKEYS_OK && !flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS)) {
        r = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }

    hsm_key_manifest_candidate_t *overwritten = &candidates[target_slot];
    if (overwritten->valid) {
        for (uint16_t i = 0; i < overwritten->manifest.object_count; i++) {
            uint64_t record_id = overwritten->manifest.objects[i].record_id;
            if (!hsm_key_manifest_references(&next, record_id) && !hsm_key_manifest_references(&current->manifest, record_id)) {
                file_t *record = file_search(hsm_key_record_fid(record_id));
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
        flash_commit();
    }
    return PICOKEYS_OK;
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
        size_t written = 0;
        r = hsm_key_container_read(key_id, sidecars[i].object_type, FILE_OBJECT_OPERATION_READ, true, object_data, object_size, &written);
        if (r == PICOKEYS_OK && written != object_size) {
            r = PICOKEYS_WRONG_LENGTH;
        }
        if (r == PICOKEYS_OK) {
            r = hsm_key_replace_file((sidecars[i].prefix << 8) | key_id, object_data, object_size);
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
    const file_object_authenticator_t *auth = hsm_object_manifest_authenticator();
    hsm_key_manifest_candidate_t candidates[2];
    hsm_key_manifest_candidate_t *current = NULL;
    int r = hsm_key_manifest_load(key_id, auth, candidates, &current);
    if (r != PICOKEYS_OK) {
        return r;
    }
    (void)current;
    for (uint8_t slot = 0; slot < 2; slot++) {
        if (candidates[slot].valid) {
            for (uint16_t i = 0; i < candidates[slot].manifest.object_count; i++) {
                file_t *record = file_search(hsm_key_record_fid(candidates[slot].manifest.objects[i].record_id));
                if (record) {
                    file_delete_no_commit(record);
                }
            }
        }
        file_t *manifest = file_search(hsm_key_manifest_fid(key_id, slot));
        if (manifest) {
            file_delete_no_commit(manifest);
        }
    }
    file_t *marker = file_search((HSM_OBJECT_PREFIX << 8) | key_id);
    if (marker) {
        file_delete_no_commit(marker);
    }
    return flash_commit_sync(HSM_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}
