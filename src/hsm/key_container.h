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

#ifndef _KEY_CONTAINER_H_
#define _KEY_CONTAINER_H_

#include "object_container.h"

#define HSM_KEY_CONTAINER_KIND 0x0001u
#define HSM_KEY_OBJECT_PRIVATE 0x0001u
#define HSM_KEY_OBJECT_PRKD 0x0002u
#define HSM_KEY_OBJECT_CERTIFICATE 0x0003u
#define HSM_KEY_OBJECT_METADATA 0x0004u
#define HSM_KEY_OBJECT_POLICY 0x0005u
#define HSM_KEY_INTERNAL_POLICY_ID 0x01ffu

typedef struct hsm_key_container_write {
    uint16_t object_type;
    const uint8_t *data;
    uint32_t data_size;
    uint16_t policy_id;
    uint8_t key_domain;
    uint8_t protection;
    uint16_t flags;
} hsm_key_container_write_t;

bool hsm_key_container_is_marker(const file_t *file);
bool hsm_key_container_physical_fid(uint16_t fid);
bool hsm_key_container_can_create(uint8_t key_id);
bool hsm_key_container_can_resume(uint8_t key_id);
bool hsm_key_container_fid_object(uint16_t fid, uint16_t *object_type);
int hsm_key_container_update(uint8_t key_id, const hsm_key_container_write_t *writes, size_t write_count);
int hsm_key_container_store_object(uint8_t key_id, uint16_t object_type, const uint8_t *data, uint32_t data_size);
int hsm_key_container_object_size(uint8_t key_id, uint16_t object_type, bool internal_firmware, uint32_t *object_size);
int hsm_key_container_read(uint8_t key_id, uint16_t object_type, uint16_t operation, bool internal_firmware, uint8_t *data, size_t capacity, size_t *written);
int hsm_key_container_remove_object(uint8_t key_id, uint16_t object_type);
int hsm_key_container_detach_sidecars(uint8_t key_id);
int hsm_key_container_delete(uint8_t key_id);

#endif // _KEY_CONTAINER_H_
