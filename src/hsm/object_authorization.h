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

#ifndef _OBJECT_AUTHORIZATION_H_
#define _OBJECT_AUTHORIZATION_H_

#include "object_policy.h"

#define HSM_OBJECT_KEY_POLICY_ID 0x0101u

int hsm_object_authorization_context_build(bool internal_firmware, file_object_authorization_context_t *context);
const uint8_t *hsm_object_authorization_key_policy(size_t *policy_size);
bool hsm_object_authorization_key_operation(uint16_t operation, bool internal_firmware);
void hsm_object_authorization_session_invalidate(void);
uint32_t hsm_object_authorization_session_epoch(void);
void hsm_object_authorization_command_set_secure_messaging(bool active);

#endif // _OBJECT_AUTHORIZATION_H_
