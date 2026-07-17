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
#include "object_authorization.h"
#include "object_provider.h"
#include "sc_hsm.h"

static uint32_t hsm_object_session_epoch = 1;
static bool hsm_object_secure_messaging;

void hsm_object_authorization_session_invalidate(void) {
    hsm_object_secure_messaging = false;
    hsm_object_session_epoch++;
    if (hsm_object_session_epoch == 0) {
        hsm_object_session_epoch = 1;
    }
}

uint32_t hsm_object_authorization_session_epoch(void) {
    return hsm_object_session_epoch;
}

void hsm_object_authorization_command_set_secure_messaging(bool active) {
    hsm_object_secure_messaging = active;
}

int hsm_object_authorization_context_build(bool internal_firmware, file_object_authorization_context_t *context) {
    if (!context) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint32_t facts = FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND;
    if (internal_firmware) {
        facts |= FILE_OBJECT_FACT_INTERNAL_FIRMWARE;
    }
    else {
        if (isUserAuthenticated) {
            facts |= FILE_OBJECT_FACT_USER_VERIFICATION;
        }
        if (has_session_pin) {
            facts |= FILE_OBJECT_FACT_APP_PIN;
        }
        if (has_session_sopin) {
            facts |= FILE_OBJECT_FACT_ADMIN;
        }
        if (hsm_object_secure_messaging) {
            facts |= FILE_OBJECT_FACT_SECURE_MESSAGING;
        }
    }

    context->facts = facts;
    context->session_epoch = hsm_object_session_epoch;
    context->facts_epoch = hsm_object_session_epoch;
    context->caller_namespace = HSM_OBJECT_NAMESPACE;
    return PICOKEYS_OK;
}
