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

#include <assert.h>
#include <stdio.h>

bool isUserAuthenticated;
bool has_session_pin;
bool has_session_sopin;

static void test_state_reset(void) {
    isUserAuthenticated = false;
    has_session_pin = false;
    has_session_sopin = false;
    hsm_object_authorization_command_set_secure_messaging(false);
}

static void test_unauthenticated_context(void) {
    file_object_authorization_context_t context;

    test_state_reset();
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert(context.caller_namespace == HSM_OBJECT_NAMESPACE);
    assert(context.session_epoch != 0);
    assert(context.facts_epoch == context.session_epoch);
    assert(context.facts == (FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND));
}

static void test_authenticated_context(void) {
    file_object_authorization_context_t context;

    test_state_reset();
    isUserAuthenticated = true;
    has_session_pin = true;
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_USER_VERIFICATION) != 0);
    assert((context.facts & FILE_OBJECT_FACT_APP_PIN) != 0);
    assert((context.facts & FILE_OBJECT_FACT_ADMIN) == 0);

    has_session_pin = false;
    has_session_sopin = true;
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_USER_VERIFICATION) != 0);
    assert((context.facts & FILE_OBJECT_FACT_APP_PIN) == 0);
    assert((context.facts & FILE_OBJECT_FACT_ADMIN) != 0);

    has_session_sopin = false;
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_USER_VERIFICATION) != 0);
    assert((context.facts & (FILE_OBJECT_FACT_APP_PIN | FILE_OBJECT_FACT_ADMIN)) == 0);
}

static void test_secure_messaging_context(void) {
    file_object_authorization_context_t context;

    test_state_reset();
    hsm_object_authorization_command_set_secure_messaging(true);
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_SECURE_MESSAGING) != 0);

    hsm_object_authorization_command_set_secure_messaging(false);
    assert(hsm_object_authorization_context_build(false, &context) == PICOKEYS_OK);
    assert((context.facts & FILE_OBJECT_FACT_SECURE_MESSAGING) == 0);
}

static void test_internal_context(void) {
    file_object_authorization_context_t context;

    test_state_reset();
    isUserAuthenticated = true;
    has_session_pin = true;
    has_session_sopin = true;
    hsm_object_authorization_command_set_secure_messaging(true);
    assert(hsm_object_authorization_context_build(true, &context) == PICOKEYS_OK);
    assert(context.facts == (FILE_OBJECT_FACT_OWNING_APPLICATION | FILE_OBJECT_FACT_SESSION_BOUND | FILE_OBJECT_FACT_INTERNAL_FIRMWARE));
}

static void test_epoch_invalidation(void) {
    file_object_authorization_context_t before;
    file_object_authorization_context_t after;

    test_state_reset();
    assert(hsm_object_authorization_context_build(false, &before) == PICOKEYS_OK);
    assert(hsm_object_authorization_session_epoch() == before.session_epoch);
    hsm_object_authorization_session_invalidate();
    assert(hsm_object_authorization_context_build(false, &after) == PICOKEYS_OK);
    assert(after.session_epoch != before.session_epoch);
    assert(hsm_object_authorization_session_epoch() == after.session_epoch);
    assert(after.facts_epoch == after.session_epoch);
}

int main(void) {
    test_unauthenticated_context();
    test_authenticated_context();
    test_secure_messaging_context();
    test_internal_context();
    test_epoch_invalidation();
    assert(hsm_object_authorization_context_build(false, NULL) == PICOKEYS_ERR_NULL_PARAM);
    puts("hsm_object_authorization_test: OK");
    return 0;
}
