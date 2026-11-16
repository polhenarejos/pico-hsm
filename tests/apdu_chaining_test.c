/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "apdu.h"
#include "led/led.h"
#include "usb.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEST_RX_BUFFER_SIZE 2048u
#define TEST_CCID_HEADER_SIZE 10u
#define TEST_CHAIN_CHUNK_SIZE 125u
#define TEST_CHAIN_DATA_MAX 2038u
#define TEST_RX_CANARY 0xa5u

typedef struct test_rx_buffer {
    uint8_t buffer[TEST_RX_BUFFER_SIZE];
    uint16_t r_ptr;
    uint16_t w_ptr;
} test_rx_buffer_t;

_Static_assert(offsetof(test_rx_buffer_t, r_ptr) == TEST_RX_BUFFER_SIZE, "CCID cursor offset changed");
_Static_assert(sizeof(test_rx_buffer_t) == TEST_RX_BUFFER_SIZE + 4u, "CCID buffer layout changed");

static test_rx_buffer_t rx[2];
static uint8_t response[TEST_RX_BUFFER_SIZE];
static uint8_t expected_payload[TEST_CHAIN_DATA_MAX];
static size_t expected_size;
static size_t expected_header_size;
static size_t expected_final_size;
static size_t expected_ring_offset;
static uint16_t expected_r_ptr;
static uint16_t expected_w_ptr;
static size_t append_size;
static size_t pad_size;
static unsigned int handler_calls;
static bool expect_staged_data;

static int test_process_apdu(void);

uint8_t num_apps;
app_t apps[16];
app_t *current_app;
uint32_t timeout;

static app_t test_app = {
    .aid = NULL,
    .process_apdu = test_process_apdu,
    .select_aid = NULL,
    .unload = NULL,
    .supports_secure_messaging = false,
};

void led_set_mode(uint32_t mode) {
    (void)mode;
}

bool app_exists(const_byte_array_t aid) {
    (void)aid;
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    (void)select_aid;
    (void)aid;
    return 0;
}

int select_app(const_byte_array_t aid) {
    (void)aid;
    return -1;
}

void timeout_stop(void) {
}

void driver_exec_finished_emul(uint8_t itf, uint16_t size_next) {
    (void)itf;
    (void)size_next;
}

void driver_exec_finished_cont_emul(uint8_t itf, uint16_t size_next, uint16_t offset) {
    (void)itf;
    (void)size_next;
    (void)offset;
}

static int test_process_apdu(void) {
    assert(apdu.nc == expected_size);
    assert((size_t)(apdu.data - apdu.header) == expected_header_size);
    assert(memcmp(apdu.data, expected_payload, expected_size) == 0);
    assert(apdu.header[0] == 0x00);
    assert(apdu.header[1] == 0x20);
    assert(apdu.header[2] == 0x00);
    assert(apdu.header[3] == 0x00);
    if (expected_header_size == 5 || expected_header_size == 7) {
        assert(apdu.data[-1] == (uint8_t)expected_final_size);
    }
    if (expect_staged_data) {
        uintptr_t data_address = (uintptr_t)apdu.data;
        uintptr_t rx_start = (uintptr_t)&rx[0];
        uintptr_t rx_end = (uintptr_t)&rx[2];

        assert(data_address < rx_start || data_address >= rx_end);
    }

    handler_calls++;
    if (append_size > 0) {
        memmove(apdu.data + append_size, apdu.data, apdu.nc);
        memset(apdu.data, 0x7f, append_size);
        apdu.nc += (uint32_t)append_size;
        assert(memcmp(apdu.data + append_size, expected_payload, expected_size) == 0);
    }
    if (pad_size > apdu.nc) {
        memset(apdu.data + apdu.nc, 0, pad_size - apdu.nc);
        for (size_t i = apdu.nc; i < pad_size; i++) {
            assert(apdu.data[i] == 0);
        }
        apdu.nc = (uint32_t)pad_size;
    }

    return SW_OK();
}

static void reset_test(size_t payload_size, size_t header_size, size_t ring_offset, uint16_t r_ptr, uint16_t w_ptr) {
    memset(rx, TEST_RX_CANARY, sizeof(rx));
    memset(response, 0, sizeof(response));
    memset(expected_payload, 0, sizeof(expected_payload));
    rx[0].r_ptr = r_ptr;
    rx[0].w_ptr = w_ptr;
    rx[1].buffer[0] = 0x5a;
    rx[1].buffer[1] = 0xc3;
    expected_size = payload_size;
    expected_header_size = header_size;
    expected_ring_offset = ring_offset;
    expected_r_ptr = r_ptr;
    expected_w_ptr = w_ptr;
    expected_final_size = 0;
    append_size = 0;
    pad_size = 0;
    handler_calls = 0;
    expect_staged_data = true;
    current_app = &test_app;

    for (size_t i = 0; i < payload_size; i++) {
        expected_payload[i] = (uint8_t)(i * 7u + 3u);
    }
}

static uint16_t send_apdu(uint8_t cla, bool extended, size_t ring_offset, const uint8_t *data, size_t data_size) {
    uint8_t *header = rx[0].buffer + ring_offset + TEST_CCID_HEADER_SIZE;
    size_t header_size = extended ? 7u : 5u;
    size_t apdu_size = header_size + data_size;

    assert(ring_offset + TEST_CCID_HEADER_SIZE + apdu_size <= sizeof(rx[0].buffer));
    memset(header, 0, header_size);
    header[0] = cla;
    header[1] = 0x20;
    header[2] = 0x00;
    header[3] = 0x00;
    if (extended) {
        header[4] = 0;
        header[5] = (uint8_t)(data_size >> 8);
        header[6] = (uint8_t)data_size;
    }
    else {
        assert(data_size <= UINT8_MAX);
        header[4] = (uint8_t)data_size;
    }
    if (data_size > 0) {
        memcpy(header + header_size, data, data_size);
    }

    apdu.rdata = response;
    apdu.rlen = 0;
    assert(apdu_process_ccid(0, CONST_BYTE_ARRAY(header, apdu_size)) == 1);
    return process_apdu();
}

static void assert_rx_unchanged(void) {
    assert(rx[0].r_ptr == expected_r_ptr);
    assert(rx[0].w_ptr == expected_w_ptr);
    assert(rx[1].buffer[0] == 0x5a);
    assert(rx[1].buffer[1] == 0xc3);
}

static void send_chain(size_t data_size, bool extended_final, size_t final_ring_offset) {
    size_t sent = 0;

    while (data_size - sent > TEST_CHAIN_CHUNK_SIZE) {
        size_t chunk_size = TEST_CHAIN_CHUNK_SIZE;

        assert(send_apdu(0x10, false, 0, expected_payload + sent, chunk_size) == 0x9000);
        sent += chunk_size;
    }
    if (sent == 0 && data_size > 1) {
        size_t chunk_size = data_size / 2;

        assert(send_apdu(0x10, false, 0, expected_payload, chunk_size) == 0x9000);
        sent = chunk_size;
    }

    expected_final_size = data_size - sent;
    uint16_t status = send_apdu(0x00, extended_final, final_ring_offset, expected_payload + sent, expected_final_size);
    assert(status == 0x9000);
}

static void test_short_maximum_chain(void) {
    reset_test(TEST_CHAIN_DATA_MAX - 1u, 5, 0, 52, 100);
    append_size = 5;
    send_chain(expected_size, false, 0);
    assert(handler_calls == 1);
    assert_rx_unchanged();
}

static void test_extended_chain_at_nonzero_ring_offset(void) {
    reset_test(TEST_CHAIN_DATA_MAX - 1u, 7, 1000, 1054, 1100);
    send_chain(expected_size, true, expected_ring_offset);
    assert(handler_calls == 1);
    assert_rx_unchanged();
}

static void test_small_chain_supports_rsa4096_padding(void) {
    reset_test(10, 5, 0, 20, 40);
    pad_size = 512;
    send_chain(expected_size, false, 0);
    assert(handler_calls == 1);
    assert_rx_unchanged();
}

static void test_maximum_unchained_apdu_preserves_ring_cursors(void) {
    reset_test(2031, 7, 0, 0, 2048);
    expected_final_size = expected_size;
    append_size = 5;
    assert(send_apdu(0x00, true, 0, expected_payload, expected_size) == 0x9000);
    assert(handler_calls == 1);
    assert_rx_unchanged();
}

static void test_oversized_chain_is_rejected(void) {
    reset_test(TEST_CHAIN_DATA_MAX, 5, 1000, 1055, 1100);
    size_t sent = 0;

    while (TEST_CHAIN_DATA_MAX - sent > TEST_CHAIN_CHUNK_SIZE) {
        assert(send_apdu(0x10, false, 0, expected_payload + sent, TEST_CHAIN_CHUNK_SIZE) == 0x9000);
        sent += TEST_CHAIN_CHUNK_SIZE;
    }
    expected_final_size = TEST_CHAIN_DATA_MAX - sent;
    assert(send_apdu(0x00, false, expected_ring_offset, expected_payload + sent, expected_final_size) == 0x6700);
    assert(handler_calls == 0);
    assert_rx_unchanged();
}

int main(void) {
    test_short_maximum_chain();
    test_extended_chain_at_nonzero_ring_offset();
    test_small_chain_supports_rsa4096_padding();
    test_maximum_unchained_apdu_preserves_ring_cursors();
    test_oversized_chain_is_rejected();
    return 0;
}
