/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include <cstring>

#include "Chain.hpp"
#include "Matcher.hpp"
#include "Rule.hpp"
#include "test.hpp"

extern "C" {
#include <linux/if_ether.h>

#include <bpf/libbpf.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/runtime.h>
}

namespace
{

constexpr uint8_t kInternetLog = BF_FLAG(BF_LOG_OPT_INTERNET);
constexpr uint8_t kTransportLog = BF_FLAG(BF_LOG_OPT_TRANSPORT);
constexpr size_t kArpPayloadLen = 28;

/**
 * Verify the internet header is only logged for packets with a supported L3
 * protocol: a non-IP packet must not log the previous packet's.
 */
static void internetHeader(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;
    bft::Packet arp;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_log_headers", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), kInternetLog,
                              {bf::Matcher::alwaysMatch()}));

    fd = bf_chain_logs_fd("test_log_headers");
    assert_true(fd >= 0);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    // IPv4: the internet header is logged
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::UDP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(kInternetLog, capture.entries.back().pkt.headers);

    // ARP isn't parsed by bpfilter: no internet header
    arp.len = bft::Ethernet().write(arp.data.data(), ETH_P_ARP);
    arp.len += kArpPayloadLen;
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP, arp,
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(0, capture.entries.back().pkt.headers);

    bft_assert_counter_eq("test_log_headers", 0, 2, -1);

    ring_buffer__free(rb);
}

/**
 * Verify the transport header is only logged for packets which have one: a
 * packet without an L4 header must not log the previous packet's.
 */
static void transportHeader(void **state)
{
    _cleanup_close_ int fd = -1;
    struct bft_log_capture capture;
    struct ring_buffer *rb;

    (void)state;

    BFT_CHAIN_SET(bf::Chain("test_log_headers", BF_HOOK_XDP, BF_VERDICT_ACCEPT)
                  << bf::Rule(BF_VERDICT_DROP, bf_counter(), kTransportLog,
                              {bf::Matcher::alwaysMatch()}));

    fd = bf_chain_logs_fd("test_log_headers");
    assert_true(fd >= 0);
    rb = ring_buffer__new(fd, bft_capture_log, &capture, nullptr);
    assert_non_null(rb);

    // TCP: the transport header is logged
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::TCP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(kTransportLog, capture.entries.back().pkt.headers);
    assert_int_equal(IPPROTO_TCP, capture.entries.back().l4_proto);

    // GRE isn't parsed by bpfilter: no transport header, but the protocol
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv4 {} / bft::GRE {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(0, capture.entries.back().pkt.headers);
    assert_int_equal(IPPROTO_GRE, capture.entries.back().l4_proto);

    // First fragment: the transport header is logged
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.more = true} / bft::UDP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(kTransportLog, capture.entries.back().pkt.headers);
    assert_int_equal(IPPROTO_UDP, capture.entries.back().l4_proto);

    // Non-first fragment: no transport header, but the protocol
    bft_assert_prog_run("test_log_headers", BF_HOOK_XDP,
                        bft::Ethernet() / bft::IPv6 {} /
                            bft::IPv6Fragment {.offset = 181} / bft::UDP {},
                        bft_hook_drop(BF_HOOK_XDP));
    assert_int_equal(1, ring_buffer__consume(rb));
    assert_int_equal(0, capture.entries.back().pkt.headers);
    assert_int_equal(IPPROTO_UDP, capture.entries.back().l4_proto);

    bft_assert_counter_eq("test_log_headers", 0, 4, -1);

    ring_buffer__free(rb);
}

} // namespace

int main()
{
    int r = bf_ctx_setup(false, "/sys/fs/bpf", 0);
    if (r != 0) {
        bf_err("failed to setup bpfilter context: %s", std::strerror(-r));
        return 1;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(internetHeader, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
        cmocka_unit_test_setup_teardown(transportHeader, bft_matcher_test_setup,
                                        bft_matcher_test_teardown),
    };

    r = cmocka_run_group_tests(tests, nullptr, nullptr);
    bf_ctx_teardown();

    return r;
}
