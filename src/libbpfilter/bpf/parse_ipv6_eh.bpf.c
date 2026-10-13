/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

/* An extension header is at least 8 bytes long,
 * and an IPv6 payload at most 65535 bytes. */
#define BF_IPV6_EXT_MAX_CHAIN (65535 / 8)

// Fragment offset (in 8-byte units, shifted by 3) and More Fragments flag
#define BF_IPV6_FRAG_OFFSET 0xfff8
#define BF_IPV6_FRAG_MORE 0x0001

/* IPv6 Fragment header (RFC 8200, section 4.5): `struct frag_hdr` isn't part of
 * the kernel's uapi. */
struct bf_ipv6_frag_hdr
{
    __u8 nexthdr;
    __u8 reserved;
    __be16 frag_off;
    __be32 identification;
};

/* Same as cgen/packet.c */
#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

__u8 bf_parse_ipv6(struct bf_runtime *ctx)
{
    struct ipv6hdr *ip6hdr = ctx->l3_hdr;
    __u8 next_hdr_type = ip6hdr->nexthdr;

    ctx->l4_offset = ctx->l3_offset + sizeof(struct ipv6hdr);

    bpf_repeat (BF_IPV6_EXT_MAX_CHAIN) {
        switch (next_hdr_type) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_DSTOPTS:
        case IPPROTO_MH:
            break;
        default:
            // L4 protocol, even if its header is truncated
            return next_hdr_type;
        }

        if (next_hdr_type == IPPROTO_FRAGMENT) {
            struct bf_ipv6_frag_hdr _frag;
            const struct bf_ipv6_frag_hdr * const frag = bpf_dynptr_slice(
                &ctx->dynptr, ctx->l4_offset, &_frag, sizeof(_frag));

            if (!frag)
                return 0;

            ctx->ipv6_eh |= BF_IPV6_EH_FRAGMENT(1);

            const __u16 frag_off = bpf_ntohs(frag->frag_off);
            if (frag_off & BF_IPV6_FRAG_OFFSET) {
                // A non-first fragment carries payload, not headers
                ctx->frag = BF_FRAG_LATER;
                return frag->nexthdr;
            }
            if (frag_off & BF_IPV6_FRAG_MORE)
                ctx->frag = BF_FRAG_FIRST;

            // Fixed size: the second byte is reserved, not a length
            ctx->l4_offset += sizeof(*frag);
            next_hdr_type = frag->nexthdr;
            continue;
        }

        struct ipv6_opt_hdr _ext;
        const struct ipv6_opt_hdr * const ext =
            bpf_dynptr_slice(&ctx->dynptr, ctx->l4_offset, &_ext, sizeof(_ext));
        if (!ext)
            return 0;

        ctx->ipv6_eh |= (BF_IPV6_EH_HOPOPTS(next_hdr_type == IPPROTO_HOPOPTS) |
                         BF_IPV6_EH_ROUTING(next_hdr_type == IPPROTO_ROUTING) |
                         BF_IPV6_EH_AH(next_hdr_type == IPPROTO_AH) |
                         BF_IPV6_EH_DSTOPTS(next_hdr_type == IPPROTO_DSTOPTS) |
                         BF_IPV6_EH_MH(next_hdr_type == IPPROTO_MH));

        if (next_hdr_type == IPPROTO_AH)
            ctx->l4_offset += (ext->hdrlen + 2) * 4;
        else
            ctx->l4_offset += (ext->hdrlen + 1) * 8;

        next_hdr_type = ext->nexthdr;
    }

    // Only reached if the packet is bigger than an IPv6 payload can be
    return 0;
}
