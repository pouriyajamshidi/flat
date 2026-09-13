// Packet header layouts never change, so skip CO-RE and its need for kernel BTF
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// vmlinux.h only has types, so the macros we need are defined here
#define ETH_P_IP         0x0800
#define ETH_P_IPV6       0x86DD
#define TC_ACT_OK        0
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512 KB
} pipe SEC(".maps");

struct packet_t {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ttl;
    bool syn;
    bool ack;
    __u64 ts;
};

static inline int handle_ip_packet(void* head, void* tail, __u32* offset, struct packet_t* pkt) {
    struct ethhdr* eth = head;
    struct iphdr* ip;
    struct ipv6hdr* ipv6;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        if (head + sizeof(struct ethhdr) + sizeof(struct iphdr) > tail) { // If the next layer is not IP, let the packet pass
            return TC_ACT_OK;
        }

        ip = head + sizeof(struct ethhdr);

        if (ip->ihl < 5) { // Malformed header
            return TC_ACT_OK;
        }

        // IHL is in 4-byte words and includes any IP options
        *offset = sizeof(struct ethhdr) + ip->ihl * 4;

        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        // Create IPv4-Mapped IPv6 Address
        pkt->src_ip.in6_u.u6_addr32[3] = ip->saddr;
        pkt->dst_ip.in6_u.u6_addr32[3] = ip->daddr;

        // Pad the field before IP address with all Fs just like the RFC
        pkt->src_ip.in6_u.u6_addr16[5] = 0xffff;
        pkt->dst_ip.in6_u.u6_addr16[5] = 0xffff;

        pkt->protocol = ip->protocol;
        pkt->ttl = ip->ttl;

        return 1; // We have a TCP or UDP packet!

    case ETH_P_IPV6:
        *offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

        if (head + (*offset) > tail) {
            return TC_ACT_OK;
        }

        ipv6 = head + sizeof(struct ethhdr);

        if (ipv6->nexthdr != IPPROTO_TCP && ipv6->nexthdr != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        pkt->src_ip = ipv6->saddr;
        pkt->dst_ip = ipv6->daddr;

        pkt->protocol = ipv6->nexthdr;
        pkt->ttl = ipv6->hop_limit;

        return 1; // We have a TCP or UDP packet!

    default:
        return TC_ACT_OK;
    }
}

static inline int handle_ip_segment(void* head, void* tail, __u32* offset, struct packet_t* pkt) {
    struct tcphdr* tcp;
    struct udphdr* udp;

    switch (pkt->protocol) {
    case IPPROTO_TCP:
        if (head + *offset + sizeof(struct tcphdr) > tail) {
            return TC_ACT_OK;
        }

        tcp = head + *offset;

        if (!tcp->syn) { // We only care about SYN and SYN/ACK
            return TC_ACT_OK;
        }

        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        pkt->syn = tcp->syn;
        pkt->ack = tcp->ack;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    case IPPROTO_UDP:
        if (head + *offset + sizeof(struct udphdr) > tail) {
            return TC_ACT_OK;
        }

        udp = head + *offset;

        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    default:
        return TC_ACT_OK;
    }
}

SEC("tc")
int flat(struct __sk_buff* skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        return TC_ACT_OK;
    }

    // We only want unicast packets
    if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
        return TC_ACT_OK;
    }

    void* head = (void*)(long)skb->data;     // Start of the packet data
    void* tail = (void*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        return TC_ACT_OK;
    }

    struct packet_t* pkt = NULL;
    pkt = bpf_ringbuf_reserve(&pipe, sizeof(struct packet_t), 0);
    if (!pkt) {
        return TC_ACT_OK;
    }

    // Zero-initialize the memory region of pkt
    // so that we do not access garbage
    __builtin_memset(pkt, 0, sizeof(struct packet_t));

    __u32 offset = 0;

    if (handle_ip_packet(head, tail, &offset, pkt) == TC_ACT_OK) {
        bpf_ringbuf_discard(pkt, 0);
        return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, pkt) == TC_ACT_OK) {
        bpf_ringbuf_discard(pkt, 0);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(pkt, 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
