// SPDX-License-Identifier: GPL-3.0
// XDR NDR — XDP Hardware-Level Packet Filter
// Runs at NIC driver level (r8169) for fastest possible packet inspection
// Actions: XDP_PASS, XDP_DROP, XDP_TX, redirect to analysis

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define ALERT_CRITICAL 3
#define ALERT_WARNING  2
#define ALERT_INFO     1

// --- NDR Event ---
struct ndr_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  alert_level;
    __u8  action;       // 0=pass, 1=drop
    __u8  event_type;   // 1=blocked_ip, 2=arp_spoof, 3=dns_tunnel, 4=new_mac
    __u32 pkt_len;
};

// --- Event ring buffer ---
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB
} ndr_events SEC(".maps");

// --- Blocked IP list (populated from userspace) ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);    // IPv4 address
    __type(value, __u8);   // 1 = drop
} ndr_blocked_ips SEC(".maps");

// --- Blocked ports ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);    // port number
    __type(value, __u8);   // 1 = drop
} ndr_blocked_ports SEC(".maps");

// --- Known MAC addresses (for ARP spoof detection) ---
struct mac_entry {
    __u8 mac[6];
    __u8 _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);              // IP address
    __type(value, struct mac_entry); // expected MAC
} known_macs SEC(".maps");

// --- Packet stats ---
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);  // 0=total, 1=passed, 2=dropped, 3=alerts
    __type(key, __u32);
    __type(value, __u64);
} pkt_stats SEC(".maps");

static __always_inline void update_stat(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&pkt_stats, &idx);
    if (val) __sync_fetch_and_add(val, 1);
}

static __always_inline void emit_ndr_event(
    __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 alert, __u8 action, __u8 evt_type, __u32 pkt_len)
{
    struct ndr_event *evt = bpf_ringbuf_reserve(&ndr_events, sizeof(*evt), 0);
    if (!evt) return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip    = src_ip;
    evt->dst_ip    = dst_ip;
    evt->src_port  = src_port;
    evt->dst_port  = dst_port;
    evt->protocol  = proto;
    evt->alert_level = alert;
    evt->action    = action;
    evt->event_type = evt_type;
    evt->pkt_len   = pkt_len;

    bpf_ringbuf_submit(evt, 0);
    update_stat(3);  // alerts
}

// ============================================================
// XDP Main Program — Runs at NIC hardware level
// ============================================================
SEC("xdp")
int xdr_ndr_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    update_stat(0);  // total packets

    // --- Parse Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // --- ARP Spoof Detection ---
    if (eth_proto == ETH_P_ARP) {
        // ARP packet: check sender IP-MAC binding
        // ARP header starts at eth+1
        struct arphdr_simple {
            __u16 ar_hrd;
            __u16 ar_pro;
            __u8  ar_hln;
            __u8  ar_pln;
            __u16 ar_op;
            __u8  ar_sha[6]; // sender MAC
            __u32 ar_sip;    // sender IP
            __u8  ar_tha[6]; // target MAC
            __u32 ar_tip;    // target IP
        } __attribute__((packed));

        struct arphdr_simple *arp = (void *)(eth + 1);
        if ((void *)(arp + 1) > data_end)
            return XDP_PASS;

        __u32 sender_ip = arp->ar_sip;
        struct mac_entry *known = bpf_map_lookup_elem(&known_macs, &sender_ip);
        if (known) {
            // Compare MACs
            int mismatch = 0;
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                if (known->mac[i] != arp->ar_sha[i])
                    mismatch = 1;
            }
            if (mismatch) {
                emit_ndr_event(sender_ip, 0, 0, 0, 0,
                    ALERT_CRITICAL, 1, 2, 0); // ARP spoof!
                update_stat(2);
                return XDP_DROP;
            }
        }
        update_stat(1);
        return XDP_PASS;
    }

    // --- IPv4 only from here ---
    if (eth_proto != ETH_P_IP) {
        update_stat(1);
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip  = ip->saddr;
    __u32 dst_ip  = ip->daddr;
    __u8  proto   = ip->protocol;
    __u32 pkt_len = data_end - data;

    // --- IP Blocklist Check ---
    __u8 *blocked_src = bpf_map_lookup_elem(&ndr_blocked_ips, &src_ip);
    if (blocked_src) {
        emit_ndr_event(src_ip, dst_ip, 0, 0, proto,
            ALERT_CRITICAL, 1, 1, pkt_len);
        update_stat(2);
        return XDP_DROP;
    }

    __u8 *blocked_dst = bpf_map_lookup_elem(&ndr_blocked_ips, &dst_ip);
    if (blocked_dst) {
        emit_ndr_event(src_ip, dst_ip, 0, 0, proto,
            ALERT_CRITICAL, 1, 1, pkt_len);
        update_stat(2);
        return XDP_DROP;
    }

    // --- TCP/UDP Port analysis ---
    __u16 src_port = 0, dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            update_stat(1);
            return XDP_PASS;
        }
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            update_stat(1);
            return XDP_PASS;
        }
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    // --- Port blocklist ---
    if (dst_port > 0) {
        __u8 *port_blocked = bpf_map_lookup_elem(&ndr_blocked_ports, &dst_port);
        if (port_blocked) {
            emit_ndr_event(src_ip, dst_ip, src_port, dst_port, proto,
                ALERT_WARNING, 1, 1, pkt_len);
            update_stat(2);
            return XDP_DROP;
        }
    }

    // --- DNS tunnel detection (port 53, large packets) ---
    if (dst_port == 53 && pkt_len > 512) {
        emit_ndr_event(src_ip, dst_ip, src_port, dst_port, proto,
            ALERT_WARNING, 0, 3, pkt_len);
        // Don't drop, just alert — could be legitimate EDNS
    }

    update_stat(1);  // passed
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
