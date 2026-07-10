#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "shared_defs.h"

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} Interface_Map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128 * 1024);
    __type(key, __u32);
    __type(value, __u32);
} Blocked_IPV4s SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32 * 1024);
    __type(key, struct ipv6_address);
    __type(value, __u32);
} Blocked_IPV6s SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, struct MAC_address);
    __type(value, __u8);
} MAC_list SEC(".maps");

static __always_inline int log_v4(__u16 protocol, __u8 *internal_mac, __u32 ip_addr, __u16 src_port, __u16 dst_port,__u16 payload_len, __u8 flags) {
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (likely(ev)) {
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version = 4;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        ev->payload_len = payload_len;
        __builtin_memcpy(ev->internal_mac, internal_mac, 6);
        __builtin_memcpy(ev->ip_addr, &ip_addr, 4);
        bpf_ringbuf_submit(ev, 0);  
    }
    if (flags & 1)
        return XDP_PASS;
    return XDP_DROP;
}

static __always_inline int log_v6(__u16 protocol, __u8 *internal_mac, void *ip_addr, __u16 src_port, __u16 dst_port,__u16 payload_len, __u8 flags) {
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (likely(ev)) {
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version = 6;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        ev->payload_len = payload_len;
        __builtin_memcpy(ev->internal_mac, internal_mac, 6);
        __builtin_memcpy(ev->ip_addr, ip_addr, 16);
        bpf_ringbuf_submit(ev, 0);
    }
    if (flags & 1)
        return XDP_PASS;
    return XDP_DROP;
}

static __always_inline int Handle_TCP(struct iphdr *iph, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);

    if (unlikely((void *)(tcph + 1) > data_end))
        return XDP_PASS;

    __u16 tcp_hdr_len = tcph->doff * 4;
    if (unlikely((void *)tcph + tcp_hdr_len > data_end))
        return XDP_PASS;

    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u16 ip_hdr_len = iph->ihl * 4;

    if (unlikely(ip_tot_len < ip_hdr_len + tcp_hdr_len))
        return XDP_PASS;

    __u16 payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
    __u32 ip_addr = (flags & F_WAN_OUT) ? iph->daddr : iph->saddr;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);

    if (unlikely((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) ||
        (tcph->syn && tcph->fin) ||
        (tcph->fin && tcph->psh && tcph->urg)))
        return log_v4(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags);

    switch (dst_port) {
        case PORT_FTP_DATA:
        case PORT_FTP_CMD:
        case PORT_TELNET:
        case PORT_NETBIOS_TCP:
            return log_v4(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
        case PORT_HTTP:
        case PORT_HTTPS:
        case PORT_SMB:
        case PORT_KERBEROS:
        case PORT_LDAP:
        case PORT_LDAPS:
        case PORT_MSSQL:
        case PORT_MYSQL:
        case PORT_POSTGRES:
        case PORT_SSH:
        case PORT_RDP:
            return log_v4(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        default:
            return log_v4(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}

static __always_inline int Handle_TCP_v6(struct ipv6hdr *ipv6h, __u16 ext_len, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct tcphdr *tcph = (void *)(ipv6h + 1) + ext_len;

    if (unlikely((void *)(tcph + 1) > data_end))
        return XDP_PASS;

    __u16 tcp_hdr_len = tcph->doff * 4;
    if (unlikely((void *)tcph + tcp_hdr_len > data_end))
        return XDP_PASS;

    __u16 ipv6_payload_len = bpf_ntohs(ipv6h->payload_len);
    if (unlikely(ipv6_payload_len < tcp_hdr_len + ext_len))
        return XDP_PASS;

    __u16 payload_len = ipv6_payload_len - tcp_hdr_len - ext_len;
    void *ip_addr = (flags & F_WAN_OUT) ? &ipv6h->daddr : &ipv6h->saddr;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);

    if (unlikely((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) ||
        (tcph->syn && tcph->fin) ||
        (tcph->fin && tcph->psh && tcph->urg)))
        return log_v6(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags);

    switch (dst_port) {
        case PORT_FTP_DATA:
        case PORT_FTP_CMD:
        case PORT_TELNET:
        case PORT_NETBIOS_TCP:
            return log_v6(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
        case PORT_HTTP:
        case PORT_HTTPS:
        case PORT_SMB:
        case PORT_KERBEROS:
        case PORT_LDAP:
        case PORT_LDAPS:
        case PORT_MSSQL:
        case PORT_MYSQL:
        case PORT_POSTGRES:
        case PORT_SSH:
        case PORT_RDP:
            return log_v6(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        default:
            return log_v6(IPPROTO_TCP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}

static __always_inline int Handle_UDP(struct iphdr *iph, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if (unlikely((void *)(udph + 1) > data_end))
        return XDP_PASS;
    __u32 ip_addr = (flags & F_WAN_OUT) ? iph->daddr : iph->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    if (unlikely(bpf_ntohs(udph->len) < sizeof(struct udphdr)))
        return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, 0, flags | F_ANOMALY);
    __u16 payload_len = bpf_ntohs(udph->len) - sizeof(struct udphdr);

    switch (dst_port) {
        case PORT_LLMNR: {
            struct dnshdr *dnsh = (void *)(udph + 1);
            if (unlikely((void *)(dnsh + 1) > data_end))
                return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1)
                return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags);
            return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_ANOMALY);
        }
    case PORT_NBT_NS:
    case PORT_TFTP:
        return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
    case PORT_SNMP:
    case PORT_SNMP_TRAP:
    case PORT_QUIC:
    case PORT_DNS:
    case PORT_MDNS:
    case PORT_SSDP:
    case PORT_WS_DISC:
        return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
    case PORT_DHCP_CLIENT: {
        if (likely(src_port == PORT_DHCP_SERVER)) {
            if (flags & F_WAN_IN)
                return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
            return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_INFRA_ALERT);
        }
        return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
    default:
        return log_v4(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}

static __always_inline int Handle_UDP_v6(struct ipv6hdr *ipv6h, __u16 ext_len, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct udphdr *udph = (void *)(ipv6h + 1) + ext_len;
    if (unlikely((void *)(udph + 1) > data_end))
        return XDP_PASS;
    void *ip_addr = (flags & F_WAN_OUT) ? &ipv6h->daddr : &ipv6h->saddr;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    if (unlikely(bpf_ntohs(udph->len) < sizeof(struct udphdr)))
        return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, 0, flags | F_ANOMALY);
    __u16 payload_len = bpf_ntohs(udph->len) - sizeof(struct udphdr);

    switch (dst_port) {
        case PORT_LLMNR: {
            struct dnshdr *dnsh = (void *)(udph + 1);
            if (unlikely((void *)(dnsh + 1) > data_end))
                return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1)
                return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags);
            return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_ANOMALY);
        }
    case PORT_NBT_NS:
    case PORT_TFTP:
        return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
    case PORT_SNMP:
    case PORT_SNMP_TRAP:
    case PORT_DNS:
    case PORT_MDNS:
    case PORT_SSDP:
    case PORT_WS_DISC:
        return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
    case PORT_DHCP_CLIENT: {
        if (likely(src_port == PORT_DHCP_SERVER)) {
            if (flags & F_WAN_IN)
                return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
            return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_INFRA_ALERT);
        }
        return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
    default:
        return log_v6(IPPROTO_UDP, internal_mac, ip_addr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}

static __always_inline int Handle_ICMP(struct iphdr *iph, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
    if (unlikely((void *)(icmph + 1) > data_end))
        return XDP_PASS;
    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u16 ip_hdr_len = iph->ihl * 4;
    if (unlikely(ip_tot_len < (ip_hdr_len + sizeof(struct icmphdr))))
        return XDP_PASS;
    __u16 payload_len = ip_tot_len - ip_hdr_len - sizeof(struct icmphdr);
    __u32 ip_addr = (flags & F_WAN_OUT) ? iph->daddr : iph->saddr;
    if (unlikely(payload_len > 1000))
        return log_v4(IPPROTO_ICMP, internal_mac, ip_addr, 0, 0, payload_len, flags | F_ANOMALY);
    return log_v4(IPPROTO_ICMP, internal_mac, ip_addr, 0, 0, payload_len, flags | F_PASS);
}

static __always_inline int Handle_ICMP_v6(struct ipv6hdr *ipv6h, __u16 ext_len, void *data_end, __u8 *internal_mac, __u8 flags) {
    struct icmp6hdr *icmpv6h = (void *)(ipv6h + 1) + ext_len;
    if (unlikely((void *)(icmpv6h + 1) > data_end))
        return XDP_PASS;
    __u16 ipv6_payload_len = bpf_ntohs(ipv6h->payload_len);
    if (unlikely(ipv6_payload_len < sizeof(struct icmp6hdr) + ext_len))
        return XDP_PASS;
    __u16 payload_len = ipv6_payload_len - sizeof(struct icmp6hdr) - ext_len;
    void *ip_addr = (flags & F_WAN_OUT) ? &ipv6h->daddr : &ipv6h->saddr;
    if (unlikely(payload_len > 1000))
        return log_v6(IPPROTO_ICMPV6, internal_mac, ip_addr, 0, 0, payload_len, flags | F_ANOMALY);
    return log_v6(IPPROTO_ICMPV6, internal_mac, ip_addr, 0, 0, payload_len, flags | F_PASS);
}

SEC("xdp")
int xdp_router_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 wan_key = 0;
    __u32 lan_key = 1;
    __u32 *wan_ifindex_ptr = bpf_map_lookup_elem(&Interface_Map, &wan_key);
    __u32 *lan_ifindex_ptr = bpf_map_lookup_elem(&Interface_Map, &lan_key);

    if (unlikely(!wan_ifindex_ptr || !lan_ifindex_ptr))
        return XDP_PASS;

    __u32 WAN_IFINDEX = *wan_ifindex_ptr;
    __u32 LAN_IFINDEX = *lan_ifindex_ptr;
    __u8 *internal_mac;
    __u8 flags = 0;
    __u8 router_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    struct ethhdr *eth = data;
    int hdr_offset = sizeof(*eth);

    if (unlikely((void *)eth + hdr_offset > data_end))
        return XDP_PASS;

    if (ctx->ingress_ifindex == WAN_IFINDEX) {
        internal_mac = eth->h_dest;
        flags |= F_WAN_IN;
    } else if (ctx->ingress_ifindex == LAN_IFINDEX) {
        internal_mac = eth->h_source;
        if ((__builtin_memcmp(eth->h_dest,router_mac,6)) == 0)
            flags |= F_WAN_OUT;
    } else
        return XDP_PASS;

    struct MAC_address search_mac;
    __builtin_memcpy(search_mac.addr, eth->h_source, 6);
    __u8 *is_banned = bpf_map_lookup_elem(&MAC_list, &search_mac);
    if (is_banned && *is_banned == 1)
        return XDP_DROP;

    __be16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan = (void *)eth + hdr_offset;
        hdr_offset += sizeof(*vlan);
        if (unlikely((void *)eth + hdr_offset > data_end))
            return XDP_PASS;
        h_proto = vlan->h_vlan_encapsulated_proto;
    }

    switch (bpf_ntohs(h_proto)) {
        case ETH_P_ARP:
            return XDP_PASS;
        case ETH_P_IP: {
            struct iphdr *iph = (void *)eth + hdr_offset;
            if (unlikely((void *)(iph + 1) > data_end))
                return XDP_PASS;

            __u32 src_ip = iph->saddr;
            __u32 *is_banned_ip = bpf_map_lookup_elem(&Blocked_IPV4s, &src_ip);
            if (is_banned_ip)
                return XDP_DROP;

            switch (iph->protocol) {
                case IPPROTO_TCP:
                    return Handle_TCP(iph, data_end, internal_mac, flags);
                case IPPROTO_UDP:
                    return Handle_UDP(iph, data_end, internal_mac, flags);
                case IPPROTO_ICMP:
                    return Handle_ICMP(iph, data_end, internal_mac, flags);
                default:
                    return XDP_PASS;
            }
        };
        case ETH_P_IPV6: {
            struct ipv6hdr *ipv6h = (void *)eth + hdr_offset;
            if (unlikely((void *)(ipv6h + 1) > data_end))
                return XDP_PASS;

            struct ipv6_address src_ipv6;
            __builtin_memcpy(src_ipv6.addr, &ipv6h->saddr, 16);
            __u32 *is_banned_ipv6 = bpf_map_lookup_elem(&Blocked_IPV6s, &src_ipv6);
            if (unlikely(is_banned_ipv6))
                return XDP_DROP;

            __u8 nexthdr = ipv6h->nexthdr;
            __u16 ext_len = 0;
            #pragma unroll
            for (int i = 0 ;i < 8; i++){
                if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP || nexthdr == IPPROTO_ICMPV6 || nexthdr == 59) break;
                struct ipv6_opt_hdr *ext = (void *)(ipv6h + 1) + ext_len;
                if ((void *)(ext + 1) > data_end) return XDP_PASS;
                nexthdr = ext->nexthdr;
                ext_len += (ext->hdrlen + 1) * 8 ;
                if (i == 6 - 1) {
                    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(struct log_event), 0);
                    if (ev) {
                        __builtin_memset(ev, 0, sizeof(*ev));
                        ev->flags = 8; 
                        __builtin_memcpy(ev->internal_mac, eth->h_source, ETH_ALEN);
                        bpf_ringbuf_submit(ev, 0);
                    }
                    return XDP_DROP; 
                }
            }
            switch (nexthdr){
                case IPPROTO_TCP : return Handle_TCP_v6(ipv6h, ext_len, data_end, internal_mac, flags);
                case IPPROTO_UDP : return Handle_UDP_v6(ipv6h, ext_len, data_end, internal_mac, flags);
                case IPPROTO_ICMPV6 : return Handle_ICMP_v6(ipv6h, ext_len, data_end, internal_mac, flags);
                default: return XDP_DROP;
            }
        };
        default:
            return XDP_PASS;
    }
}
char _license[] SEC("license") = "GPL";