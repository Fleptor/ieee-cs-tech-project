#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

// Tell the compiler how to handle the SEC macro to define ELF sections
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif


#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define PORT_NBT_NS   137
#define PORT_SSDP     1900
#define PORT_WS_DISC  3702
#define PORT_MDNS     5353
#define PORT_LLMNR    5355

static __always_inline int is_private_ip(__u32 ip) {
    // Convert from network byte order to normal numbers
    __u32 h_ip = bpf_ntohl(ip); 
    
    // Check RFC1918 Private IP Ranges
    if ((h_ip >> 24) == 10) return 1;
    if ((h_ip >> 20) == ((172 << 4) | 16)) return 1;
    if ((h_ip >> 16) == ((192 << 8) | 168)) return 1;
    
    return 0; // It's a public IP
}



struct MAC_address {
    __u8 addr[6];
};
struct ipv6_address {
    __u8 addr[16];
};
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};
struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

//log struct for sending metadata for the user space
struct log_event {
    __u8 ip_version;
    __u16 protocol;
    __u8 flags;         // bitmasking {1->pass or drop, 2-> north south or east west, 3-> anomaly protocol, 4-> Legacy Hard Drop, if both 3&4 then Heuristic Telemetry }
    __u8 local_mac[6];
    __u8 padding;
    __u16 src_port;
    __u16 dst_port;
    __u8 src_ip[16];
    __u8 dst_ip[16];
};

//maps structs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2); // Key 0 = WAN, Key 1 = LAN
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





//log helper functions
static __always_inline int log_v4(__u16 protocol, __u8 *local_mac, __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u8 flags){
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev){
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version= 4;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        __builtin_memcpy(ev->local_mac, local_mac, 6);
        __builtin_memcpy(ev->src_ip, &src_ip, 4);
        __builtin_memcpy(ev->dst_ip, &dst_ip, 4);
        bpf_ringbuf_submit(ev, 0);
    }
    if (flags & 1) return XDP_PASS;
    return XDP_DROP;
}
static __always_inline int log_v6(__u16 protocol, __u8 *local_mac, void *src_ip, void *dst_ip, __u16 src_port, __u16 dst_port, __u8 flags){ 
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev){
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version= 6;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        __builtin_memcpy(ev->local_mac, local_mac, 6);
        __builtin_memcpy(ev->src_ip, src_ip, 16);
        __builtin_memcpy(ev->dst_ip, dst_ip, 16);
        bpf_ringbuf_submit(ev, 0);
    }
    if (flags & 1) return XDP_PASS;
    return XDP_DROP;
}




//handling layer 4 protocols
static __always_inline int Handle_TCP(struct iphdr *iph, void *data_end, __u8 *local_mac, __u8 flags){
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    if ((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) || (tcph->syn && tcph->fin) || (tcph->fin && tcph->psh && tcph->urg))
        return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags);
    return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags | 1);
}
static __always_inline int Handle_UDP(struct iphdr *iph, void *data_end, __u8 *local_mac, __u8 flags){
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    switch (dst_port) {
        case PORT_LLMNR:{
            struct dnshdr *dnsh = (void *)(udph + 1);
            if ((void *)(dnsh + 1) > data_end) return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1) return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags);
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags | 4);
        }
        case PORT_NBT_NS:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags | 8);
        case PORT_MDNS:
        case PORT_SSDP:
        case PORT_WS_DISC:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags | 13);// flags | 1 | 4 | 8
        default:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, flags | 1);

    }
}
static __always_inline int Handle_ICMP(struct iphdr *iph, void *data_end, __u8 *local_mac, __u8 flags){
    struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
    if ((void *)(icmph + 1) > data_end) return XDP_PASS;
    if (icmph->type == 8 || icmph->type == 0)
        return log_v4(IPPROTO_ICMP, local_mac, iph->saddr, iph->daddr, 0, 0, flags | 1);
    return log_v4(IPPROTO_ICMP, local_mac, iph->saddr, iph->daddr, 0, 0, flags);
}
static __always_inline int Handle_TCP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct tcphdr *tcph = (void *)(ipv6h +1);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    if ((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) || (tcph->syn && tcph->fin) || (tcph->fin && tcph->psh && tcph->urg))
        return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags);
    return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags | 1);
}
static __always_inline int Handle_UDP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct udphdr *udph = (void *)(ipv6h +1);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    switch (dst_port) {
        case PORT_LLMNR:{
            struct dnshdr *dnsh = (void *)(udph + 1);
            if ((void *)(dnsh + 1) > data_end) return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1) return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags);
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags | 4);
        }
        case PORT_NBT_NS:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags | 8);
        case PORT_MDNS:
        case PORT_SSDP:
        case PORT_WS_DISC:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags | 13);// flags | 1 | 4 | 8
        default:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, flags | 1);

    }
}
static __always_inline int Handle_ICMP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct icmp6hdr *icmpv6h = (void *)(ipv6h +1);
    if ((void *)(icmpv6h + 1) > data_end) return XDP_PASS;
    if ((icmpv6h->icmp6_type == 128 || icmpv6h->icmp6_type == 129) || (icmpv6h->icmp6_type >= 133 && icmpv6h->icmp6_type <= 136))
        return log_v6(IPPROTO_ICMPV6, local_mac, &ipv6h->saddr, &ipv6h->daddr, 0, 0, flags | 1);
    return log_v6(IPPROTO_ICMPV6, local_mac, &ipv6h->saddr, &ipv6h->daddr, 0, 0, flags);
}





// eBPF programs use SEC() macros to tell the ELF loader where to place the code
SEC("xdp")
int xdp_router_prog(struct xdp_md *ctx) {
    // 1. Establish boundaries
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 wan_key = 0;
    __u32 lan_key = 1;
    __u32 *wan_ifindex_ptr = bpf_map_lookup_elem(&Interface_Map, &wan_key);
    __u32 *lan_ifindex_ptr = bpf_map_lookup_elem(&Interface_Map, &lan_key);

    if (!wan_ifindex_ptr || !lan_ifindex_ptr) return XDP_PASS;

    __u32 WAN_IFINDEX = *wan_ifindex_ptr;
    __u32 LAN_IFINDEX = *lan_ifindex_ptr;
    __u8 *local_mac;
    __u8 flags = 0;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS; 

    if (ctx->ingress_ifindex == WAN_IFINDEX) {
        local_mac = eth->h_dest;
        flags = 2; // Inbound from Internet
    } else if (ctx->ingress_ifindex == LAN_IFINDEX) {
        local_mac = eth->h_source;
        // The is_private_ip check happens later once you extract the IP header
    } else
        return XDP_PASS;
    
    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_ARP: return XDP_PASS;
        case ETH_P_IP:{
            struct iphdr *iph = (void *)(eth + 1);
            if((void *)(iph + 1) > data_end) return XDP_PASS;
            switch (iph->protocol){
                case IPPROTO_TCP : return Handle_TCP(iph, data_end, local_mac, flags);
                case IPPROTO_UDP : return Handle_UDP(iph, data_end, local_mac, flags);
                case IPPROTO_ICMP : return Handle_ICMP(iph, data_end, local_mac, flags);
                default: return XDP_DROP;
            }
        };
        case ETH_P_IPV6:{
            struct ipv6hdr *ipv6h = (void *)(eth + 1);
            if((void *)(ipv6h + 1) > data_end) return XDP_PASS;
            switch (ipv6h->nexthdr){
                case IPPROTO_TCP : return Handle_TCP_v6(ipv6h, data_end, local_mac, flags);
                case IPPROTO_UDP : return Handle_UDP_v6(ipv6h, data_end, local_mac, flags);
                case IPPROTO_ICMPV6 : return Handle_ICMP_v6(ipv6h, data_end, local_mac, flags);
                default: return XDP_DROP;
            }
        };
    default: return XDP_DROP;
    }
}

// Required license definition for the kernel to load the program
char _license[] SEC("license") = "GPL";