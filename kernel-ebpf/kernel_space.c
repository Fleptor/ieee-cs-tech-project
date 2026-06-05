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
#define PORT_NBT_NS        137
#define PORT_SSDP          1900
#define PORT_WS_DISC       3702
#define PORT_MDNS          5353
#define PORT_LLMNR         5355
#define PORT_DHCP_SERVER   67
#define PORT_DHCP_CLIENT   68
#define PORT_DNS           53
#define PORT_TFTP          69
#define PORT_SNMP          161
#define PORT_SNMP_TRAP     162
#define PORT_QUIC          443
#define PORT_NETBIOS_TCP   139
#define PORT_SMB           445
#define PORT_FTP_DATA      20
#define PORT_FTP_CMD       21
#define PORT_SSH           22
#define PORT_TELNET        23
#define PORT_RDP           3389
#define PORT_HTTP          80
#define PORT_HTTPS         443
#define PORT_KERBEROS      88
#define PORT_LDAP          389
#define PORT_LDAPS         636
#define PORT_MSSQL         1433
#define PORT_MYSQL         3306
#define PORT_POSTGRES      5432

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
    __u8 src_ip[16];
    __u8 dst_ip[16];
    __u8 local_mac[6];
    __u16 protocol;
    __u16 payload_len;
    __u16 src_port;
    __u16 dst_port;
    __u8 ip_version;
    __u8 flags;
};
// --- Bit 0: The Enforcement Action ---
#define F_PASS           1   // Bit 0: 1 = Pass, 0 = Drop

#define F_WAN_IN         2   // Bit 1: Arrived from Internet (WAN -> LAN)
#define F_WAN_OUT        4   // Bit 2: Headed to Internet (LAN -> WAN)

#define F_ANOMALY        8   // Bit 3: Protocol Anomaly (Failed DPI)
#define F_LEGACY_DROP    16  // Bit 4: Legacy Hard Drop (NBT-NS)
#define F_HEURISTIC      32  // Bit 5: Heuristic Telemetry (mDNS/SSDP)
#define F_INFRA_ALERT    64  // Bit 6: Infrastructure Hijack (Rogue DHCP)

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
static __always_inline int log_v4(__u16 protocol, __u8 *local_mac, __u32 src_ip, __u32 dst_ip, __u16 src_port, __u16 dst_port, __u16 payload_len, __u8 flags){
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev){
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version= 4;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        ev->payload_len = payload_len;
        __builtin_memcpy(ev->local_mac, local_mac, 6);
        __builtin_memcpy(ev->src_ip, &src_ip, 4);
        __builtin_memcpy(ev->dst_ip, &dst_ip, 4);
        bpf_ringbuf_submit(ev, 0);
    }
    if (flags & 1) return XDP_PASS;
    return XDP_DROP;
}
static __always_inline int log_v6(__u16 protocol, __u8 *local_mac, void *src_ip, void *dst_ip, __u16 src_port, __u16 dst_port, __u16 payload_len,  __u8 flags){ 
    struct log_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev){
        __builtin_memset(ev, 0, sizeof(*ev));
        ev->ip_version= 6;
        ev->flags = flags;
        ev->protocol = protocol;
        ev->src_port = src_port;
        ev->dst_port = dst_port;
        ev->payload_len = payload_len;
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
    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u16 ip_hdr_len = iph->ihl * 4;
    __u16 tcp_hdr_len= tcph->doff * 4;
    if (ip_tot_len < ip_hdr_len + tcp_hdr_len) return XDP_PASS;
    __u16 payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    if ((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) || (tcph->syn && tcph->fin) || (tcph->fin && tcph->psh && tcph->urg))
        return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags);
    
    switch (dst_port){
        
        case PORT_FTP_DATA:
        case PORT_FTP_CMD:
        case PORT_TELNET:
        case PORT_NETBIOS_TCP:
            return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
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
            return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        default:
            return log_v4(IPPROTO_TCP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}
static __always_inline int Handle_TCP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct tcphdr *tcph = (void *)(ipv6h +1);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    __u16 ipv6_payload_len = bpf_ntohs(ipv6h->payload_len);
    __u16 tcp_hdr_len      = tcph->doff * 4;
    if (ipv6_payload_len < tcp_hdr_len) return XDP_PASS;
    __u16 payload_len = ipv6_payload_len - tcp_hdr_len;
    __u16 src_port = bpf_ntohs(tcph->source);
    __u16 dst_port = bpf_ntohs(tcph->dest);
    if ((!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) || (tcph->syn && tcph->fin) || (tcph->fin && tcph->psh && tcph->urg))
        return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags);
    switch (dst_port){
        case PORT_FTP_DATA:
        case PORT_FTP_CMD:
        case PORT_TELNET:
        case PORT_NETBIOS_TCP:
            return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
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
            return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        default:
            return log_v6(IPPROTO_TCP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS);
    }
}



static __always_inline int Handle_UDP(struct iphdr *iph, void *data_end, __u8 *local_mac, __u8 flags){
    struct udphdr *udph = (void *)iph + (iph->ihl * 4);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u16 payload_len = bpf_ntohs(udph->len);
    if (payload_len < sizeof(struct udphdr))
        return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, 0, flags | F_ANOMALY );

    switch (dst_port) {
        case PORT_LLMNR:{
            struct dnshdr *dnsh = (void *)(udph + 1);
            if ((void *)(dnsh + 1) > data_end) return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1) return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags);
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_ANOMALY);
        }
        case PORT_NBT_NS:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
        
        case PORT_TFTP:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);

        case PORT_SNMP:
        case PORT_SNMP_TRAP:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);

        case PORT_QUIC:
        case PORT_DNS:
        case PORT_MDNS:
        case PORT_SSDP:
        case PORT_WS_DISC:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        
        case PORT_DHCP_CLIENT:{
        if (src_port == PORT_DHCP_SERVER){
            if (flags & F_WAN_IN)
                return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS);
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_INFRA_ALERT);
        }
        return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS);
        }
        default:
            return log_v4(IPPROTO_UDP, local_mac, iph->saddr, iph->daddr, src_port, dst_port, payload_len, flags | F_PASS);

    }
}
static __always_inline int Handle_UDP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct udphdr *udph = (void *)(ipv6h +1);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;
    __u16 src_port = bpf_ntohs(udph->source);
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u16 payload_len = bpf_ntohs(udph->len);
    if (payload_len < sizeof(struct udphdr))
        return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, 0, flags | F_ANOMALY );
    
    switch (dst_port) {
        case PORT_LLMNR:{
            struct dnshdr *dnsh = (void *)(udph + 1);
            if ((void *)(dnsh + 1) > data_end) return XDP_DROP;
            if (bpf_ntohs(dnsh->qdcount) == 1) return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags);
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_ANOMALY );
        }
        case PORT_NBT_NS:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);
        
        case PORT_TFTP:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_LEGACY_DROP);

        case PORT_SNMP:
        case PORT_SNMP_TRAP:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);
        
        case PORT_DNS:
        case PORT_MDNS:
        case PORT_SSDP:
        case PORT_WS_DISC:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS | F_HEURISTIC);

        case PORT_DHCP_CLIENT:{
        if (src_port == PORT_DHCP_SERVER){
            if (flags & F_WAN_IN)
                return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS);
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_INFRA_ALERT);
        }
        return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS);
        }
        default:
            return log_v6(IPPROTO_UDP, local_mac, &ipv6h->saddr, &ipv6h->daddr, src_port, dst_port, payload_len, flags | F_PASS);

    }
}



static __always_inline int Handle_ICMP(struct iphdr *iph, void *data_end, __u8 *local_mac, __u8 flags){
    struct icmphdr *icmph = (void *)iph + (iph->ihl * 4);
    if ((void *)(icmph + 1) > data_end) return XDP_PASS;
    __u16 ip_tot_len = bpf_ntohs(iph->tot_len);
    __u16 ip_hdr_len = iph->ihl * 4;
    if (ip_tot_len < (ip_hdr_len + sizeof(struct icmphdr))) return XDP_PASS;
    __u16 payload_len = ip_tot_len - ip_hdr_len - sizeof(struct icmphdr);
    if (payload_len > 1000)
        return log_v4(IPPROTO_ICMP, local_mac, iph->saddr, iph->daddr, 0, 0, payload_len, flags | F_ANOMALY);
    return log_v4(IPPROTO_ICMP, local_mac, iph->saddr, iph->daddr, 0, 0, payload_len, flags | F_PASS);
}
static __always_inline int Handle_ICMP_v6(struct ipv6hdr *ipv6h, void *data_end, __u8 *local_mac, __u8 flags){
    struct icmp6hdr *icmpv6h = (void *)(ipv6h +1);
    if ((void *)(icmpv6h + 1) > data_end) return XDP_PASS;
    __u16 ipv6_payload_len = bpf_ntohs(ipv6h->payload_len);
    if (ipv6_payload_len < sizeof(struct icmp6hdr)) return XDP_PASS;
    __u16 payload_len = ipv6_payload_len - sizeof(struct icmp6hdr);
    if (payload_len > 1000)
        return log_v6(IPPROTO_ICMPV6, local_mac, &ipv6h->saddr, &ipv6h->daddr, 0, 0, payload_len, flags | F_ANOMALY);
    return log_v6(IPPROTO_ICMPV6, local_mac, &ipv6h->saddr, &ipv6h->daddr, 0, 0, payload_len, flags | F_PASS);
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
    __u8 router_mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS; 

    if (ctx->ingress_ifindex == WAN_IFINDEX) {
        local_mac = eth->h_dest;
        flags |= F_WAN_IN;
    } else if (ctx->ingress_ifindex == LAN_IFINDEX) {
        local_mac = eth->h_source;
        if ((__builtin_memcmp(eth->h_dest,router_mac,6)) == 0)
            flags |= F_WAN_OUT;
    } else
        return XDP_PASS;
    
    struct MAC_address search_mac;
    __builtin_memcpy(search_mac.addr, eth->h_source, 6);
    __u8 *is_banned = bpf_map_lookup_elem(&MAC_list, &search_mac);
    if (is_banned && *is_banned == 1) {
        return XDP_DROP; // Instantly kill traffic from Trust Score 0 devices
    }

    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_ARP: return XDP_PASS;
        case ETH_P_IP:{
            struct iphdr *iph = (void *)(eth + 1);
            if((void *)(iph + 1) > data_end) return XDP_PASS;

            __u32 src_ip = iph->saddr;
            __u32 *is_banned_ip = bpf_map_lookup_elem(&Blocked_IPV4s, &src_ip);
            if (is_banned_ip)
                return XDP_DROP;

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

            struct ipv6_address src_ipv6;
            __builtin_memcpy(src_ipv6.addr, &ipv6h->saddr, 16);
            __u32 *is_banned_ipv6 = bpf_map_lookup_elem(&Blocked_IPV6s, &src_ipv6);
            if (is_banned_ipv6) 
                return XDP_DROP;

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
