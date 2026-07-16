#ifndef SHARED_DEFS_H
#define SHARED_DEFS_H

#include <linux/types.h>

// --- High-Risk & Target SOHO Ports ---
#define PORT_NBT_NS 137
#define PORT_SMB 445
#define PORT_WS_DISC 3702
#define PORT_MDNS 5353
#define PORT_LLMNR 5355
#define PORT_SSDP 1900
#define PORT_DHCP_SERVER 67
#define PORT_DHCP_CLIENT 68
#define PORT_DNS 53
#define PORT_TFTP 69
#define PORT_SNMP 161
#define PORT_SNMP_TRAP 162
#define PORT_QUIC 443
#define PORT_NETBIOS_TCP 139
#define PORT_FTP_DATA 20
#define PORT_FTP_CMD 21
#define PORT_SSH 22
#define PORT_TELNET 23
#define PORT_RDP 3389
#define PORT_HTTP 80
#define PORT_HTTPS 443
#define PORT_KERBEROS 88
#define PORT_LDAP 389
#define PORT_LDAPS 636
#define PORT_MSSQL 1433
#define PORT_MYSQL 3306
#define PORT_POSTGRES 5432

// --- Core Data Structures ---
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

struct flow_key {
__u8 external_ip[16];
__u8 internal_mac[6];
__u16 src_port;
__u16 dst_port;
__u8 protocol;
__u8 pad;
} attribute((packed));

// --- The Telemetry Payload ---
// Mapped for 16-byte IPv6 compatibility (IPv4 takes the first 4 bytes)
struct log_event {
__u8 ip_addr[16];
__u8 internal_mac[6];
__u16 payload_len;
__u16 src_port;
__u16 dst_port;
__u8 layer_4_protocol;
__u8 tcp_flags;
__u8 ip_version;
__u8 flags;
} attribute((packed));

// --- Triage Enforcement Bitmasks ---
#define F_PASS 1         // Bit 0: 1 = Pass, 0 = Drop
#define F_WAN_IN 2       // Bit 1: Arrived from Internet (WAN -> LAN)
#define F_WAN_OUT 4      // Bit 2: Headed to Internet (LAN -> WAN)
#define F_ANOMALY 8      // Bit 3: Protocol Anomaly (Failed DPI)
#define F_LEGACY_DROP 16 // Bit 4: Legacy Hard Drop (NBT-NS)
#define F_HEURISTIC 32   // Bit 5: Heuristic Telemetry (mDNS/SSDP)
#define F_INFRA_ALERT 64 // Bit 6: Infrastructure Hijack (Rogue DHCP)
#define F_AD_DROP 128    // Bit 7: Bloom Filter Ad/Telemetry Drop

#endif // SHARED_DEFS_H
