use anyhow::Context;
use aya::Ebpf;
use aya::programs::{xdp::XdpMode, Xdp};
use aya::maps::{RingBuf, Array, HashMap as BpfHashMap, BloomFilter};
use tokio::signal;
use std::mem;
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};
use std::time;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustc_hash::{FxHashMap}; 
use hyperloglog::HyperLogLog;

use futures_util::{StreamExt, SinkExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;


// Assuming you ran `make flatbuffers` and the generated file is in src/
#[allow(dead_code, unused_imports, clippy::all, mismatched_lifetime_syntaxes, elided_lifetimes_in_paths, unsafe_op_in_unsafe_fn)]
#[path = "router_generated.rs"]
mod router_generated;
use router_generated::*;

// --- THE ACTOR PATTERN COMMAND ENUM ---
#[derive(Debug)]
enum ExecutionCommand {
    BlockMac([u8; 6], String),
    AllowMac([u8; 6]),
    PromoteVip([u8; 28]),
    UpdateAdList(Vec<String>),
    UpdateBannedIps(Vec<IpAddr>)
}

// 1. The API Boundary: The Optimized 32-Byte Struct
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LogEvent {
    pub external_ip: [u8; 16],
    pub payload_len: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub internal_mac: [u8; 6],
    pub layer_4_protocol: u8,
    pub tcp_flags: u8,
    pub layer_3_protocol: u8,
    pub flags: u8,
} 

// 2A. The Short-Term AI Aggregator (Wiped every 10s for the Cloud)
struct DeviceTotals {
    bytes_in: u64,
    bytes_out: u64,
    unique_external_ips: HyperLogLog,
    port_counts: FxHashMap<u16, u32>,
    syn_count: u32,
    rst_count: u32,
    total_connections: u32,
    passed_connections: u32,
    dropped_connections: u32,
    anomaly_flags_count: u32,
    heuristic_flags_count: u32,
    infra_alert_count: u32,
}

impl Default for DeviceTotals {
    fn default() -> Self {
        Self {
            bytes_in: 0,
            bytes_out: 0,
            unique_external_ips: HyperLogLog::new(0.05), 
            port_counts: FxHashMap::default(),
            syn_count: 0,
            rst_count: 0,
            total_connections: 0,
            passed_connections: 0,
            dropped_connections: 0,
            anomaly_flags_count: 0,
            heuristic_flags_count: 0,
            infra_alert_count: 0,
        }
    }
}

// 2B. The Long-Term Connection Tracker (Pillar 6: State Exhaustion)
#[derive(Debug)]
struct TcpSession {
    start_time: time::Instant,
    last_seen: time::Instant,
    bytes_transferred: u64,
    is_vip: bool
}

// 2C. The Master State Wrapper
struct DeviceState {
    totals: DeviceTotals,
    last_seen: time::Instant,
    active_tcp_sessions: FxHashMap<([u8; 16], u16, u16), TcpSession>,
}

#[derive(sqlx::FromRow)]
struct ReportForDb {
    id: i64,
    network_id: String,
    mac: String,
    bytes_in: i64,
    bytes_out: i64,
    unique_external_ips: i64,
    total_connections: i64,
    passed_connections: i64,
    dropped_connections: i64,
    anomaly_flags_count: i64,
    heuristic_flags_count: i64,
    infra_alert_count: i64,
    port_entropy: f64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("🛡️ Initializing Project_CIPHER Trust Score Engine...");

    let mut bpf = Ebpf::load_file("../ebpf/target/cipher_ebpf.o")
        .context("Failed to load the eBPF object file. Did you compile the C code?")?;

    println!("✅ eBPF ELF loaded successfully.");

    // --- INTERFACE MAPPING LOGIC ---
    let test_iface = "enp0s8"; 
    let c_iface = CString::new(test_iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    println!("📡 Mapped interface '{}' to OS Index: {}", test_iface, ifindex);

    let mut iface_map: Array<_, u32> = Array::try_from(bpf.map_mut("Interface_Map").unwrap())?;
    iface_map.set(0, ifindex, 0)?; 
    iface_map.set(1, ifindex, 0)?;

    let program: &mut Xdp = bpf.program_mut("xdp_router_prog").unwrap().try_into()?;
    program.load().context("Failed to load XDP program into the kernel")?;
    program.attach(test_iface, XdpMode::Skb)
        .context(format!("Failed to attach XDP to {}", test_iface))?;
    
    // --- CREATE DATABASE --- 
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("router.db")
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    // --- CONNECT TO AXUM CLOUD ---
    let network_id = "NET_123";
    let cloud_url = format!("wss://localhost:3000/api/router/ws/{}", network_id);
    println!("🔌 Connecting to Axum Cloud at {}...", cloud_url);
    
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    
    let mut request = cloud_url.into_client_request().expect("Invalid Cloud URL");
    let router_secret = std::env::var("ROUTER_SECRET").unwrap_or_else(|_| "router_secret_key".to_string());
    let auth_header_value = format!("ApiKey {}", router_secret);
    
    // Inject the authentication header so Axum's `RouterKey` extractor accepts us!
    request.headers_mut().insert("Authorization", auth_header_value.parse().expect("Invalid Authorization Header Format"));

    // --- NEW: BYPASS SELF-SIGNED CERTIFICATE VALIDATION ---
    use native_tls::TlsConnector;
    use tokio_tungstenite::Connector;

    let native_tls_connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)     // Ignore the self-signed nature
        .danger_accept_invalid_hostnames(true) // Ignore localhost mismatch
        .build()
        .context("Failed to build custom TLS connector")?;

    let connector = Connector::NativeTls(native_tls_connector.into());

    // Connect using the custom, relaxed TLS configuration
    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
       .await.expect("Failed to connect to Axum Cloud! Is the server running?");
    
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    println!("🟢 WebSocket established! Secure tunnel active.");

    let cancel_token = CancellationToken::new();

    // --- THE GLOBAL AI MEMORY BANK ---
    let telemetry_state: Arc<Mutex<FxHashMap<[u8; 6], DeviceState>>> = Arc::new(Mutex::new(FxHashMap::default()));

    let mut heartbeat_map: Array<_, u64> = Array::try_from(bpf.take_map("Heartbeat").expect("Heartbeat map not found"))
        .context("Failed to map Heartbeat array")?;
    
    let ct_hb = cancel_token.clone();
    let handle_hb = tokio::spawn(async move {
        println!("🫀 Watchdog Thread Started...");
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = ct_hb.cancelled() => {
                    println!("🛑 Watchdog Thread spinning down...");
                    break;
                }
                _ = ticker.tick() => {
                    // Writing 0 tells the eBPF kernel code to reset its internal timer!
                    if let Err(e) = heartbeat_map.set(0, 0, 0) {
                        println!("⚠️ [WATCHDOG] Failed to ping kernel: {}", e);
                    }
                }
            }
        }
    });

    // --- THREAD 0: THE EXECUTIONER (eBPF Map Manager) ---
    let mut mac_list: BpfHashMap<_, [u8; 6], u8> = BpfHashMap::try_from(bpf.take_map("MAC_list").expect("MAC_list map not found"))
        .context("Failed to map MAC_list")?;
    let mut vip_map: BpfHashMap<_, [u8; 28], u64> = BpfHashMap::try_from(bpf.take_map("fast_path_vip").expect("fast_path_vip map not found"))
        .context("Failed to map fast_path_vip")?;
    let mut ad_filter: BloomFilter<_, u32> = BloomFilter::try_from(bpf.take_map("Ad_Bloom_Filter").expect("Ad_Bloom_Filter map not found"))
        .context("Failed to map Ad_Bloom_Filter")?;
    let mut blocked_ipv4: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(bpf.take_map("Blocked_IPV4s").expect("Blocked_IPV4s map not found"))
        .context("Failed to map Blocked_IPV4s")?;
    let mut blocked_ipv6: BpfHashMap<_, [u8; 16], u32> = BpfHashMap::try_from(bpf.take_map("Blocked_IPV6s").expect("Blocked_IPV6s map not found"))
        .context("Failed to map Blocked_IPV6s")?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ExecutionCommand>(100);
    let ct_0 = cancel_token.clone();

    let handle_0 = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ct_0.cancelled() => {
                    println!("🛑 Executioner Thread spinning down...");
                    break;
                }
                cmd = cmd_rx.recv() => {
                    if let Some(command) = cmd {
                        match command {
                            ExecutionCommand::BlockMac(mac, reason) => {
                                let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                                if let Err(e) = mac_list.insert(mac, 1u8, 0) {
                                    println!("🔴 [eBPF ERROR] Failed to drop {}: {}", mac_str, e);
                                } else {
                                    println!("💀 [EXECUTIONER] Device {} isolated at Layer 2. Reason: {}", mac_str, reason);
                                }
                            }
                            ExecutionCommand::AllowMac(mac) => {
                                let _ = mac_list.remove(&mac);
                                println!("✅ [EXECUTIONER] Device restored to network.");
                            }
                            ExecutionCommand::PromoteVip(key) => {
                                // Initialize the packet counter to 0 in the kernel map
                                if let Err(e) = vip_map.insert(key, 0u64, 0) {
                                    println!("🔴 [eBPF ERROR] Failed to promote VIP flow: {}", e);
                                } else {
                                    println!("🐘 [ELEPHANT FLOW] 50MB+ Transfer Detected. Flow promoted to VIP Fast Path! CPU cycles bypassed.");
                                }
                            }
                            ExecutionCommand::UpdateAdList(domains) => {
                                let mut count = 0;
                                for domain in domains {
                                    let mut hash: u32 = 2166136261;
                                    // Parse flat "ad.com" into DNS wire format "\x02ad\x03com" and hash it
                                    for part in domain.split('.') {
                                        hash ^= part.len() as u32;
                                        hash = hash.wrapping_mul(16777619);
                                        for byte in part.bytes() {
                                            let mut val = byte;
                                            if val >= b'A' && val <= b'Z' { val |= 0x20; }
                                            hash ^= val as u32;
                                            hash = hash.wrapping_mul(16777619);
                                        }
                                    }
                                    // Insert the domain hash into the eBPF Bloom Filter
                                    let _ = ad_filter.insert(hash, 0);
                                    count += 1;
                                }
                                println!("🛑 [BLOOM FILTER] Successfully loaded {} Ad/Tracker Domains into kernel memory.", count);
                            }
                            ExecutionCommand::UpdateBannedIps(ips) => {
                                let mut v4_count = 0;
                                let mut v6_count = 0;
                                for ip in ips {
                                    match ip {
                                        IpAddr::V4(ipv4) => {
                                            // from_ne_bytes elegantly maps the Rust IP exactly how the C kernel reads it in memory!
                                            let ip_u32 = u32::from_ne_bytes(ipv4.octets());
                                            let _ = blocked_ipv4.insert(ip_u32, 1u32, 0);
                                            v4_count += 1;
                                        }
                                        IpAddr::V6(ipv6) => {
                                            let _ = blocked_ipv6.insert(ipv6.octets(), 1u32, 0);
                                            v6_count += 1;
                                        }
                                    }
                                }
                                println!("🌍 [THREAT INTEL] Loaded {} IPv4s and {} IPv6s into Global Ban Maps.", v4_count, v6_count);
                            }
                        }
                    }
                }
            }
        }
    });

    // --- THREAD 1: THE KERNEL HARVESTER ---
    let telemetry_clone = Arc::clone(&telemetry_state);
    let cmd_tx_harvester = cmd_tx.clone();
    let ct_1 = cancel_token.clone();
    
    let mut ring_buf = RingBuf::try_from(bpf.take_map("events").expect("Map not found"))
        .context("Failed to map the events RingBuffer")?;

    let handle_1 = tokio::spawn(async move {
        println!("🚀 Kernel Harvester Thread Started...");
        let mut last_gc = time::Instant::now();
        loop {
            if ct_1.is_cancelled() {
                println!("🛑 Harvester Thread spinning down...");
                break;
            }
            let mut processed_in_batch = 0;
            {
                let mut state= telemetry_clone.lock().unwrap();
                let now = time::Instant::now();
                while let Some(item) = ring_buf.next() {
                    let event = ptr_to_struct(&item);

                    let external_ip = event.external_ip;                    
                    let mac = event.internal_mac;
                    let l4_proto = event.layer_4_protocol;
                    let tcp_flags = event.tcp_flags;
                    let payload = event.payload_len;
                    let src_port = event.src_port;
                    let dst_port = event.dst_port;
                    let l3_proto = event.layer_3_protocol;
                    let flags = event.flags;

                    let mut should_ban = false;
                    let mut ban_reason = "";

                    // Get or create the master state for this device
                    let device = state.entry(mac).or_insert_with(|| DeviceState{
                        totals: DeviceTotals::default(),
                        last_seen: now,
                        active_tcp_sessions: FxHashMap::default()
                    });

                    // 1. AI Aggregation Math (Short-Term)
                    device.last_seen = now;
                    device.totals.total_connections += 1;
                    device.totals.unique_external_ips.insert(&external_ip);
                    *device.totals.port_counts.entry(dst_port).or_insert(0) += 1;

                    if flags & 1 != 0 { device.totals.passed_connections += 1; }
                    if flags & 2 != 0 { device.totals.bytes_in += payload as u64; }
                    if flags & 4 != 0 { device.totals.bytes_out += payload as u64; }
                    if flags & 8 != 0 {
                        device.totals.anomaly_flags_count += 1; 
                        if device.totals.anomaly_flags_count == 1{
                            let ip_string = if l3_proto == 4 {
                                // Slice the first 4 bytes and convert to Ipv4Addr
                                let v4_bytes: [u8; 4] = external_ip[0..4].try_into().unwrap_or([0; 4]);
                                IpAddr::V4(Ipv4Addr::from(v4_bytes)).to_string()
                            } else {
                                // Use all 16 bytes for IPv6
                                IpAddr::V6(Ipv6Addr::from(external_ip)).to_string()
                            };
                            println!("[ANOMALY DROP] L4 Violation | Proto: {} | Payload: {} bytes from IP: {}", l4_proto, payload, ip_string);
                        }
                    }
                    if flags & 16 != 0 { device.totals.dropped_connections += 1; }
                    if flags & 32 != 0 { device.totals.heuristic_flags_count += 1; }
                    if flags & 64 != 0 {
                        device.totals.infra_alert_count += 1;
                        let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        println!("[CRITICAL] Rogue Infrastructure Hijack Attempted by {}!", mac_str);
                        should_ban = true;
                        ban_reason = "Infrastructure Hijack (Rogue DHCP)";
                    }
                    if flags & 128 != 0 {
                        let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                        println!("🚫 [SINKHOLE] {} attempted to query a blocked domain (DNS request annihilated).", mac_str);
                    }
                    if device.totals.anomaly_flags_count > 500 {
                        should_ban = true;
                        ban_reason = "Volumetric Anomaly Flood (Tripwire Exceeded)";
                    }

                    if l4_proto == 6 {
                        if (tcp_flags & 0x02) != 0 {
                            device.totals.syn_count += 1;
                        }
                        if (tcp_flags & 0x04) != 0{
                            device.totals.rst_count += 1;
                        }

                        // PILLAR 4: SYN/RST Anomaly Detection (Port Scans / Lateral Movement)
                        if device.totals.syn_count > 50 {
                            let anomaly_ratio = (device.totals.rst_count as f64) / (device.totals.syn_count as f64 + 1.0);
                            if anomaly_ratio > 0.6 {
                                let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                                println!("🚨 [PILLAR 4] TCP Scan detected from {}! (RST/SYN Ratio: {:.2})", mac_str, anomaly_ratio);
                                should_ban = true;
                                ban_reason = "TCP Session Health: Scanner Detected (High RST Ratio)";
                            }
                        }

                        // PILLAR 6: Session Longevity
                        let session_key = (external_ip, src_port, dst_port);
                        let session = device.active_tcp_sessions.entry(session_key)
                            .or_insert_with(|| TcpSession {start_time: now, last_seen: now, bytes_transferred: 0, is_vip: false});
                        session.last_seen = now;
                        session.bytes_transferred += payload as u64;

                        if session.bytes_transferred > 50_000_000 && device.totals.anomaly_flags_count == 0 {
                            if !session.is_vip {
                                let mut key_bytes = [0u8; 28];
                                key_bytes[0..16].copy_from_slice(&external_ip);
                                key_bytes[16..22].copy_from_slice(&mac);
                                key_bytes[22..24].copy_from_slice(&src_port.to_ne_bytes());
                                key_bytes[24..26].copy_from_slice(&dst_port.to_ne_bytes());
                                key_bytes[26] = l4_proto;
                                
                                let _ = cmd_tx_harvester.try_send(ExecutionCommand::PromoteVip(key_bytes));
                                session.is_vip = true;
                            }
                        }
                    }
                    if should_ban {
                        let _ = cmd_tx_harvester.try_send(ExecutionCommand::BlockMac(mac, ban_reason.to_string()));
                    }
                    processed_in_batch += 1;
                    if processed_in_batch >= 100 { break; } 
                }

                // --- PILLAR 6 GARBAGE COLLECTOR (Runs every 10 seconds) ---
                if last_gc.elapsed().as_secs() >= 10 {
                    
                    let mut mac_to_remove = Vec::new();
                    for (mac_key, device) in state.iter_mut() {
                        if now.duration_since(device.last_seen) > time::Duration::from_secs(86400) {
                            mac_to_remove.push(mac_key.clone());
                            continue;
                        }
                        let mut slowloris_detected = false;

                        device.active_tcp_sessions.retain(|key, session| {
                            let uptime = now.duration_since(session.start_time).as_secs();
                            let idle_time = now.duration_since(session.last_seen).as_secs();

                            // Edge Case Mitigation: Skip Persistent SSH sessions (Port 22)
                            if key.1 == 22 || key.2 == 22 { return true; }

                            // The State Exhaustion Trigger (5 mins = 300s)
                            if uptime > 300 {
                                let throughput = session.bytes_transferred / uptime;
                                if throughput < 100 {
                                    slowloris_detected = true;
                                    return false; // Evict it
                                }
                            }
                            // Silent Memory Safety: Drop dead connections idle for > 5 mins
                            if idle_time > 300 { return false; }
                            true // Keep session alive
                        });
                        if slowloris_detected {
                            let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac_key[0], mac_key[1], mac_key[2], mac_key[3], mac_key[4], mac_key[5]);
                            println!("🐢 [SLOWLORIS DETECTED] Device {} is exhausting state (Throughput < 100 B/s for > 5 mins)!", mac_str);
                            let _ = cmd_tx_harvester.try_send(ExecutionCommand::BlockMac(*mac_key, "State Exhaustion (Slowloris)".to_string()));
                        }
                    }
                    for mac_key in mac_to_remove{
                        state.remove(&mac_key);
                    }
                    last_gc = now;
                }
            } // <--- Lock is automatically dropped here

            // Yield control back to Tokio
            if processed_in_batch == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await; 
            } else {
                tokio::task::yield_now().await; 
            }
        }
    });
    // --- THREAD 2: THE CLOUD REPORTER (WebSocket Sender) ---
    let telemetry_reporter_clone = Arc::clone(&telemetry_state);
    let db_vault = db.clone();
    let ct_2 = cancel_token.clone();
    let handle_2 = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        loop {
            tokio::select! {
                _ = ct_2.cancelled() => {
                    println!("🛑 Cloud Reporter Thread spinning down...");
                    break;
                }
                _ = ticker.tick() => {
                    let mut reports_to_send;
                    {
                        let mut state = telemetry_reporter_clone.lock().unwrap();
                        reports_to_send = Vec::with_capacity(state.len());
                        for (mac, device) in state.iter_mut() {
                            let totals = std::mem::take(&mut device.totals);
                            if totals.total_connections > 0 {
                                reports_to_send.push((*mac, totals));
                            }
                        }
                    }
                    if !reports_to_send.is_empty() {
                        for (mac, totals) in reports_to_send {
                            builder.reset();
                            let mac_string = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                            let mac_fb = builder.create_string(&mac_string);
                            let net_id_fb = builder.create_string(network_id);
                            let ip_count = totals.unique_external_ips.len().round() as u32;

                            let mut port_entropy: f32 = 0.0;
                            let total_ports_hit: u32 = totals.port_counts.values().sum();
                            if total_ports_hit > 0 {
                                let total_f = total_ports_hit as f32;
                                for &count in totals.port_counts.values() {
                                    let probability = (count as f32) / total_f;
                                    // Formula: H(X) = - SUM ( P(x) * log2(P(x)) )
                                    port_entropy -= probability * probability.log2();
                                }
                            }

                            // Build the AI Telemetry Payload defined in your router.fbs
                            let mut tel_builder = TelemetryReportBuilder::new(&mut builder);
                            tel_builder.add_network_id(net_id_fb);
                            tel_builder.add_mac(mac_fb);
                            tel_builder.add_bytes_in(totals.bytes_in);
                            tel_builder.add_bytes_out(totals.bytes_out);
                            tel_builder.add_unique_external_ips(ip_count);
                            tel_builder.add_total_connections(totals.total_connections);
                            tel_builder.add_passed_connections(totals.passed_connections);
                            tel_builder.add_dropped_connections(totals.dropped_connections);
                            tel_builder.add_anomaly_flags_count(totals.anomaly_flags_count);
                            tel_builder.add_heuristic_flags_count(totals.heuristic_flags_count);
                            tel_builder.add_infra_alert_count(totals.infra_alert_count);
                            tel_builder.add_port_entropy_score(port_entropy); 

                            let tel_offset = tel_builder.finish();
                            let mut msg_builder = RouterMessageBuilder::new(&mut builder);
                            msg_builder.add_payload_type(IncomingPayload::TelemetryReport);
                            msg_builder.add_payload(tel_offset.as_union_value());
                            let final_msg = msg_builder.finish();
                            builder.finish(final_msg, None);

                            if let Err(_) = ws_sender.send(Message::Binary(builder.finished_data().to_vec().into())).await {
                                println!("🔴 [WS ERROR] Failed to beam telemetry to cloud. Vaulting to SQLite...");
                                let _ = sqlx::query("INSERT OR REPLACE INTO reports (network_id, mac, bytes_in, bytes_out, unique_external_ips, total_connections, passed_connections, dropped_connections, anomaly_flags_count, heuristic_flags_count, infra_alert_count, port_entropy)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                                    .bind(network_id)
                                    .bind(mac_string)
                                    .bind(totals.bytes_in as i64)
                                    .bind(totals.bytes_out as i64)
                                    .bind(ip_count as i64)
                                    .bind(totals.total_connections as i64)
                                    .bind(totals.passed_connections as i64)
                                    .bind(totals.dropped_connections as i64)
                                    .bind(totals.anomaly_flags_count as i64)
                                    .bind(totals.heuristic_flags_count as i64)
                                    .bind(totals.infra_alert_count as i64)
                                    .bind(port_entropy as f64)
                                    .execute(&db_vault).await;
                            } 
                            else {
                                if let Ok(backlog) = sqlx::query_as::<_, ReportForDb>("SELECT * FROM reports").fetch_all(&db_vault).await {
                                    if !backlog.is_empty() {
                                        println!("🔄 [VAULT] Uploading {} backlogged reports...", backlog.len());
                                        let mut flag = true;
                                        for report in backlog {
                                            builder.reset();
                                            let b_mac_fb = builder.create_string(&report.mac);
                                            let b_net_id_fb = builder.create_string(&report.network_id);

                                            let mut b_tel = TelemetryReportBuilder::new(&mut builder);
                                            b_tel.add_network_id(b_net_id_fb);
                                            b_tel.add_mac(b_mac_fb);
                                            b_tel.add_bytes_in(report.bytes_in as u64);
                                            b_tel.add_bytes_out(report.bytes_out as u64);
                                            b_tel.add_unique_external_ips(report.unique_external_ips as u32);
                                            b_tel.add_total_connections(report.total_connections as u32);
                                            b_tel.add_passed_connections(report.passed_connections as u32);
                                            b_tel.add_dropped_connections(report.dropped_connections as u32);
                                            b_tel.add_anomaly_flags_count(report.anomaly_flags_count as u32);
                                            b_tel.add_heuristic_flags_count(report.heuristic_flags_count as u32);
                                            b_tel.add_infra_alert_count(report.infra_alert_count as u32);
                                            b_tel.add_port_entropy_score(report.port_entropy as f32); 

                                            let b_tel_offset = b_tel.finish();
                                            let mut b_msg = RouterMessageBuilder::new(&mut builder);
                                            b_msg.add_payload_type(IncomingPayload::TelemetryReport);
                                            b_msg.add_payload(b_tel_offset.as_union_value());
                                            let b_final = b_msg.finish();
                                            builder.finish(b_final, None);

                                            if ws_sender.send(Message::Binary(builder.finished_data().to_vec().into())).await.is_err() {
                                                let _ = sqlx::query("DELETE FROM reports WHERE id < ?").bind(&report.id).execute(&db_vault).await;
                                                flag = false;
                                                break;
                                            }
                                        }
                                        if flag {
                                            let _ = sqlx::query("DELETE FROM reports").execute(&db_vault).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // --- THREAD 3: THE CLOUD LISTENER (WebSocket Receiver) ---
    let cmd_tx_cloud = cmd_tx.clone();
    let ct_3 = cancel_token.clone();
    let handle_3 = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ct_3.cancelled() => {
                    println!("🛑 Cloud Listener Thread spinning down...");
                    break;
                }
                msg_opt = ws_receiver.next() => {
                    let Some(msg) = msg_opt else { break; }; // Break if socket closes
                    if let Ok(Message::Binary(bytes)) = msg {
                        if let Ok(response) = flatbuffers::root::<RouterResponse>(&bytes) {
                            if let Some(status) = response.status() {
                                // --- NEW: THREAT INTEL EXTRACTION ---
                                if status == "threat_intel" {
                                    if let Some(intel) = response.threat_intel() {
                                        // 1. Unpack Ad Domains
                                        if let Some(ad_domains_fb) = intel.ad_domains() {
                                            let mut domains = Vec::new();
                                            for i in 0..ad_domains_fb.len() {
                                                domains.push(ad_domains_fb.get(i).to_string());
                                            }
                                            let _ = cmd_tx_cloud.send(ExecutionCommand::UpdateAdList(domains)).await;
                                        }
                                        // 2. Unpack Banned IPs
                                        if let Some(banned_ips_fb) = intel.banned_ips() {
                                            let mut ips = Vec::new();
                                            for i in 0..banned_ips_fb.len() {
                                                if let Ok(ip) = banned_ips_fb.get(i).parse::<IpAddr>() {
                                                    ips.push(ip);
                                                }
                                            }
                                            let _ = cmd_tx_cloud.send(ExecutionCommand::UpdateBannedIps(ips)).await;
                                        }
                                    }
                                } 
                                // --- EXISTING: INDIVIDUAL MAC COMMANDS ---
                                else if let Some(mac_str) = response.mac() {
                                    println!("☁️ [CLOUD COMMAND] Received {} for MAC: {}", status, mac_str);

                                    let mut mac_bytes = [0u8; 6];
                                    let parts: Vec<&str> = mac_str.split(':').collect();
                                    if parts.len() == 6 {
                                        for i in 0..6 {
                                            mac_bytes[i] = u8::from_str_radix(parts[i], 16).unwrap_or(0);
                                        }

                                        if status == "command_blocked" || status == "command_suspicious" {
                                            let _ = cmd_tx_cloud.send(ExecutionCommand::BlockMac(mac_bytes, "Cloud ML Verdict: Threat Detected".to_string())).await;
                                        } else if status == "command_allowed" {
                                            let _ = cmd_tx_cloud.send(ExecutionCommand::AllowMac(mac_bytes)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("\n🛑 Graceful Shutdown Initiated! Alerting threads...");
            cancel_token.cancel();
        }
    }
    let _ = tokio::join!(handle_hb, handle_0, handle_1, handle_2, handle_3);
    println!("✅ All threads safely terminated. eBPF links detached. Goodbye.");
    Ok(())
}

fn ptr_to_struct(bytes: &[u8]) -> LogEvent {
    unsafe {
        let mut event: LogEvent = mem::zeroed();
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut event as *mut _ as *mut u8,
            mem::size_of::<LogEvent>(),
        );
        event
    }
}