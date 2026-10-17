use anyhow::Context;
use aya::Ebpf;
use aya::maps::{Array, BloomFilter, HashMap as BpfHashMap, RingBuf};
use aya::programs::{Xdp, xdp::XdpMode};

use hyperloglog::HyperLogLog;
use rustc_hash::FxHashMap;
use std::ffi::CString;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
mod network;
use tokio_util::sync::CancellationToken;

#[allow(
    dead_code,
    unused_imports,
    clippy::all,
    mismatched_lifetime_syntaxes,
    elided_lifetimes_in_paths,
    unsafe_op_in_unsafe_fn
)]
#[path = "router_generated.rs"]
mod router_generated;
use router_generated::*;

#[derive(Debug)]
enum ExecutionCommand {
    SetDeviceState {
        mac: [u8; 6],
        blocked: bool,
        id: i64,
        automatic: bool,
        revision: i64,
    },
    SetPolicy(serde_json::Value),
    BlockMac([u8; 6], String),
    PromoteVip([u8; 28]),
    UpdateAdList(Vec<String>),
    UpdateBannedIps(Vec<IpAddr>),
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LogEvent {
    pub external_ip: [u8; 16],
    pub internal_mac: [u8; 6],
    pub payload_len: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub layer_4_protocol: u8,
    pub tcp_flags: u8,
    pub layer_3_protocol: u8,
    pub flags: u8,
}

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

#[derive(Debug)]
struct TcpSession {
    start_time: time::Instant,
    last_seen: time::Instant,
    bytes_transferred: u64,
    is_vip: bool,
}

struct DeviceState {
    totals: DeviceTotals,
    last_seen: time::Instant,
    active_tcp_sessions: FxHashMap<([u8; 16], u16, u16), TcpSession>,
}

#[derive(sqlx::FromRow)]
struct ReportForDb {
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
    report_key: String,
    captured_at: i64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    if let Ok(path) = std::env::var("CIPHER_ENV_FILE") {
        dotenvy::from_path(path).ok();
    } else {
        dotenvy::dotenv().ok();
    }
    println!("🛡️ Initializing Project_CIPHER Trust Score Engine...");

    let mut bpf = Ebpf::load_file("Router/ebpf/target/cipher_ebpf.o")
        .context("Failed to load the eBPF object file. Did you compile the C code?")?;

    println!("✅ eBPF ELF loaded successfully.");

    // INTERFACE MAPPING LOGIC
    let interface = std::env::var("CIPHER_INTERFACE").unwrap_or_else(|_| "enp7s0".into());
    let test_iface = interface.as_str();
    let c_iface = CString::new(test_iface).unwrap();
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    anyhow::ensure!(ifindex != 0, "Interface does not exist: {}", test_iface);
    println!(
        "📡 Mapped interface '{}' to OS Index: {}",
        test_iface, ifindex
    );

    let mut iface_map: Array<_, u32> = Array::try_from(bpf.map_mut("Interface_Map").unwrap())?;
    iface_map.set(0, ifindex, 0)?;
    iface_map.set(1, ifindex, 0)?;

    let program: &mut Xdp = bpf.program_mut("xdp_router_prog").unwrap().try_into()?;
    program
        .load()
        .context("Failed to load XDP program into the kernel")?;
    program
        .attach(test_iface, XdpMode::Skb)
        .context(format!("Failed to attach XDP to {}", test_iface))?;

    // CREATE DATABASE
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(std::env::var("CIPHER_ROUTER_DB").unwrap_or_else(|_| "router.db".into()))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    network::initialize(&db).await?;
    let network_id = std::env::var("CIPHER_NETWORK_ID").unwrap_or_else(|_| "NET_123".into());
    let cancel_token = CancellationToken::new();

    // THE GLOBAL AI MEMORY BANK
    let telemetry_state: Arc<Mutex<FxHashMap<[u8; 6], DeviceState>>> =
        Arc::new(Mutex::new(FxHashMap::default()));

    let mut heartbeat_map: Array<_, u64> =
        Array::try_from(bpf.take_map("Heartbeat").expect("Heartbeat map not found"))
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

    // THREAD 0: THE EXECUTIONER (eBPF Map Manager)
    let mut mac_list: BpfHashMap<_, [u8; 6], u8> =
        BpfHashMap::try_from(bpf.take_map("MAC_list").expect("MAC_list map not found"))
            .context("Failed to map MAC_list")?;
    let mut vip_map: BpfHashMap<_, [u8; 28], u64> = BpfHashMap::try_from(
        bpf.take_map("fast_path_vip")
            .expect("fast_path_vip map not found"),
    )
    .context("Failed to map fast_path_vip")?;
    let mut ad_filter: BloomFilter<_, u32> = BloomFilter::try_from(
        bpf.take_map("Ad_Bloom_Filter")
            .expect("Ad_Bloom_Filter map not found"),
    )
    .context("Failed to map Ad_Bloom_Filter")?;
    let mut blocked_ipv4: BpfHashMap<_, u32, u32> = BpfHashMap::try_from(
        bpf.take_map("Blocked_IPV4s")
            .expect("Blocked_IPV4s map not found"),
    )
    .context("Failed to map Blocked_IPV4s")?;
    let mut blocked_ipv6: BpfHashMap<_, [u8; 16], u32> = BpfHashMap::try_from(
        bpf.take_map("Blocked_IPV6s")
            .expect("Blocked_IPV6s map not found"),
    )
    .context("Failed to map Blocked_IPV6s")?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ExecutionCommand>(100);
    let ct_0 = cancel_token.clone();

    let saved_blocks: Vec<String> =
        sqlx::query_scalar("SELECT mac FROM local_blocks WHERE network_id=?")
            .bind(&network_id)
            .fetch_all(&db)
            .await?;
    for mac in saved_blocks.iter().filter_map(|m| network::parse_mac(m)) {
        mac_list.insert(mac, 1u8, 0)?;
    }
    let execution_db = db.clone();
    let execution_network = network_id.clone();
    let handle_0 = tokio::spawn(async move {
        let mut policy = network::load_policy(&execution_db, &execution_network).await;
        let mut last_alert: FxHashMap<[u8; 6], time::Instant> = FxHashMap::default();
        loop {
            tokio::select! {
                _ = ct_0.cancelled() => {
                    println!("🛑 Executioner Thread spinning down...");
                    break;
                }
                cmd = cmd_rx.recv() => {
                    if let Some(command) = cmd {
                        match command {
                            ExecutionCommand::SetPolicy(next) => {
                                if network::valid_policy(&next) {
                                    let result=network::save_policy(&execution_db,&execution_network,&next).await;
                                    if result.is_ok() { policy=next.clone(); }
                                    let ack=serde_json::json!({"type":"policy_ack","revision":next["revision"],"applied":result.is_ok()});
                                    let _=network::event(&execution_db,&execution_network,&ack).await;
                                }
                            }
                            ExecutionCommand::SetDeviceState { mac, blocked, id, automatic, revision } => {
                                if automatic && (!network::may_isolate(&policy,&mac) || policy["revision"].as_i64()!=Some(revision)) {
                                    let ack=serde_json::json!({"type":"command_ack","id":id,"applied":false,"detail":"Automatic isolation suppressed by current device/response policy"});
                                    let _=network::event(&execution_db,&execution_network,&ack).await;
                                    continue;
                                }
                                let result = if blocked { mac_list.insert(mac, 1u8, 0) }
                                    else { match mac_list.get(&mac, 0) {
                                        Ok(_) => mac_list.remove(&mac),
                                        Err(aya::maps::MapError::KeyNotFound) => Ok(()),
                                        Err(e) => Err(e),
                                    } };
                                let result: anyhow::Result<()>=match result {
                                    Ok(())=>network::remember_block(&execution_db,&execution_network,&mac,blocked).await.map_err(Into::into),
                                    Err(e)=>Err(e.into()),
                                };
                                let ack = serde_json::json!({"type":"command_ack","id":id,"applied":result.is_ok(),"detail":result.err().map(|e| e.to_string()).unwrap_or_default()});
                                let _ = network::event(&execution_db,&execution_network,&ack).await;
                            }

                            ExecutionCommand::BlockMac(mac, reason) => {
                                if last_alert.get(&mac).is_some_and(|at|at.elapsed().as_secs()<120) {continue;}
                                last_alert.insert(mac,time::Instant::now());
                                let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                                if !network::may_isolate(&policy,&mac) {
                                    let event=serde_json::json!({"type":"edge_alert","mac":mac_str,"reason":reason,"action":"suppressed_by_policy"});
                                    let _=network::event(&execution_db,&execution_network,&event).await;
                                    continue;
                                }
                                if let Err(e) = mac_list.insert(mac, 1u8, 0) {
                                    println!("🔴 [eBPF ERROR] Failed to drop {}: {}", mac_str, e);
                                } else {
                                    println!("💀 [EXECUTIONER] Device {} isolated at Layer 2. Reason: {}", mac_str, reason);
                                    if let Err(e)=network::remember_block(&execution_db,&execution_network,&mac,true).await {eprintln!("Persist local block: {e}");}
                                    let event = serde_json::json!({"type":"edge_action","mac":mac_str,"state":"blocked","reason":reason});
                                    let _ = network::event(&execution_db,&execution_network,&event).await;
                                }
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

    // THREAD 1: THE KERNEL HARVESTER
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
                let mut state = telemetry_clone.lock().unwrap();
                let now = time::Instant::now();
                while let Some(item) = ring_buf.next() {
                    if item.len() != mem::size_of::<LogEvent>() {
                        continue;
                    }
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
                    let device = state.entry(mac).or_insert_with(|| DeviceState {
                        totals: DeviceTotals::default(),
                        last_seen: now,
                        active_tcp_sessions: FxHashMap::default(),
                    });

                    // 1. AI Aggregation Math (Short-Term)
                    device.last_seen = now;
                    device.totals.total_connections += 1;
                    device.totals.unique_external_ips.insert(&external_ip);
                    *device.totals.port_counts.entry(dst_port).or_insert(0) += 1;

                    if flags & 1 != 0 {
                        device.totals.passed_connections += 1;
                    }
                    if flags & 2 != 0 {
                        device.totals.bytes_in += payload as u64;
                    }
                    if flags & 4 != 0 {
                        device.totals.bytes_out += payload as u64;
                    }
                    if flags & 8 != 0 {
                        device.totals.anomaly_flags_count += 1;
                        if device.totals.anomaly_flags_count == 1 {
                            let ip_string = if l3_proto == 4 {
                                // Slice the first 4 bytes and convert to Ipv4Addr
                                let v4_bytes: [u8; 4] =
                                    external_ip[0..4].try_into().unwrap_or([0; 4]);
                                IpAddr::V4(Ipv4Addr::from(v4_bytes)).to_string()
                            } else {
                                // Use all 16 bytes for IPv6
                                IpAddr::V6(Ipv6Addr::from(external_ip)).to_string()
                            };
                            println!(
                                "[ANOMALY DROP] L4 Violation | Proto: {} | Payload: {} bytes from IP: {}",
                                l4_proto, payload, ip_string
                            );
                        }
                    }
                    if flags & 1 == 0 {
                        device.totals.dropped_connections += 1;
                    }
                    if flags & 32 != 0 {
                        device.totals.heuristic_flags_count += 1;
                    }
                    if flags & 64 != 0 {
                        device.totals.infra_alert_count += 1;
                        let mac_str = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        );
                        println!(
                            "[CRITICAL] Rogue Infrastructure Hijack Attempted by {}!",
                            mac_str
                        );
                        should_ban = true;
                        ban_reason = "Infrastructure Hijack (Rogue DHCP)";
                    }
                    if flags & 128 != 0 {
                        let mac_str = format!(
                            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                        );
                        println!(
                            "🚫 [SINKHOLE] {} attempted to query a blocked domain (DNS request annihilated).",
                            mac_str
                        );
                    }
                    if device.totals.anomaly_flags_count > 500 {
                        should_ban = true;
                        ban_reason = "Volumetric Anomaly Flood (Tripwire Exceeded)";
                    }

                    if l4_proto == 6 {
                        if (tcp_flags & 0x02) != 0 {
                            device.totals.syn_count += 1;
                        }
                        if (tcp_flags & 0x04) != 0 {
                            device.totals.rst_count += 1;
                        }

                        // PILLAR 4: SYN/RST Anomaly Detection (Port Scans / Lateral Movement)
                        if device.totals.syn_count > 50 {
                            let anomaly_ratio = (device.totals.rst_count as f64)
                                / (device.totals.syn_count as f64 + 1.0);
                            if anomaly_ratio > 0.6 {
                                let mac_str = format!(
                                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                                );
                                println!(
                                    "🚨 [PILLAR 4] TCP Scan detected from {}! (RST/SYN Ratio: {:.2})",
                                    mac_str, anomaly_ratio
                                );
                                should_ban = true;
                                ban_reason =
                                    "TCP Session Health: Scanner Detected (High RST Ratio)";
                            }
                        }

                        // PILLAR 6: Session Longevity
                        let session_key = (external_ip, src_port, dst_port);
                        let session = device
                            .active_tcp_sessions
                            .entry(session_key)
                            .or_insert_with(|| TcpSession {
                                start_time: now,
                                last_seen: now,
                                bytes_transferred: 0,
                                is_vip: false,
                            });
                        session.last_seen = now;
                        session.bytes_transferred += payload as u64;

                        if session.bytes_transferred > 50_000_000
                            && device.totals.anomaly_flags_count == 0
                        {
                            if !session.is_vip {
                                let mut key_bytes = [0u8; 28];
                                key_bytes[0..16].copy_from_slice(&external_ip);
                                key_bytes[16..22].copy_from_slice(&mac);
                                key_bytes[22..24].copy_from_slice(&src_port.to_ne_bytes());
                                key_bytes[24..26].copy_from_slice(&dst_port.to_ne_bytes());
                                key_bytes[26] = l4_proto;

                                let _ = cmd_tx_harvester
                                    .try_send(ExecutionCommand::PromoteVip(key_bytes));
                                session.is_vip = true;
                            }
                        }
                    }
                    if should_ban {
                        let _ = cmd_tx_harvester
                            .try_send(ExecutionCommand::BlockMac(mac, ban_reason.to_string()));
                    }
                    processed_in_batch += 1;
                    if processed_in_batch >= 100 {
                        break;
                    }
                }

                // PILLAR 6 GARBAGE COLLECTOR (Runs every 10 seconds)
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
                            if key.1 == 22 || key.2 == 22 {
                                return true;
                            }

                            // The State Exhaustion Trigger (5 mins = 300s)
                            if uptime > 300 {
                                let throughput = session.bytes_transferred / uptime;
                                if throughput < 100 {
                                    slowloris_detected = true;
                                    return false; // Evict it
                                }
                            }
                            // Silent Memory Safety: Drop dead connections idle for > 5 mins
                            if idle_time > 300 {
                                return false;
                            }
                            true // Keep session alive
                        });
                        if slowloris_detected {
                            let mac_str = format!(
                                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                mac_key[0],
                                mac_key[1],
                                mac_key[2],
                                mac_key[3],
                                mac_key[4],
                                mac_key[5]
                            );
                            println!(
                                "🐢 [SLOWLORIS DETECTED] Device {} is exhausting state (Throughput < 100 B/s for > 5 mins)!",
                                mac_str
                            );
                            let _ = cmd_tx_harvester.try_send(ExecutionCommand::BlockMac(
                                *mac_key,
                                "State Exhaustion (Slowloris)".to_string(),
                            ));
                        }
                    }
                    for mac_key in mac_to_remove {
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
    // Collection continues during network outages; the transport drains this durable outbox.
    let collector_state = telemetry_state.clone();
    let collector_db = db.clone();
    let collector_network = network_id.clone();
    let ct_2 = cancel_token.clone();
    let handle_2 = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(10));
        loop {
            tokio::select! {
                _=ct_2.cancelled()=>break,
                _=tick.tick()=> {
                    let reports: Vec<_>={
                        let mut state=collector_state.lock().unwrap();
                        state.iter_mut().filter_map(|(mac,device)| {
                            let totals=std::mem::take(&mut device.totals);
                            (totals.total_connections>0).then_some((*mac,totals))
                        }).collect()
                    };
                    for (mac,totals) in reports {
                        if let Err(e)=network::store_report(&collector_db,&collector_network,mac,totals).await {eprintln!("Telemetry outbox: {e}");}
                    }
                }
            }
        }
    });
    let handle_3 = tokio::spawn(network::run(
        db.clone(),
        network_id,
        interface,
        cmd_tx.clone(),
        cancel_token.clone(),
    ));
    tokio::select! {
        _ = cancel_token.cancelled() => {},
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
    assert!(
        bytes.len() >= mem::size_of::<LogEvent>(),
        "Truncated kernel event"
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_event_layout_matches_c_producer() {
        assert_eq!(mem::size_of::<LogEvent>(), 32);
        let bytes: [u8; 32] = [
            1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x34, 0x12, 0x50, 0, 0xbb, 1, 6, 2, 4, 5,
        ];
        let event = ptr_to_struct(&bytes);
        assert_eq!(event.internal_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let (len, src, dst) = (event.payload_len, event.src_port, event.dst_port);
        assert_eq!((len, src, dst), (0x1234, 80, 443));
        assert_eq!(event.flags, 5);
    }
}
