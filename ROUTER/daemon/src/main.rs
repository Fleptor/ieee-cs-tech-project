use anyhow::Context;
use aya::Ebpf;
use aya::programs::{xdp::XdpMode, Xdp};
use aya::maps::{RingBuf, Array, HashMap as BpfHashMap};
use tokio::signal;
use std::mem;
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};
use std::time::Instant; 

// --- HIGH PERFORMANCE HASHING ---
use rustc_hash::{FxHashMap, FxHashSet}; 

// --- NEW NETWORKING IMPORTS ---
use futures_util::{StreamExt, SinkExt};
// THE FIX: Removed connect_async from the import list
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::sync::mpsc; // For the Actor Pattern

// Assuming you ran `make flatbuffers` and the generated file is in src/
#[allow(dead_code, unused_imports, clippy::all, mismatched_lifetime_syntaxes, elided_lifetimes_in_paths, unsafe_op_in_unsafe_fn)]
#[path = "schema_generated.rs"]
mod schema_generated;
use schema_generated::*;

// --- THE ACTOR PATTERN COMMAND ENUM ---
#[derive(Debug)]
enum ExecutionCommand {
    BlockMac([u8; 6], String),
    AllowMac([u8; 6]),
}

// 1. The API Boundary: The Optimized 32-Byte Struct
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LogEvent {
    pub external_ip: [u8; 16],   
    pub internal_mac: [u8; 6],   
    pub layer_4_protocol: u16,   
    pub src_port: u16,           
    pub dst_port: u16,           
    pub payload_len: u16,        
    pub layer_3_protocol: u8,    
    pub flags: u8,               
} 

// 2A. The Short-Term AI Aggregator (Wiped every 10s for the Cloud)
#[derive(Default, Debug)]
struct DeviceTotals {
    bytes_in: u64,
    bytes_out: u64,
    unique_external_ips: FxHashSet<[u8; 16]>, 
    total_connections: u32,
    passed_connections: u32,
    dropped_connections: u32,
    anomaly_flags_count: u32,
    heuristic_flags_count: u32,
    infra_alert_count: u32,
}

// 2B. The Long-Term Connection Tracker (Pillar 6: State Exhaustion)
#[derive(Debug)]
struct TcpSession {
    start_time: Instant,
    last_seen: Instant,
    bytes_transferred: u64,
}

// 2C. The Master State Wrapper
#[derive(Default, Debug)]
struct DeviceState {
    totals: DeviceTotals,
    // Maps a TCP 4-Tuple (External IP, Src Port, Dst Port) to a Session
    active_tcp_sessions: FxHashMap<([u8; 16], u16, u16), TcpSession>,
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
    
    // --- CONNECT TO AXUM CLOUD ---
    let network_id = "NET_123";
    // 1. THE FIX: Change 'ws' to 'wss' for HTTPS support
    let cloud_url = format!("wss://localhost:3000/api/router/ws/{}", network_id);
    println!("🔌 Connecting to Axum Cloud at {}...", cloud_url);
    
    // 2. THE FIX: Build a formal HTTP request to inject your security headers
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    
    let mut request = cloud_url.into_client_request().expect("Invalid Cloud URL");
    
    // THE FIX: Dynamically pull the API key from the environment instead of hardcoding it!
    let router_secret = std::env::var("ROUTER_SECRET").unwrap_or_else(|_| "your_router_secret_key_here".to_string());
    // THE FIX: Change "Bearer {}" to "ApiKey {}" to match your Axum server's auth.rs
    let auth_header_value = format!("ApiKey {}", router_secret);
    
    // Inject the authentication header so Axum's `RouterKey` extractor accepts us!
    request.headers_mut().insert(
        "Authorization",
        auth_header_value.parse().expect("Invalid Authorization Header Format"),
    );

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
    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        request,
        None,
        false,
        Some(connector)
    ).await.expect("Failed to connect to Axum Cloud! Is the server running?");
    
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    println!("🟢 WebSocket established! Secure tunnel active.");

    // --- THE GLOBAL AI MEMORY BANK ---
    let telemetry_state: Arc<Mutex<FxHashMap<[u8; 6], DeviceState>>> = Arc::new(Mutex::new(FxHashMap::default()));

    // --- THREAD 0: THE EXECUTIONER (eBPF Map Manager) ---
    let mut mac_list: BpfHashMap<_, [u8; 6], u8> = BpfHashMap::try_from(bpf.take_map("MAC_list").expect("MAC_list map not found"))
        .context("Failed to map MAC_list")?;
    
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ExecutionCommand>(100);
    
    tokio::spawn(async move {
        while let Some(command) = cmd_rx.recv().await {
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
            }
        }
    });

    // --- THREAD 1: THE KERNEL HARVESTER ---
    let telemetry_clone = Arc::clone(&telemetry_state);
    let cmd_tx_harvester = cmd_tx.clone(); 
    
    let mut ring_buf = RingBuf::try_from(bpf.take_map("events").expect("Map not found"))
        .context("Failed to map the events RingBuffer")?;

    tokio::spawn(async move {
        println!("🚀 Kernel Harvester Thread Started...");
        let mut last_gc = Instant::now(); // GC Timer

        loop {
            let mut processed_in_batch = 0;
            
            // 🔒 SCOPED SYNC BLOCK
            {
                let mut state = telemetry_clone.lock().unwrap();

                while let Some(item) = ring_buf.next() {
                    let event = ptr_to_struct(&item);
                    
                    let flags = event.flags;
                    let l4_proto = { event.layer_4_protocol }; 
                    let src_port = { event.src_port };
                    let dst_port = { event.dst_port };
                    let payload = { event.payload_len };
                    let mac = event.internal_mac;
                    let ext_ip = event.external_ip;
                    
                    let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let mut should_ban = false;
                    let mut ban_reason = "";
                    
                    if flags & 64 != 0 {
                        println!("[CRITICAL] Rogue Infrastructure Hijack Attempted by {}!", mac_str);
                        should_ban = true;
                        ban_reason = "Infrastructure Hijack (Rogue DHCP)";
                    } else if flags & 8 != 0 {
                        println!("[ANOMALY DROP] L4 Violation | Proto: {} | Payload: {} bytes", l4_proto, payload);
                    }

                    // Get or create the master state for this device
                    let device = state.entry(mac).or_insert_with(DeviceState::default);
                    
                    // 1. AI Aggregation Math (Short-Term)
                    device.totals.total_connections += 1;
                    device.totals.unique_external_ips.insert(ext_ip);

                    if flags & 4 != 0 { device.totals.bytes_out += payload as u64; }
                    if flags & 2 != 0 { device.totals.bytes_in += payload as u64; }
                    if flags & 1 != 0 { device.totals.passed_connections += 1; }
                    if flags & 16 != 0 { device.totals.dropped_connections += 1; }
                    if flags & 8 != 0 { device.totals.anomaly_flags_count += 1; }
                    if flags & 32 != 0 { device.totals.heuristic_flags_count += 1; }

                    if device.totals.anomaly_flags_count > 500 {
                        should_ban = true;
                        ban_reason = "Volumetric Anomaly Flood (Tripwire Exceeded)";
                    }

                    // 2. PILLAR 6: TCP Session Tracking (Long-Term)
                    if l4_proto == 6 {
                        let session_key = (ext_ip, src_port, dst_port);
                        let now = Instant::now();
                        let session = device.active_tcp_sessions.entry(session_key).or_insert_with(|| TcpSession {
                            start_time: now,
                            last_seen: now,
                            bytes_transferred: 0,
                        });
                        session.last_seen = now;
                        session.bytes_transferred += payload as u64;
                    }

                    // AUTONOMOUS LOCAL DEFENSE
                    if should_ban {
                        // FIX: Use `try_send` to avoid `.await` inside the sync lock!
                        let _ = cmd_tx_harvester.try_send(ExecutionCommand::BlockMac(mac, ban_reason.to_string()));
                    }

                    processed_in_batch += 1;
                    if processed_in_batch >= 100 { break; } 
                }

                // --- PILLAR 6 GARBAGE COLLECTOR (Runs every 10 seconds) ---
                if last_gc.elapsed().as_secs() >= 10 {
                    let now = Instant::now();
                    for (mac_key, device) in state.iter_mut() {
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
                            
                            // Silent Memory Safety: Drop dead connections idle for > 10 mins
                            if idle_time > 600 { return false; }
                            
                            true // Keep session alive
                        });

                        if slowloris_detected {
                            let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac_key[0], mac_key[1], mac_key[2], mac_key[3], mac_key[4], mac_key[5]);
                            println!("🐢 [SLOWLORIS DETECTED] Device {} is exhausting state (Throughput < 100 B/s for > 5 mins)!", mac_str);
                            
                            // FIX: Use `try_send` here as well
                            let _ = cmd_tx_harvester.try_send(ExecutionCommand::BlockMac(*mac_key, "State Exhaustion (Slowloris)".to_string()));
                        }
                    }
                    last_gc = Instant::now();
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
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));
        loop {
            ticker.tick().await;
            
            let mut reports_to_send = Vec::new();
            {
                let mut state = telemetry_reporter_clone.lock().unwrap();
                for (mac, device) in state.iter_mut() {
                    let totals = std::mem::take(&mut device.totals);
                    if totals.total_connections > 0 {
                        reports_to_send.push((*mac, totals));
                    }
                }
            } 

            if !reports_to_send.is_empty() {
                println!("📤 Packing {} telemetry reports for the AI...", reports_to_send.len());
                
                for (mac, totals) in reports_to_send {
                    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
                    
                    let mac_string = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let mac_fb = builder.create_string(&mac_string);
                    let net_id_fb = builder.create_string(network_id);

                    // Build the AI Telemetry Payload defined in your router.fbs
                    let mut tel_builder = TelemetryReportBuilder::new(&mut builder);
                    tel_builder.add_network_id(net_id_fb);
                    tel_builder.add_mac(mac_fb);
                    tel_builder.add_bytes_in(totals.bytes_in);
                    tel_builder.add_bytes_out(totals.bytes_out);
                    tel_builder.add_unique_external_ips(totals.unique_external_ips.len() as u32);
                    tel_builder.add_total_connections(totals.total_connections);
                    tel_builder.add_passed_connections(totals.passed_connections);
                    tel_builder.add_dropped_connections(totals.dropped_connections);
                    tel_builder.add_anomaly_flags_count(totals.anomaly_flags_count);
                    tel_builder.add_heuristic_flags_count(totals.heuristic_flags_count);
                    tel_builder.add_infra_alert_count(totals.infra_alert_count);
                    // Mock port entropy for now until we add the math
                    tel_builder.add_port_entropy_score(0.0); 
                    
                    let tel_offset = tel_builder.finish();

                    let mut msg_builder = RouterMessageBuilder::new(&mut builder);
                    msg_builder.add_payload_type(IncomingPayload::TelemetryReport);
                    msg_builder.add_payload(tel_offset.as_union_value());
                    let final_msg = msg_builder.finish();
                    builder.finish(final_msg, None);

                    // Blast it to Axum! (Add .into() here to convert the Vec to Tungstenite's Bytes)
                    if let Err(e) = ws_sender.send(Message::Binary(builder.finished_data().to_vec().into())).await {
                        println!("🔴 [WS ERROR] Failed to beam telemetry to cloud: {}", e);
                    }
                }
            }
        }
    });

    // --- THREAD 3: THE CLOUD LISTENER (WebSocket Receiver) ---
    let cmd_tx_cloud = cmd_tx.clone();
    tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            if let Ok(Message::Binary(bytes)) = msg {
                if let Ok(response) = flatbuffers::root::<RouterResponse>(&bytes) {
                    if let (Some(status), Some(mac_str)) = (response.status(), response.mac()) {
                        println!("☁️ [CLOUD COMMAND] Received {} for MAC: {}", status, mac_str);
                        
                        let mut mac_bytes = [0u8; 6];
                        let parts: Vec<&str> = mac_str.split(':').collect();
                        if parts.len() == 6 {
                            for i in 0..6 {
                                mac_bytes[i] = u8::from_str_radix(parts[i], 16).unwrap_or(0);
                            }
                            
                            // Safe to await here since Thread 3 doesn't hold the Mutex lock
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
    });

    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("\n🛑 Shutting down Project_CIPHER... eBPF links detaching.");
        }
    }

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