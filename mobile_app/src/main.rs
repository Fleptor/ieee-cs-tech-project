#![allow(non_snake_case)]
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

// Load the compiled Tailwind CSS and custom global styles into the application
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");
const MAIN_CSS: Asset = asset!("/assets/main.css");

// Application entry point. Bootstraps the Dioxus virtual DOM and launches the App component.
fn main() {
    dioxus::launch(App);
}

// Optimized zero-allocation sequence matcher for ultra-fast searches
fn sequence_match(query: &str, target: &str) -> bool {
    if query.is_empty() { return true; }
    let mut q_chars = query.chars().peekable();
    for t_char in target.chars() {
        if let Some(&q) = q_chars.peek() {
            if q.to_ascii_lowercase() == t_char.to_ascii_lowercase() { q_chars.next(); }
        }
        if q_chars.peek().is_none() { return true; }
    }
    false
}

// Represents the possible network access states for a device. Maps directly to the backend enum.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
enum DeviceState { Allowed, Blocked, Suspicious }

// Core data model representing a single device detected on the network.
// Mission 1: Manufacturer added!
#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct NetworkDevice {
    hostname: String, 
    ip: String, 
    mac: String, 
    manufacturer: String, 
    state: DeviceState, 
    last_seen: String,
}

// Represents the threat level of a specific security event.
#[derive(Clone, PartialEq)]
enum Severity { Critical, Warning, Info }

// Data model representing a historical security log or anomaly detection event.
#[derive(Clone, PartialEq)]
struct AlertEvent {
    id: usize, timestamp: String, severity: Severity, title: String, message: String,
}

// Filter states for the Devices view (used by the quick-filter chips).
#[derive(Clone, PartialEq)]
enum DeviceFilter { All, Allowed, Suspicious, Blocked, IoT }

// Filter states for the Alerts view (used by the severity filter chips).
#[derive(Clone, PartialEq)]
enum AlertFilter { All, Critical, Warnings, Info }

// Defines the application's routing tree. The NavBar layout wraps around all primary views.
#[derive(Clone, Routable, Debug, PartialEq)]
enum Route {
    #[layout(NavBar)]
    #[route("/")] Dashboard {},
    #[route("/devices")] Devices {},
    #[route("/alerts")] Alerts {},
}

// The root component. Injects global stylesheets and initializes the Router.
#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        Router::<Route> {}
    }
}

// Global layout component that wraps all pages, providing the bottom navigation tab bar.
#[component]
fn NavBar() -> Element {
    rsx! {
        // Main application layout wrapper: full screen, dark gradient background
        div { class: "h-screen w-full flex flex-col bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-slate-950 to-black font-sans relative overflow-hidden",
            
            // Scrollable content area: takes up remaining space above the fixed bottom navigation bar.
            // Outlet is where the active page (Dashboard, Devices, or Alerts) is dynamically injected.
            div { class: "flex-1 overflow-y-auto pb-28", Outlet::<Route> {} }
            
            // Bottom fixed navigation bar container providing global app routing
            nav { class: "absolute bottom-0 w-full h-24 bg-slate-950/80 backdrop-blur-xl border-t border-slate-800/50 flex flex-row justify-around items-start pt-3 px-2 z-[90]",
                
                // Navigation link to the Dashboard (Home) view
                Link { to: Route::Dashboard {}, active_class: "text-emerald-400 bg-slate-800/60 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)]", class: "flex flex-col items-center gap-1 w-20 py-2 rounded-2xl text-slate-500 transition-all duration-300 hover:text-slate-300",
                    // SVG Icon for the Dashboard (Grid/Home symbol)
                    svg { class: "w-6 h-6", fill: "none", stroke: "currentColor", stroke_width: "2", path { stroke_linecap: "round", stroke_linejoin: "round", d: "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" } }
                    // Text label for the Dashboard tab
                    span { class: "text-[10px] font-bold tracking-widest", "DASH" }
                }
                
                // Navigation link to the Device Management view
                Link { to: Route::Devices {}, active_class: "text-cyan-400 bg-slate-800/60 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)]", class: "flex flex-col items-center gap-1 w-20 py-2 rounded-2xl text-slate-500 transition-all duration-300 hover:text-slate-300",
                    // SVG Icon for Devices (Server/Network symbol)
                    svg { class: "w-6 h-6", fill: "none", stroke: "currentColor", stroke_width: "2", path { stroke_linecap: "round", stroke_linejoin: "round", d: "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" } }
                    // Text label for the Devices tab
                    span { class: "text-[10px] font-bold tracking-widest", "DEVICES" }
                }
                
                // Navigation link to the Alert History view
                Link { to: Route::Alerts {}, active_class: "text-red-400 bg-slate-800/60 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)]", class: "flex flex-col items-center gap-1 w-20 py-2 rounded-2xl text-slate-500 transition-all duration-300 hover:text-slate-300",
                    // SVG Icon for Alerts (Shield/Warning symbol)
                    svg { class: "w-6 h-6", fill: "none", stroke: "currentColor", stroke_width: "2", path { stroke_linecap: "round", stroke_linejoin: "round", d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" } }
                    // Text label for the Alerts tab
                    span { class: "text-[10px] font-bold tracking-widest", "ALERTS" }
                }
            }
        }
    }
}

// The Command Center view providing a high-level overview of network lockdown status.
#[component]
fn Dashboard() -> Element {
    // Local state: Tracks whether the entire network is currently in a manual lockdown mode.
    let mut is_locked = use_signal(|| false);
    rsx! {
        // Dashboard main container: changes to a red tint based on the lockdown state
        div { class: if is_locked() { "min-h-full w-full bg-red-950/40 flex flex-col items-center justify-center font-mono transition-colors duration-700 p-6" } else { "min-h-full w-full flex flex-col items-center justify-center font-mono transition-colors duration-700 p-6" },
            
            // Container for the central status ring and text below it
            div { class: "text-center mb-16",
                
                // The visual status ring: pulses red when locked, static emerald when nominal
                div { class: if is_locked() { "w-32 h-32 mx-auto rounded-full border-4 border-red-500 shadow-[0_0_30px_rgba(239,68,68,0.4)] flex items-center justify-center animate-pulse mb-6" } else { "w-32 h-32 mx-auto rounded-full border-4 border-emerald-500/30 shadow-[0_0_30px_rgba(52,211,153,0.1)] flex items-center justify-center mb-6" },
                    // Central logo text inside the ring
                    h1 { class: "text-3xl font-bold text-white tracking-widest", "CPHR" }
                }
                
                // Subtitle text indicating current system status
                p { class: if is_locked() { "text-red-400 tracking-widest text-lg font-bold" } else { "text-emerald-400 tracking-widest text-sm drop-shadow-[0_0_8px_rgba(52,211,153,0.5)]" },
                    if is_locked() { "L2 DATAPATH ISOLATED" } else { "SYSTEM NOMINAL" }
                }
            }
            
            // Main lockdown toggle button: executes the system override
            button {
                class: if is_locked() { "px-8 py-4 bg-transparent text-red-400 font-bold rounded-xl border border-red-500/50 transition-all active:scale-95 w-full max-w-xs backdrop-blur-sm" } else { "px-8 py-4 bg-red-600 hover:bg-red-500 text-white font-bold rounded-xl shadow-[0_10px_20px_rgba(220,38,38,0.3)] transition-all active:scale-95 w-full max-w-xs" },
                onclick:{
                    move |_| {
                        let currently_locked = is_locked();
                        spawn(async move{
                            if !currently_locked {
                                let client = reqwest::Client::new();
                                let _ = client.delete("http://127.0.0.1:3000/api/delete_blocked")
                                    .header("password", "super_secret_123")
                                    .send()
                                    .await;
                            }
                        });
                        is_locked.set(!is_locked()); }},
                if is_locked() { "DISENGAGE LOCKDOWN" } else { "SYSTEM OVERRIDE" }
            }
        }
    }
}

// The core Device Management view for monitoring and blocking individual network endpoints.
#[component]
fn Devices() -> Element {
    // Local state: Tracks which device is currently selected to show in the modal (None means modal is closed)
    let mut selected_device = use_signal(|| None::<NetworkDevice>);
    // Local state: Holds the current text typed into the fuzzy search bar
    let mut search_query = use_signal(|| String::new());
    // Local state: Tracks the active category filter chip (All, Allowed, Suspicious, Blocked, IoT)
    let mut active_filter = use_signal(|| DeviceFilter::All);

    // FETCH DATA FROM CLOUD API: Background asynchronous task to fetch the SQLite device list from the Axum backend
    let mut devices_resource = use_resource(move || async move {
        match reqwest::get("http://localhost:3000/api/devices").await {
            Ok(res) => res.json::<Vec<NetworkDevice>>().await.unwrap_or_default(),
            Err(_) => vec![], // Graceful degradation to an empty list if backend is off or unreachable
        }
    });

    // Unwraps the async resource payload into a usable Rust Vector
    let devices_list = match &*devices_resource.read() {
        Some(data) => data.clone(),
        None => vec![], 
    };

    // Extracting raw values from signals for use in the render loop
    let current_query = search_query();
    let current_filter = active_filter();

    rsx! {
        // Devices view main container: full height with standard padding
        div { class: "min-h-full w-full p-6 flex flex-col font-sans",
            
            // Header section: contains the page title and search bar area
            div { class: "mb-6 pt-4",
                // Page title
                h2 { class: "text-3xl font-bold text-white mb-4", "Devices" }
                
                // Search bar container: holds the input field and positioning for search/clear icons
                div { class: "relative w-full",
                    // Magnifying glass icon for the search bar
                    svg { class: "absolute left-3 top-3 w-5 h-5 text-slate-500", fill: "none", stroke: "currentColor", stroke_width: "2", path { stroke_linecap: "round", stroke_linejoin: "round", d: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" } }
                    
                    // Text input field for fuzzy matching devices by IP, MAC, or Hostname
                    input { 
                        class: "w-full bg-slate-900/80 border border-slate-700 text-white rounded-xl py-3 pl-10 pr-4 focus:outline-none focus:border-cyan-500 transition-all", 
                        placeholder: "Fuzzy search IP, MAC, Name, Manufacturer...",
                        // Lag fix applied: Uncontrolled input means typing remains smooth, updating state on every keystroke
                        oninput: move |e| search_query.set(e.value())
                    }
                }
            }

            // Filter chips container: horizontal scrollable row of policy state filters
            div { class: "flex flex-row gap-2 mb-6 overflow-x-auto pb-2 scrollbar-hide",
                // Filter button: Shows all devices
                button { class: if current_filter == DeviceFilter::All { "px-4 py-1.5 bg-cyan-900/50 text-cyan-400 border border-cyan-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(DeviceFilter::All), "All" }
                // Filter button: Shows only allowed devices
                button { class: if current_filter == DeviceFilter::Allowed { "px-4 py-1.5 bg-emerald-900/50 text-emerald-400 border border-emerald-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(DeviceFilter::Allowed), "Allowed" }
                // Filter button: Shows only suspicious devices pending review
                button { class: if current_filter == DeviceFilter::Suspicious { "px-4 py-1.5 bg-amber-900/50 text-amber-400 border border-amber-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(DeviceFilter::Suspicious), "Review" }
                // Filter button: Shows only blocked devices
                button { class: if current_filter == DeviceFilter::Blocked { "px-4 py-1.5 bg-red-900/50 text-red-400 border border-red-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(DeviceFilter::Blocked), "Blocked" }
                // Filter button: Shows only IoT devices (based on hostname prefix)
                button { class: if current_filter == DeviceFilter::IoT { "px-4 py-1.5 bg-indigo-900/50 text-indigo-400 border border-indigo-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(DeviceFilter::IoT), "IoT Only" }
            }

            // Device list container: vertically stacks all the individual device list cards
            div { class: "flex flex-col gap-3",
                // Loops through the fetched devices, applying the active search query and active filter chip logic
                for device in devices_list.iter().filter(|d| {
                    let matches_search = current_query.is_empty() 
                        || sequence_match(&current_query, &d.hostname) 
                        || sequence_match(&current_query, &d.ip) 
                        || sequence_match(&current_query, &d.mac)
                        || sequence_match(&current_query, &d.manufacturer);
                    
                    let matches_chip = match current_filter {
                        DeviceFilter::All => true,
                        DeviceFilter::Allowed => d.state == DeviceState::Allowed,
                        DeviceFilter::Suspicious => d.state == DeviceState::Suspicious,
                        DeviceFilter::Blocked => d.state == DeviceState::Blocked,
                        DeviceFilter::IoT => d.hostname.starts_with("IoT"), 
                    };
                    matches_search && matches_chip }) 
                {
                    // Individual device card: clickable row showing device basic info and state
                    div { 
                        key: "{device.mac}", 
                        class: "w-full bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-row justify-between items-center cursor-pointer hover:bg-slate-800 transition-colors",
                        // Click handler to open the modal by setting the selected_device state to this specific device
                        onclick: {
                            let device_target = device.clone();
                            move |_| selected_device.set(Some(device_target.clone()))
                        },
                        
                        // Device identity text block: holds the hostname, IP, and MAC address
                        div { class: "flex flex-col",
                            // Primary text: Hostname
                            span { class: "text-white font-bold text-sm", "{device.hostname}" }
                            // Secondary text: IP and MAC
                            span { class: "text-slate-500 text-xs font-mono mt-1", "{device.ip} • {device.mac} • {device.manufacturer}" }
                        }
                        
                        // Device state badge: visual indicator (pill) for Allowed/Blocked/Review
                        div { class: match device.state {
                                DeviceState::Allowed => "px-3 py-1 bg-emerald-500/10 text-emerald-400 text-[10px] font-bold rounded-full border border-emerald-500/20",
                                DeviceState::Blocked => "px-3 py-1 bg-red-500/10 text-red-500 text-[10px] font-bold rounded-full border border-red-500/20 shadow-[0_0_8px_rgba(239,68,68,0.2)]",
                                DeviceState::Suspicious => "px-3 py-1 bg-amber-500/10 text-amber-400 text-[10px] font-bold rounded-full border border-amber-500/20",
                            },
                            // Text rendered inside the pill badge
                            match device.state { DeviceState::Allowed => "ALLOWED", DeviceState::Blocked => "BLOCKED", DeviceState::Suspicious => "REVIEW" }
                        }
                    }
                }
            }
        }

        // Conditional rendering: Only displays the modal if a device has been clicked/selected
        if let Some(target) = selected_device() {
            // Modal overlay background: darkens the screen behind the active modal and handles outside clicks to close it
            div { 
                class: "fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex flex-col justify-end",
                onclick: move |_| selected_device.set(None),
                
                // Modal content container: slides up from the bottom with curved top edges
                div { 
                    class: "w-full bg-slate-900 border-t border-slate-700 rounded-t-3xl p-6 pb-12 shadow-2xl flex flex-col",
                    // Prevents clicks inside the modal from bubbling up and closing the overlay
                    onclick: move |e| e.stop_propagation(),
                    
                    // Modal drag handle indicator (purely visual pill at the top)
                    div { class: "w-12 h-1.5 bg-slate-700 rounded-full mx-auto mb-6" }
                    
                    // Modal Header: Device name
                    h3 { class: "text-2xl font-bold text-white mb-1", "{target.hostname}" }
                    // Modal Subtitle
                    span { class: "text-slate-400 text-sm mb-6", "Device Identity Profile" }
                    
                    // Device details grid: 2-column layout for detailed device telemetry
                    div { class: "grid grid-cols-2 gap-4 mb-8",
                        // Detail cell: IPv4 Address
                        div { class: "flex flex-col bg-slate-950 rounded-xl p-3 border border-slate-800", span { class: "text-slate-500 text-[10px] uppercase font-bold tracking-widest mb-1", "IPv4 Address" } span { class: "text-cyan-400 font-mono text-sm", "{target.ip}" } }
                        
                        // Detail cell: MAC Address
                        div { class: "flex flex-col bg-slate-950 rounded-xl p-3 border border-slate-800", span { class: "text-slate-500 text-[10px] uppercase font-bold tracking-widest mb-1", "MAC Address" } span { class: "text-cyan-400 font-mono text-sm", "{target.mac}" } }
                        
                        // Detail cell: Hardware Manufacturer (spans both columns)
                        div { class: "flex flex-col bg-slate-950 rounded-xl p-3 border border-slate-800 col-span-2", span { class: "text-slate-500 text-[10px] uppercase font-bold tracking-widest mb-1", "Hardware Manufacturer" } span { class: "text-cyan-400 font-mono text-sm", "{target.manufacturer}" } }
                        
                        // Detail cell: Last Seen timestamp
                        div { class: "flex flex-col bg-slate-950 rounded-xl p-3 border border-slate-800", span { class: "text-slate-500 text-[10px] uppercase font-bold tracking-widest mb-1", "Last Seen" } span { class: "text-white text-sm", "{target.last_seen}" } }
                        
                        // Detail cell: Current Policy State
                        div { class: "flex flex-col bg-slate-950 rounded-xl p-3 border border-slate-800", span { class: "text-slate-500 text-[10px] uppercase font-bold tracking-widest mb-1", "Policy State" } span { class: "text-white text-sm font-bold", match target.state { DeviceState::Allowed => "ALLOWED", DeviceState::Blocked => "BLOCKED", DeviceState::Suspicious => "REVIEW" } } }
                    }
                    
                    // Modal action buttons container: vertically stacks the block/unblock and cancel buttons
                    div { class: "flex flex-col gap-3",
                        // Conditional Action Button: If the device is not blocked, show the red block button
                        if target.state != DeviceState::Blocked {
                            button { class: "w-full py-4 bg-red-600 hover:bg-red-500 text-white font-bold rounded-xl shadow-[0_5px_15px_rgba(220,38,38,0.3)] transition-all", onclick:{
                                let mac_to_block = target.mac.clone();
                                move |_| {
                                    let mac = mac_to_block.clone();
                                    spawn(async move {
                                        let client = reqwest::Client::new();
                                        let payload = serde_json::json!({
                                            "mac": mac,
                                            "state":"blocked"
                                        });
                                        let _ = client.post("http://127.0.0.1:3000/api/state")
                                            .json(&payload)
                                            .send()
                                            .await;
                                        devices_resource.restart();
                                        selected_device.set(None);
                                    });
                                    println!("API CALL: Block MAC {}", target.mac); 
                                }
                            }, "REVOKE NETWORK ACCESS" }
                        } else {
                            // Conditional Action Button: If the device is blocked, show the green unblock button
                            button { class: "w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl shadow-[0_5px_15px_rgba(52,211,153,0.3)] transition-all", onclick:{
                                let mac_to_allow = target.mac.clone();
                                move |_| {
                                    let mac = mac_to_allow.clone();
                                    spawn(async move{
                                        let client = reqwest::Client::new();
                                        let payload = serde_json::json!({
                                            "mac": mac,
                                            "state": "allowed"
                                        });
                                    let _ = client.post("http://127.0.0.1:3000/api/state")
                                        .json(&payload)
                                        .send()
                                        .await;
                                    devices_resource.restart();
                                    selected_device.set(None);
                                    });
                                    println!("API CALL: Unblock MAC {}", target.mac); }}
                                , "RESTORE NETWORK ACCESS" }
                        }
                        // Action Button: Closes the modal without making any API calls
                        button { class: "w-full py-4 bg-transparent text-slate-400 font-bold rounded-xl border border-slate-700 hover:bg-slate-800 transition-all", onclick: move |_| selected_device.set(None), "CANCEL" }
                    }
                }
            }
        }
    }
}

// The Forensics view displaying a chronological timeline of security events.
#[component]
fn Alerts() -> Element {
    // Local state: Tracks the active severity filter for the event log
    let mut active_filter = use_signal(|| AlertFilter::All);
    let current_filter = active_filter();

    // Mock data: A static list of historical security events for UI demonstration
    let alerts_list = use_signal(|| vec![
        AlertEvent { id: 101, timestamp: "02:04:12 AM".to_string(), severity: Severity::Critical, title: "L2 Datapath Auto-Block".to_string(), message: "SYN Flood detected from 192.168.1.200. 4,521 packets dropped via eBPF.".to_string() },
        AlertEvent { id: 102, timestamp: "01:15:00 AM".to_string(), severity: Severity::Warning, title: "Suspicious Traffic Rate".to_string(), message: "IoT-Smart-Thermostat exceeded standard payload size (5MB up).".to_string() },
        AlertEvent { id: 103, timestamp: "11:30:45 PM".to_string(), severity: Severity::Info, title: "New MAC Registered".to_string(), message: "Unknown Apple Device connected. Allowed by default rule.".to_string() },
    ]);

    rsx! {
        // Alerts view main container: full height with standard padding
        div { class: "min-h-full w-full p-6 flex flex-col font-sans",
            
            // Header section: contains the page title and filter chips
            div { class: "mb-6 pt-4",
                // Page title
                h2 { class: "text-3xl font-bold text-white mb-4", "Event Log" }
                
                // Filter chips container: horizontal scrollable row of severity filters
                div { class: "flex flex-row gap-2 overflow-x-auto pb-2 scrollbar-hide",
                    // Filter button: Shows all historical logs
                    button { class: if current_filter == AlertFilter::All { "px-4 py-1.5 bg-cyan-900/50 text-cyan-400 border border-cyan-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(AlertFilter::All), "All Logs" }
                    // Filter button: Shows only critical events
                    button { class: if current_filter == AlertFilter::Critical { "px-4 py-1.5 bg-red-900/50 text-red-400 border border-red-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(AlertFilter::Critical), "Critical" }
                    // Filter button: Shows only warning events
                    button { class: if current_filter == AlertFilter::Warnings { "px-4 py-1.5 bg-amber-900/50 text-amber-400 border border-amber-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(AlertFilter::Warnings), "Warnings" }
                    // Filter button: Shows only informational events
                    button { class: if current_filter == AlertFilter::Info { "px-4 py-1.5 bg-blue-900/50 text-blue-400 border border-blue-800 rounded-full text-sm font-bold shrink-0" } else { "px-4 py-1.5 bg-slate-800/80 text-slate-400 rounded-full text-sm font-bold shrink-0 hover:bg-slate-700 transition-colors" }, onclick: move |_| active_filter.set(AlertFilter::Info), "Info" }
                }
            }
            
            // Alerts list container: vertically stacks all the alert event cards
            div { class: "flex flex-col gap-4",
                // Loops through the mock alerts list, applying the active severity filter logic
                for alert in alerts_list().iter().filter(|a| { 
                    match current_filter { 
                        AlertFilter::All => true, 
                        AlertFilter::Critical => a.severity == Severity::Critical, 
                        AlertFilter::Warnings => a.severity == Severity::Warning, 
                        AlertFilter::Info => a.severity == Severity::Info, 
                    } 
                }) {
                    // Individual alert card: color-coded left border based on severity
                    div { key: "{alert.id}",
                        class: match alert.severity { Severity::Critical => "w-full bg-slate-900/60 border-y border-r border-slate-800 border-l-4 border-l-red-500 rounded-r-2xl p-4 flex flex-col relative", Severity::Warning => "w-full bg-slate-900/60 border-y border-r border-slate-800 border-l-4 border-l-amber-500 rounded-r-2xl p-4 flex flex-col relative", Severity::Info => "w-full bg-slate-900/60 border-y border-r border-slate-800 border-l-4 border-l-blue-500 rounded-r-2xl p-4 flex flex-col relative", },
                        // Timestamp text
                        span { class: "text-slate-500 text-[10px] font-mono mb-2 tracking-wider", "{alert.timestamp}" }
                        // Alert Title (color matches severity)
                        span { class: match alert.severity { Severity::Critical => "text-red-400 font-bold text-sm mb-1", Severity::Warning => "text-amber-400 font-bold text-sm mb-1", Severity::Info => "text-blue-400 font-bold text-sm mb-1", }, "{alert.title}" }
                        // Alert Description text
                        span { class: "text-slate-300 text-xs leading-relaxed", "{alert.message}" }
                    }
                }
            }
        }
    }
}