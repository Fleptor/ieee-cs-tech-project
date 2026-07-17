use ndarray::{Array1, Array2, Axis};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

// --- LAYER 2: LLM STRUCTURES ---
#[derive(Deserialize, Debug)]
pub struct LlmVerdict {
    pub threat_name: String,
    pub confidence: u8,
    pub human_explanation: String,
    pub should_block: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GlobalThreatIntel {
    pub banned_ips: Vec<String>,
    pub ad_domains: Vec<String>,
}

#[derive(Serialize)]
struct LlmRequest {
    model: String,
    max_tokens: u32, // <-- THE MISSING REQUIREMENT
    messages: Vec<Message>,
    system: String,
    temperature: f32,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct LlmResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

// --- LAYER 1: RUST ML STRUCTURES (Z-Score Baseline) ---
pub struct NetworkBaseline {
    pub training_buffer: Vec<[f64; 4]>, 
    pub means: Option<Array1<f64>>,
    pub std_devs: Option<Array1<f64>>,
}

impl Default for NetworkBaseline {
    fn default() -> Self {
        Self {
            training_buffer: Vec::with_capacity(50),
            means: None,
            std_devs: None,
        }
    }
}

impl NetworkBaseline {
    pub fn process_telemetry(&mut self, bytes_in: u64, bytes_out: u64, drops: u32, entropy: f32) -> bool {
        let feature_vector = [bytes_in as f64, bytes_out as f64, drops as f64, entropy as f64];

        if self.means.is_none() {
            self.training_buffer.push(feature_vector);
            
            if self.training_buffer.len() >= 50 {
                println!("🧠 [LAYER 1] 50 reports collected. Training Statistical Baseline...");
                
                let flat_data: Vec<f64> = self.training_buffer.iter().flatten().cloned().collect();
                let dataset = Array2::from_shape_vec((50, 4), flat_data).unwrap();
                
                let means = dataset.mean_axis(Axis(0)).unwrap();
                let std_devs = dataset.std_axis(Axis(0), 0.0);

                self.means = Some(means);
                self.std_devs = Some(std_devs);
                self.training_buffer.clear(); 
                println!("✅ [LAYER 1] Baseline established!");
            }
            println!("report number {} collected", self.training_buffer.len());
            return false; 
        }

        if let (Some(means), Some(std_devs)) = (&self.means, &self.std_devs) {
            let obs = Array1::from_vec(feature_vector.to_vec());
            
            let epsilon = 1e-8;
            let diff = &obs - means;
            let z_scores = diff.mapv(|x| x.abs()) / (std_devs + epsilon);

            let is_anomaly = z_scores.iter().any(|&z| z > 3.0);

            if is_anomaly {
                println!("🚨 [LAYER 1] Mathematical Anomaly Detected! Passing to Layer 2...");
                return true;
            }
        }
        false
    }
}

// --- LAYER 2: THE REASONING ENGINE ---
pub async fn consult_llm_supervisor(mac: &str, bytes_in: u64, bytes_out: u64, drops: u32, entropy: f32) -> Result<LlmVerdict, anyhow::Error> {
    println!("🤖 [LAYER 2] Waking up LLM Supervisor for MAC {}...", mac);
    
    let api_key = env::var("LLM_API_KEY").expect("API key not found");
    let client = Client::new();

    let prompt = format!(
        "ROUTER TELEMETRY ALERT:\nMAC: {}\nBytes In: {}\nBytes Out: {}\nDropped Connections: {}\nPort Entropy: {}\n\nAnalyze this data. Reply ONLY in raw JSON matching the required schema.",
        mac, bytes_in, bytes_out, drops, entropy
    );

    let request_body = LlmRequest {
        model: "claude-haiku-4-5".to_string(),
        max_tokens: 1024,
        temperature: 0.1, 
        system: "You are a Level 3 SOC Analyst AI monitoring a network. A Layer 1 Algorithm has flagged a device. You must decide if it is a false positive (e.g. Netflix download) or a true threat (e.g. Nmap scan, Data Exfiltration). You must reply strictly with a JSON object: { \"threat_name\": \"...\", \"confidence\": 0-100, \"human_explanation\": \"...\", \"should_block\": true/false }".to_string(),
        messages: vec![Message { role: "user".to_string(), content: prompt }],
    };

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&request_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let err_text = response.text().await?;
        return Err(anyhow::anyhow!("Anthropic API Error: {}", err_text));
    }

    let raw_res_text = response.text().await?;
    let llm_res: LlmResponse = serde_json::from_str(&raw_res_text)?;
    
    // Safety cleaner: Just in case Claude wraps the JSON in markdown blocks
    let mut raw_json_text = llm_res.content[0].text.trim();
    if raw_json_text.starts_with("```json") {
        raw_json_text = raw_json_text.trim_start_matches("```json").trim_end_matches("```").trim();
    }
    
    let verdict: LlmVerdict = serde_json::from_str(raw_json_text)?;
    Ok(verdict)
}

// --- NEW: DYNAMIC THREAT INTEL GENERATION (OSINT FEEDS) ---
pub async fn fetch_global_threat_intel() -> Result<GlobalThreatIntel, anyhow::Error> {
    println!("🌍 [CTI] Fetching live OSINT Threat Intel feeds...");
    
    let mut banned_ips = Vec::new();
    let mut ad_domains = Vec::new();
    let client = Client::new();

    // 1. Fetch Known Compromised IPs (Emerging Threats)
    println!("   -> Downloading Emerging Threats IP list...");
    if let Ok(res) = client.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt").send().await {
        if let Ok(text) = res.text().await {
            for line in text.lines() {
                let ip_str = line.trim();
                // Ignore comments and empty lines
                if !ip_str.is_empty() && !ip_str.starts_with('#') {
                    // Quick safety validation to ensure it's actually an IP
                    if ip_str.parse::<std::net::IpAddr>().is_ok() {
                        banned_ips.push(ip_str.to_string());
                        if banned_ips.len() >= 5000 { break; } // Cap at 5,000 to save router RAM
                    }
                }
            }
        }
    }

    // 2. Fetch Ad/Tracker Domains (StevenBlack's Unified Hosts)
    println!("   -> Downloading StevenBlack Ad/Tracker Domains...");
    if let Ok(res) = client.get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts").send().await {
        if let Ok(text) = res.text().await {
            for line in text.lines() {
                let line = line.trim();
                // The hosts file format is "0.0.0.0 trackingdomain.com"
                if line.starts_with("0.0.0.0") && line != "0.0.0.0 0.0.0.0" {
                    if let Some(domain) = line.split_whitespace().nth(1) {
                        ad_domains.push(domain.to_string());
                        if ad_domains.len() >= 10000 { break; } // Cap at 10,000 to save router RAM
                    }
                }
            }
        }
    }

    println!("✅ [CTI] Successfully parsed {} IPs and {} Ad Domains!", banned_ips.len(), ad_domains.len());

    Ok(GlobalThreatIntel {
        banned_ips,
        ad_domains,
    })
}