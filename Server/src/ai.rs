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
    /// Feeds new telemetry into Layer 1. 
    /// Returns `true` if it's an anomaly, `false` if it's normal traffic.
    pub fn process_telemetry(&mut self, bytes_in: u64, bytes_out: u64, drops: u32, entropy: f32) -> bool {
        let feature_vector = [bytes_in as f64, bytes_out as f64, drops as f64, entropy as f64];

        // If we don't have a model yet, we are still learning what "normal" is.
        if self.means.is_none() {
            self.training_buffer.push(feature_vector);
            
            // Once we hit 50 reports (approx 8 minutes of data), train the baseline!
            if self.training_buffer.len() >= 50 {
                println!("🧠 [LAYER 1] 50 reports collected. Training Statistical Baseline...");
                
                // Convert our Vec array into a mathematical Matrix (ndarray)
                let flat_data: Vec<f64> = self.training_buffer.iter().flatten().cloned().collect();
                let dataset = Array2::from_shape_vec((50, 4), flat_data).unwrap();
                
                // Calculate means and standard deviations for each of the 4 features
                let means = dataset.mean_axis(Axis(0)).unwrap();
                let std_devs = dataset.std_axis(Axis(0), 0.0);

                self.means = Some(means);
                self.std_devs = Some(std_devs);
                self.training_buffer.clear(); // Free the RAM
                println!("✅ [LAYER 1] Baseline established!");
            }
            return false; // Can't block while training
        }

        // We HAVE a baseline! Score the new traffic using Z-Scores.
        if let (Some(means), Some(std_devs)) = (&self.means, &self.std_devs) {
            let obs = Array1::from_vec(feature_vector.to_vec());
            
            // Calculate Z-Score: |x - mean| / std_dev
            // We add a tiny epsilon to prevent division by zero if std_dev is exactly 0
            let epsilon = 1e-8;
            let diff = &obs - means;
            let z_scores = diff.mapv(|x| x.abs()) / (std_devs + epsilon);

            // If ANY metric deviates by more than 3 standard deviations, it's an anomaly!
            // (In a normal distribution, 99.7% of benign data falls within 3 standard deviations).
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
        model: "claude-3-haiku-20240307".to_string(),
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

    let llm_res: LlmResponse = response.json().await?;
    let raw_json_text = &llm_res.content[0].text;
    
    let verdict: LlmVerdict = serde_json::from_str(raw_json_text)?;
    Ok(verdict)
}

// --- NEW: DYNAMIC THREAT INTEL GENERATION ---
pub async fn fetch_global_threat_intel() -> Result<GlobalThreatIntel, anyhow::Error> {
    println!("🌍 [CTI] Requesting latest Global Threat Intel from Claude...");
    
    let api_key = env::var("LLM_API_KEY").expect("API key not found");
    let client = Client::new();

    let prompt = "Provide the latest known IOCs (Indicators of Compromise). I need 5 known malicious botnet/malware IP addresses, and 5 known aggressive ad-tracking/telemetry domains. Reply strictly with JSON matching this schema: { \"banned_ips\": [\"ip1\", ...], \"ad_domains\": [\"domain1\", ...] }".to_string();

    let request_body = LlmRequest {
        model: "claude-3-haiku-20240307".to_string(),
        temperature: 0.5, // Slightly higher temperature so it generates varied IPs each time it boots
        system: "You are an elite Cyber Threat Intelligence (CTI) API. Reply strictly with raw JSON. No markdown, no conversational text.".to_string(),
        messages: vec![Message { role: "user".to_string(), content: prompt }],
    };

    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&request_body)
        .send()
        .await?;

    let llm_res: LlmResponse = response.json().await?;
    let raw_json_text = &llm_res.content[0].text;
    
    let intel: GlobalThreatIntel = serde_json::from_str(raw_json_text)?;
    Ok(intel)
}