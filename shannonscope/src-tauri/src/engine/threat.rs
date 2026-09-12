use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub name: String,
    pub description: String,
    pub severity: String, // CRITICAL, HIGH, MEDIUM
    pub byte_pattern: Vec<u8>,
}

pub struct ThreatEngine {
    signatures: Vec<ThreatSignature>,
}

impl ThreatEngine {
    pub fn new() -> Self {
        Self {
            signatures: vec![
                // Ransomware Signatures (Simplified Examples)
                ThreatSignature {
                    name: "WannaCry_Ransomware_Marker".to_string(),
                    description: "WannaCry WanaCrypt0r File Marker".to_string(),
                    severity: "CRITICAL".to_string(),
                    byte_pattern: b"WanaCrypt0r".to_vec(),
                },
                ThreatSignature {
                    name: "Ryuk_Ransomware_Marker".to_string(),
                    description: "Ryuk Hermes Ransomware Marker".to_string(),
                    severity: "CRITICAL".to_string(),
                    byte_pattern: b"HERMES".to_vec(),
                },
                ThreatSignature {
                    name: "LockBit_Ransomware".to_string(),
                    description: "LockBit 3.0 Ransomware Note Marker".to_string(),
                    severity: "CRITICAL".to_string(),
                    byte_pattern: b"LockBit_Ransomware".to_vec(),
                },
                // Emotet / Trojan
                ThreatSignature {
                    name: "Emotet_Dropper_Macro".to_string(),
                    description: "Emotet Malicious Office Macro Signature".to_string(),
                    severity: "HIGH".to_string(),
                    byte_pattern: b"AutoOpen".to_vec(),
                },
                // Basic Crypto Miner
                ThreatSignature {
                    name: "XMRig_CoinMiner".to_string(),
                    description: "XMRig Monero CPU Miner".to_string(),
                    severity: "HIGH".to_string(),
                    byte_pattern: b"stratum+tcp://".to_vec(),
                },
                // Hacking Tools
                ThreatSignature {
                    name: "Mimikatz_Credential_Dumper".to_string(),
                    description: "Mimikatz sekurlsa::logonpasswords output".to_string(),
                    severity: "CRITICAL".to_string(),
                    byte_pattern: b"mimikatz".to_vec(),
                }
            ],
        }
    }

    /// Scans a byte slice (e.g. an extracted carved file) for known Threat Signatures
    pub fn scan_payload(&self, data: &[u8]) -> Vec<String> {
        let mut detected_threats = Vec::new();
        
        // A simple brute-force sliding window search (can be upgraded to Aho-Corasick later for massive scales)
        for sig in &self.signatures {
            if Self::contains_subslice(data, &sig.byte_pattern) {
                detected_threats.push(format!("{}: {}", sig.severity, sig.name));
            }
        }

        detected_threats
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() { return true; }
        if haystack.len() < needle.len() { return false; }
        
        haystack.windows(needle.len()).any(|window| window == needle)
    }
}
