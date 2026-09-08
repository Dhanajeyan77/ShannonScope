use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CarvedArtifact {
    pub file_type: String,
    pub start_offset: u64,
    pub size_bytes: u64,
    pub output_path: String,
    pub sha256_checksum: String,
    pub is_fragmented_candidate: bool,
    pub confidence_score: f64,
    pub regex_strings: Vec<String>,
    pub threat_tags: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub index: usize,
    pub timestamp: u64,
    pub action: String,
    pub target: String,
    pub status: String,
    pub operator_id: String,
    pub previous_hash: String,
    pub record_hash: String,
}
