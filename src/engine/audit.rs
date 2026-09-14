use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use printpdf::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: u64,
    pub action: String,
    pub target: String,
    pub status: String,
    pub operator_id: String,
    pub previous_hash: String,
    pub record_hash: String,
}

pub struct AuditLedger {
    log_path: String,
    pub entries: Vec<AuditEntry>,
}

impl AuditLedger {
    pub fn init(path: &str) -> Self {
        let mut ledger = Self {
            log_path: path.to_string(),
            entries: Vec::new(),
        };
        ledger.load();
        ledger
    }

    fn load(&mut self) {
        if Path::new(&self.log_path).exists() {
            if let Ok(mut file) = File::open(&self.log_path) {
                let mut data = String::new();
                if file.read_to_string(&mut data).is_ok() {
                    self.entries = serde_json::from_str(&data).unwrap_or_default();
                }
            }
        }
    }

    pub fn append(&mut self, action: &str, target: &str, status: &str, operator: &str) -> AuditEntry {
        let prev_hash = self.entries.last()
            .map(|e| e.record_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let index = self.entries.len() as u64;

        // Structured payload to hash
        let raw_to_hash = format!("{index}:{timestamp}:{action}:{target}:{status}:{operator}:{prev_hash}");
        let mut hasher = Sha256::new();
        hasher.update(raw_to_hash.as_bytes());
        let result = hasher.finalize();
        let record_hash = result.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let entry = AuditEntry {
            index,
            timestamp,
            action: action.to_string(),
            target: target.to_string(),
            status: status.to_string(),
            operator_id: operator.to_string(),
            previous_hash: prev_hash,
            record_hash,
        };

        self.entries.push(entry.clone());
        self.flush_to_disk();
        entry
    }

    pub fn verify_integrity(&self) -> (bool, Option<u64>) {
        let mut expected_prev = "0".repeat(64);
        for entry in &self.entries {
            if entry.previous_hash != expected_prev {
                return (false, Some(entry.index)); // Chain link broken
            }
            let raw_to_hash = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                entry.index, entry.timestamp, entry.action, entry.target,
                entry.status, entry.operator_id, entry.previous_hash
            );
            let mut hasher = Sha256::new();
            hasher.update(raw_to_hash.as_bytes());
            let result = hasher.finalize();
        let computed = result.iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if computed != entry.record_hash {
                return (false, Some(entry.index)); // Signature mismatch (entry tampered)
            }
            expected_prev = entry.record_hash.clone();
        }
        (true, None)
    }

    fn flush_to_disk(&self) {
        if let Ok(json_blob) = serde_json::to_string_pretty(&self.entries) {
            let _ = std::fs::write(&self.log_path, json_blob);
        }
    }

    pub fn generate_pdf_certificate(&self, entry_index: usize, out_path: &str) -> Result<(), String> {
        if entry_index >= self.entries.len() {
            return Err("Invalid entry index".to_string());
        }
        let entry = &self.entries[entry_index];
        let (doc, page1, layer1) = PdfDocument::new("Compliance Certificate", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);
        let font = doc.add_builtin_font(BuiltinFont::Helvetica).map_err(|e| e.to_string())?;
        
        current_layer.use_text(format!("Digital Forensics Compliance Certificate"), 16.0, Mm(20.0), Mm(270.0), &font);
        current_layer.use_text(format!("Action: {}", entry.action), 12.0, Mm(20.0), Mm(250.0), &font);
        current_layer.use_text(format!("Target: {}", entry.target), 12.0, Mm(20.0), Mm(240.0), &font);
        current_layer.use_text(format!("Timestamp: {}", entry.timestamp), 12.0, Mm(20.0), Mm(230.0), &font);
        current_layer.use_text(format!("Status: {}", entry.status), 12.0, Mm(20.0), Mm(220.0), &font);
        current_layer.use_text(format!("Operator ID: {}", entry.operator_id), 12.0, Mm(20.0), Mm(210.0), &font);
        current_layer.use_text(format!("Standard: NIST SP 800-88 Rev.1"), 12.0, Mm(20.0), Mm(190.0), &font);
        
        current_layer.use_text(format!("Entry hash: {}", entry.record_hash), 10.0, Mm(20.0), Mm(170.0), &font);
        current_layer.use_text(format!("Previous hash: {}", entry.previous_hash), 10.0, Mm(20.0), Mm(160.0), &font);

        let mut file = File::create(out_path).map_err(|e| e.to_string())?;
        let mut buf_writer = std::io::BufWriter::new(file);
        doc.save(&mut buf_writer).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn export_csv(&self, out_path: &str) -> Result<(), String> {
        let mut file = File::create(out_path).map_err(|e| e.to_string())?;
        writeln!(file, "Index,Timestamp,Action,Target,Status,Operator,RecordHash").map_err(|e| e.to_string())?;
        for entry in &self.entries {
            writeln!(file, "{},{},{},{},{},{},{}", 
                entry.index, entry.timestamp, entry.action, entry.target, entry.status, entry.operator_id, entry.record_hash
            ).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
