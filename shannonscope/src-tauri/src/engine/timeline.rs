use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct TimelineEvent {
    pub file_path: String,
    pub timestamp: u64, // Unix Timestamp
    pub event_type: String, // "MODIFIED", "ACCESSED", "CREATED"
}

pub struct TimelineEngine;

impl TimelineEngine {
    pub fn generate_timeline(mount_point: &str) -> Result<Vec<TimelineEvent>, String> {
        let mut events = Vec::new();
        Self::walk_dir(Path::new(mount_point), &mut events, 0)?;
        
        // Sort events chronologically (oldest to newest)
        events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        
        Ok(events)
    }

    fn walk_dir(dir: &Path, events: &mut Vec<TimelineEvent>, depth: u32) -> Result<(), String> {
        // Prevent infinite recursion on extremely deep or circular filesystems
        if depth > 10 { return Ok(()); }
        
        // Hardcap at 1000 events to ensure the UI graph renders quickly for the hackathon demo
        if events.len() > 1000 { return Ok(()); }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Skip directories we can't read
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            
            if let Ok(metadata) = entry.metadata() {
                let file_path = path.to_string_lossy().to_string();

                if let Ok(modified) = metadata.modified() {
                    events.push(TimelineEvent {
                        file_path: file_path.clone(),
                        timestamp: modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                        event_type: "MODIFIED".to_string(),
                    });
                }
                
                if let Ok(accessed) = metadata.accessed() {
                    events.push(TimelineEvent {
                        file_path: file_path.clone(),
                        timestamp: accessed.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                        event_type: "ACCESSED".to_string(),
                    });
                }

                // Linux metadata.created() can fail on some filesystems (like ext4 without xattrs), 
                // but we will try.
                if let Ok(created) = metadata.created() {
                    events.push(TimelineEvent {
                        file_path: file_path.clone(),
                        timestamp: created.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                        event_type: "CREATED".to_string(),
                    });
                }
            }

            if path.is_dir() {
                let _ = Self::walk_dir(&path, events, depth + 1);
            }
        }

        Ok(())
    }
}
