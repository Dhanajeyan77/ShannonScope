#!/bin/bash
sed -i '329,333c\#[tauri::command]\nfn generate_timeline(mount_point: String) -> Result<Vec<TimelineEvent>, String> {\n    TimelineEngine::generate_timeline(\&mount_point)\n}' src-tauri/src/main.rs
