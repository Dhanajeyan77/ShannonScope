#!/bin/bash
sed -i '324c\fn sandbox_unmount(target: String) -> Result<SandboxResult, String> {\n    SandboxEngine::safe_unmount(\&target)\n}' src-tauri/src/main.rs
sed -i '330c\fn generate_timeline(mount_point: String) -> Result<Vec<TimelineEvent>, String> {\n    TimelineEngine::generate_timeline(\&mount_point)\n}' src-tauri/src/main.rs
