#!/bin/bash
# Append a chmod 777 to the persist_artifact function
sed -i 's/Ok(hash_hex)/let _ = std::process::Command::new("chmod").arg("777").arg(path).output();\n        Ok(hash_hex)/g' src-tauri/src/engine/carver.rs
