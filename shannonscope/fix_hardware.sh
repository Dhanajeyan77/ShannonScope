#!/bin/bash
sed -i 's/let file = File::open(target).map_err/let parent_target = target.trim_end_matches(|c: char| c.is_ascii_digit());\n        let file = File::open(parent_target).map_err/g' src-tauri/src/engine/hardware.rs
sed -i 's/let dev_name = Path::new(target)/let parent_target = target.trim_end_matches(|c: char| c.is_ascii_digit());\n    let dev_name = Path::new(parent_target)/g' src-tauri/src/engine/hardware.rs
