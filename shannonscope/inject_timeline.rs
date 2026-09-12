use crate::engine::timeline::{TimelineEngine, TimelineEvent};

#[tauri::command]
fn generate_timeline(mount_point: String) -> Result<Vec<TimelineEvent>, String> {
    TimelineEngine::generate_timeline(&mount_point)
}
