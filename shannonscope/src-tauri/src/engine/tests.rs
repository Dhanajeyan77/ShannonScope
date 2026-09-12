#[cfg(test)]
mod tests {
    use super::super::engine::threat::ThreatEngine;
    use super::super::engine::timeline::TimelineEngine;
    use std::path::Path;

    #[test]
    fn test_threat_engine() {
        let engine = ThreatEngine::new();
        let safe_payload = b"Just some normal text data. Nothing to see here.";
        let malicious_payload = b"Hello this is WanaCrypt0r ransomware!";
        
        assert_eq!(engine.scan_payload(safe_payload).len(), 0);
        
        let threats = engine.scan_payload(malicious_payload);
        assert_eq!(threats.len(), 1);
        assert!(threats[0].contains("WannaCry"));
    }

    #[test]
    fn test_timeline_engine() {
        // Test it on the src directory itself
        let events = TimelineEngine::generate_timeline("../src").unwrap();
        assert!(events.len() > 0); // Should find at least some files in src/
    }
}
