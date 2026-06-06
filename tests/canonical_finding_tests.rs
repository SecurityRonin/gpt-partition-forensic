//! gpt-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Source};
use gpt_forensic::{Anomaly, AnomalyKind};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = Anomaly::new(AnomalyKind::BackupGptUnreadable);
    let f = a.to_finding(Source {
        analyzer: "gpt-forensic".to_string(),
        scope: "GPT".to_string(),
        version: None,
    });
    assert_eq!(f.code, "GPT-BACKUP-MISSING");
    assert!(f.severity.is_some());
    assert_eq!(f.source.analyzer, "gpt-forensic");
}
