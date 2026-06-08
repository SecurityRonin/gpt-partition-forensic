#![allow(clippy::unwrap_used, clippy::expect_used)]
//! gpt-forensic anomalies normalize onto the canonical `forensicnomicon::report`
//! model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Source};
use gpt_partition_forensic::{Anomaly, AnomalyKind};

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

#[test]
fn anomaly_evidence_carries_its_location() {
    use forensicnomicon::report::Location;
    // A location-bearing kind surfaces its LBA through Observation::evidence().
    let a = Anomaly::new(AnomalyKind::PartitionOutOfBounds {
        index: 2,
        last_lba: 4096,
        last_usable: 2048,
    });
    let ev = a.evidence();
    assert!(
        ev.iter()
            .any(|e| matches!(e.location, Some(Location::Lba(4096)))),
        "out-of-bounds partition should surface its last_lba as evidence: {ev:?}"
    );
}
