//! Cross-disk GPT disk-GUID collision detection (cloning / imaging indicator).

use gpt_forensic::collision::{find_disk_guid_collisions, GuidCollision};

const ZERO: &str = "00000000-0000-0000-0000-000000000000";

#[test]
fn distinct_guids_have_no_collisions() {
    let guids = [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ];
    assert!(find_disk_guid_collisions(&guids).is_empty());
}

#[test]
fn shared_guid_is_a_collision() {
    let g = "AABBCCDD-0000-0000-0000-000000000000";
    let guids = [g, "22222222-2222-2222-2222-222222222222", g];
    let c = find_disk_guid_collisions(&guids);
    assert_eq!(c.len(), 1);
    let first: &GuidCollision = &c[0];
    assert_eq!(first.members, vec![0, 2]);
}

#[test]
fn case_insensitive_and_zero_excluded() {
    let guids = [
        "aabbccdd-0000-0000-0000-000000000001",
        "AABBCCDD-0000-0000-0000-000000000001", // same, different case
        ZERO,
        ZERO, // the unset GUID is never a collision
    ];
    let c = find_disk_guid_collisions(&guids);
    assert_eq!(c.len(), 1, "only the real shared GUID collides");
    assert_eq!(c[0].members, vec![0, 1]);
}
