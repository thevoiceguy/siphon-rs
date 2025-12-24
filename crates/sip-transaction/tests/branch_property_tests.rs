// siphon-rs - The Siphon SIP Stack
// Copyright (C) 2025 James Ferris <ferrous.communications@gmail.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use proptest::prelude::*;
use sip_transaction::{branch_from_via, generate_branch_id};

// Helper function to validate branch has RFC 3261 magic cookie
fn is_valid_branch(branch: &str) -> bool {
    branch.starts_with("z9hG4bK")
}

proptest! {
    /// Test that generated branch IDs always start with magic cookie.
    #[test]
    fn generated_branch_has_magic_cookie(_iteration in 0..100) {
        let branch = generate_branch_id();
        prop_assert!(branch.starts_with("z9hG4bK"), "Branch: {}", branch);
        prop_assert!(branch.len() > 7, "Branch too short: {}", branch);
    }

    /// Test that generated branch IDs are unique.
    #[test]
    fn generated_branches_are_unique(_iteration in 0..50) {
        let branch1 = generate_branch_id();
        let branch2 = generate_branch_id();
        prop_assert_ne!(branch1, branch2);
    }

    /// Test valid branch detection.
    #[test]
    fn valid_branch_detection(suffix in "[a-zA-Z0-9]{8,16}") {
        let branch = format!("z9hG4bK{}", suffix);
        prop_assert!(is_valid_branch(&branch));
    }

    /// Test invalid branches are rejected.
    #[test]
    fn invalid_branch_detection(
        prefix in "[a-z]{1,8}",
        suffix in "[a-z0-9]{1,8}"
    ) {
        // Branch without magic cookie should be invalid
        let branch = format!("{}{}", prefix, suffix);
        if !branch.starts_with("z9hG4bK") {
            prop_assert!(!is_valid_branch(&branch));
        }
    }

    /// Test branch extraction from Via headers.
    #[test]
    fn branch_extraction_from_via(
        host in "[a-z]{3,10}",
        branch_suffix in "[a-zA-Z0-9]{8,16}"
    ) {
        let branch = format!("z9hG4bK{}", branch_suffix);
        let via = format!("SIP/2.0/UDP {};branch={}", host, branch);

        let extracted = branch_from_via(&via);
        prop_assert!(extracted.is_some());
        prop_assert_eq!(extracted.unwrap(), branch);
    }

    /// Test branch extraction with additional parameters.
    #[test]
    fn branch_with_multiple_params(
        host in "[a-z]{3,10}",
        branch_suffix in "[a-zA-Z0-9]{8}",
        received in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        rport in 1024u16..65535,
    ) {
        let branch = format!("z9hG4bK{}", branch_suffix);
        let via = format!(
            "SIP/2.0/UDP {};branch={};received={};rport={}",
            host, branch, received, rport
        );

        let extracted = branch_from_via(&via);
        prop_assert!(extracted.is_some());
        prop_assert_eq!(extracted.unwrap(), branch);
    }

    /// Test case sensitivity of branch parameter.
    #[test]
    fn branch_param_case_insensitive(
        branch_suffix in "[a-zA-Z0-9]{8}",
        case_variant in 0u8..4,
    ) {
        let branch = format!("z9hG4bK{}", branch_suffix);
        let param_name = match case_variant {
            0 => "branch",
            1 => "Branch",
            2 => "BRANCH",
            _ => "BrAnCh",
        };

        let via = format!("SIP/2.0/UDP host;{}={}", param_name, branch);
        let extracted = branch_from_via(&via);

        prop_assert!(extracted.is_some());
        prop_assert_eq!(extracted.unwrap(), branch);
    }
}

#[test]
fn branch_from_via_without_branch_param() {
    let via = "SIP/2.0/UDP host.example.com:5060";
    assert_eq!(branch_from_via(via), None);
}

#[test]
fn branch_from_via_with_empty_branch() {
    let via = "SIP/2.0/UDP host;branch=";
    let extracted = branch_from_via(via);
    // Should extract empty string (parser behavior)
    assert!(extracted.is_some());
}

#[test]
fn branch_from_via_complex() {
    let via = "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKnashds8;received=192.0.2.1;rport=5060";
    let extracted = branch_from_via(via).expect("Should extract branch");
    assert_eq!(extracted, "z9hG4bKnashds8");
}

#[test]
fn valid_branch_magic_cookie() {
    assert!(is_valid_branch("z9hG4bKabcdef123"));
    assert!(is_valid_branch("z9hG4bK"));
    assert!(is_valid_branch("z9hG4bKx"));
}

#[test]
fn invalid_branch_patterns() {
    assert!(!is_valid_branch("z9hG4b")); // Too short
    assert!(!is_valid_branch("branch123")); // No magic cookie
    assert!(!is_valid_branch("")); // Empty
    assert!(!is_valid_branch("Z9HG4BKabcdef")); // Wrong case (if case sensitive)
}

#[test]
fn branch_generation_length() {
    let branch = generate_branch_id();
    // Should be magic cookie (7) + random suffix
    assert!(branch.len() > 7);
    assert!(branch.len() < 40); // Reasonable upper bound
}

#[test]
fn branch_generation_uniqueness() {
    use std::collections::HashSet;
    let mut branches = HashSet::new();

    for _ in 0..1000 {
        let branch = generate_branch_id();
        assert!(
            branches.insert(branch.to_string()),
            "Generated duplicate branch"
        );
    }
}
