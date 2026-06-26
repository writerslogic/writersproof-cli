// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use crate::mmr::errors::MmrError;
use crate::mmr::proof::{InclusionProof, RangeProof};
use crate::mmr::store::MemoryStore;

#[test]
fn test_find_peaks() {
    assert_eq!(find_peaks(0), Vec::<u64>::new());
    assert_eq!(find_peaks(1), vec![0]);
    assert_eq!(find_peaks(3), vec![2]);
    assert_eq!(find_peaks(4), vec![2, 3]);
    assert_eq!(find_peaks(7), vec![6]);
}

#[test]
fn test_mmr_append_and_root() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    let idx1 = mmr.append(b"1").expect("append 1");
    assert_eq!(idx1, 0);
    assert_eq!(mmr.size(), 1);
    let root1 = mmr.get_root().expect("get root 1");

    let idx2 = mmr.append(b"2").expect("append 2");
    assert_eq!(idx2, 1);
    assert_eq!(mmr.size(), 3);
    let root2 = mmr.get_root().expect("get root 2");
    assert_ne!(root1, root2);

    let idx3 = mmr.append(b"3").expect("append 3");
    assert_eq!(idx3, 3);
    assert_eq!(mmr.size(), 4);
}

#[test]
fn test_leaf_count_from_size() {
    assert_eq!(leaf_count_from_size(0), 0);
    assert_eq!(leaf_count_from_size(1), 1);
    assert_eq!(leaf_count_from_size(3), 2);
    assert_eq!(leaf_count_from_size(4), 3);
    assert_eq!(leaf_count_from_size(7), 4);
}

#[test]
fn test_inclusion_proof() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..10 {
        mmr.append(&[i as u8]).expect("append");
    }

    for i in 0..10 {
        let leaf_idx = mmr.get_leaf_index(i).expect("get leaf index");
        let proof = mmr.generate_proof(leaf_idx).expect("generate proof");

        assert_eq!(proof.leaf_index, leaf_idx);
        assert_eq!(proof.root, mmr.get_root().expect("get root"));
    }
}

#[test]
fn test_inclusion_proof_verify_valid() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..10u8 {
        mmr.append(&[i]).expect("append");
    }

    for i in 0..10u64 {
        let leaf_idx = mmr.get_leaf_index(i).expect("get leaf index");
        let proof = mmr.generate_proof(leaf_idx).expect("generate proof");
        proof.verify(&[i as u8]).expect("valid proof should verify");
    }
}

#[test]
fn test_inclusion_proof_verify_wrong_data() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..5u8 {
        mmr.append(&[i]).expect("append");
    }

    let leaf_idx = mmr.get_leaf_index(2).expect("get leaf index");
    let proof = mmr.generate_proof(leaf_idx).expect("generate proof");
    let err = proof.verify(b"wrong data").unwrap_err();
    assert!(
        matches!(err, MmrError::HashMismatch),
        "expected HashMismatch, got {err:?}"
    );
}

#[test]
fn test_inclusion_proof_verify_tampered_root() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..4u8 {
        mmr.append(&[i]).expect("append");
    }

    let leaf_idx = mmr.get_leaf_index(0).expect("get leaf index");
    let mut proof = mmr.generate_proof(leaf_idx).expect("generate proof");
    proof.root = [0xffu8; 32];
    let err = proof.verify(&[0u8]).unwrap_err();
    assert!(
        matches!(err, MmrError::InvalidProof),
        "expected InvalidProof, got {err:?}"
    );
}

#[test]
fn test_inclusion_proof_serialize_deserialize_roundtrip() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..8u8 {
        mmr.append(&[i]).expect("append");
    }

    for i in 0..8u64 {
        let leaf_idx = mmr.get_leaf_index(i).expect("get leaf index");
        let proof = mmr.generate_proof(leaf_idx).expect("generate proof");
        let bytes = proof.serialize().expect("serialize should succeed");
        let restored = InclusionProof::deserialize(&bytes).expect("deserialize should succeed");

        assert_eq!(proof.leaf_index, restored.leaf_index);
        assert_eq!(proof.leaf_hash, restored.leaf_hash);
        assert_eq!(proof.merkle_path.len(), restored.merkle_path.len());
        for (a, b) in proof.merkle_path.iter().zip(restored.merkle_path.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.is_left, b.is_left);
        }
        assert_eq!(proof.peaks, restored.peaks);
        assert_eq!(proof.peak_position, restored.peak_position);
        assert_eq!(proof.mmr_size, restored.mmr_size);
        assert_eq!(proof.root, restored.root);

        // Deserialized proof should still verify
        restored
            .verify(&[i as u8])
            .expect("deserialized proof should verify");
    }
}

#[test]
fn test_inclusion_proof_deserialize_too_short() {
    let err = InclusionProof::deserialize(&[0u8; 10]).unwrap_err();
    assert!(matches!(err, MmrError::InvalidNodeData));
}

#[test]
fn test_inclusion_proof_deserialize_wrong_version() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");
    mmr.append(b"a").expect("append");
    let leaf_idx = mmr.get_leaf_index(0).expect("get leaf index");
    let proof = mmr.generate_proof(leaf_idx).expect("generate proof");
    let mut bytes = proof.serialize().expect("serialize");
    bytes[0] = 0xff; // corrupt version
    let err = InclusionProof::deserialize(&bytes).unwrap_err();
    assert!(matches!(err, MmrError::InvalidProof));
}

#[test]
fn test_single_element_proof() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    mmr.append(b"only").expect("append");
    let proof = mmr.generate_proof(0).expect("generate proof");

    assert!(
        proof.merkle_path.is_empty(),
        "single leaf should have empty path"
    );
    assert_eq!(proof.peaks.len(), 1);
    proof
        .verify(b"only")
        .expect("single-element proof should verify");

    let bytes = proof.serialize().expect("serialize");
    let restored = InclusionProof::deserialize(&bytes).expect("deserialize");
    restored
        .verify(b"only")
        .expect("roundtripped single-element proof should verify");
}

#[test]
fn test_range_proof_verify_valid() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..8u8 {
        mmr.append(&[i]).expect("append");
    }

    let proof = mmr
        .generate_range_proof(1, 3)
        .expect("generate range proof");
    let leaf_data: Vec<Vec<u8>> = (1..=3u8).map(|i| vec![i]).collect();
    proof
        .verify(&leaf_data)
        .expect("valid range proof should verify");
}

#[test]
fn test_range_proof_verify_wrong_data() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..8u8 {
        mmr.append(&[i]).expect("append");
    }

    let proof = mmr
        .generate_range_proof(0, 2)
        .expect("generate range proof");
    let bad_data: Vec<Vec<u8>> = vec![vec![0], vec![1], vec![99]];
    let err = proof.verify(&bad_data).unwrap_err();
    assert!(matches!(err, MmrError::HashMismatch));
}

#[test]
fn test_range_proof_wrong_count() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..4u8 {
        mmr.append(&[i]).expect("append");
    }

    let proof = mmr
        .generate_range_proof(0, 1)
        .expect("generate range proof");
    // Pass wrong number of leaves
    let err = proof.verify(&[vec![0]]).unwrap_err();
    assert!(matches!(err, MmrError::InvalidProof));
}

#[test]
fn test_range_proof_serialize_deserialize_roundtrip() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..8u8 {
        mmr.append(&[i]).expect("append");
    }

    let proof = mmr
        .generate_range_proof(2, 5)
        .expect("generate range proof");
    let bytes = proof.serialize().expect("serialize should succeed");
    let restored = RangeProof::deserialize(&bytes).expect("deserialize should succeed");

    assert_eq!(proof.start_leaf, restored.start_leaf);
    assert_eq!(proof.end_leaf, restored.end_leaf);
    assert_eq!(proof.leaf_indices, restored.leaf_indices);
    assert_eq!(proof.leaf_hashes, restored.leaf_hashes);
    assert_eq!(proof.sibling_path.len(), restored.sibling_path.len());
    for (a, b) in proof.sibling_path.iter().zip(restored.sibling_path.iter()) {
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.is_left, b.is_left);
    }
    assert_eq!(proof.peaks, restored.peaks);
    assert_eq!(proof.peak_position, restored.peak_position);
    assert_eq!(proof.mmr_size, restored.mmr_size);
    assert_eq!(proof.root, restored.root);

    // Deserialized proof should still verify
    let leaf_data: Vec<Vec<u8>> = (2..=5u8).map(|i| vec![i]).collect();
    restored
        .verify(&leaf_data)
        .expect("deserialized range proof should verify");
}

#[test]
fn test_range_proof_deserialize_too_short() {
    let err = RangeProof::deserialize(&[0u8; 5]).unwrap_err();
    assert!(matches!(err, MmrError::InvalidNodeData));
}

#[test]
fn test_range_proof_deserialize_wrong_version() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");
    for i in 0..4u8 {
        mmr.append(&[i]).expect("append");
    }
    let proof = mmr
        .generate_range_proof(0, 1)
        .expect("generate range proof");
    let mut bytes = proof.serialize().expect("serialize");
    bytes[0] = 0xff;
    let err = RangeProof::deserialize(&bytes).unwrap_err();
    assert!(matches!(err, MmrError::InvalidProof));
}

#[test]
fn test_mmr_error_variants() {
    // Verify Display output for each variant
    let cases: Vec<(MmrError, &str)> = vec![
        (MmrError::Empty, "empty"),
        (MmrError::CorruptedStore, "corrupted store"),
        (MmrError::IndexOutOfRange, "index out of range"),
        (MmrError::InvalidNodeData, "invalid node data"),
        (MmrError::InvalidProof, "invalid proof"),
        (MmrError::HashMismatch, "hash mismatch"),
        (MmrError::NodeNotFound, "node not found"),
        (
            MmrError::ProofTooLarge,
            "proof component exceeds u16::MAX elements",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn test_empty_mmr_operations() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    assert_eq!(mmr.size(), 0);
    assert_eq!(mmr.leaf_count(), 0);
    assert!(matches!(mmr.get_root(), Err(MmrError::Empty)));
    assert!(matches!(mmr.generate_proof(0), Err(MmrError::Empty)));
    assert!(matches!(
        mmr.generate_range_proof(0, 0),
        Err(MmrError::Empty)
    ));
    assert!(matches!(mmr.get_leaf_index(0), Err(MmrError::Empty)));
}

#[test]
fn test_index_out_of_range() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");
    mmr.append(b"a").expect("append a");
    mmr.append(b"b").expect("append b");

    // Leaf ordinal beyond leaf count
    assert!(matches!(
        mmr.get_leaf_index(5),
        Err(MmrError::IndexOutOfRange)
    ));
    // MMR position beyond size
    assert!(matches!(mmr.get(99), Err(MmrError::IndexOutOfRange)));
    // Range proof beyond leaf count
    assert!(matches!(
        mmr.generate_range_proof(0, 99),
        Err(MmrError::IndexOutOfRange)
    ));
}

#[test]
fn test_large_mmr_proof_integrity() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..64u64 {
        mmr.append(&i.to_le_bytes()).expect("append");
    }

    assert_eq!(mmr.leaf_count(), 64);

    // Verify proofs at boundaries: first, last, middle
    for &ordinal in &[0u64, 31, 63] {
        let leaf_idx = mmr.get_leaf_index(ordinal).expect("get leaf index");
        let proof = mmr.generate_proof(leaf_idx).expect("generate proof");
        proof
            .verify(&ordinal.to_le_bytes())
            .expect("large MMR proof should verify");
    }

    // Range proof spanning multiple subtrees
    let range_proof = mmr
        .generate_range_proof(10, 20)
        .expect("generate range proof");
    let leaf_data: Vec<Vec<u8>> = (10..=20u64).map(|i| i.to_le_bytes().to_vec()).collect();
    range_proof
        .verify(&leaf_data)
        .expect("large range proof should verify");
}

#[test]
fn test_inclusion_proof_tampered_peak() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..4u8 {
        mmr.append(&[i]).expect("append");
    }

    let leaf_idx = mmr.get_leaf_index(1).expect("get leaf index");
    let mut proof = mmr.generate_proof(leaf_idx).expect("generate proof");
    // Corrupt the peak at peak_position
    proof.peaks[proof.peak_position] = [0xaa; 32];
    let err = proof.verify(&[1u8]).unwrap_err();
    assert!(matches!(err, MmrError::InvalidProof));
}

#[test]
fn test_inclusion_proof_invalid_peak_position() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");
    mmr.append(b"x").expect("append x");
    mmr.append(b"y").expect("append y");

    let leaf_idx = mmr.get_leaf_index(0).expect("get leaf index");
    let mut proof = mmr.generate_proof(leaf_idx).expect("generate proof");
    proof.peak_position = 999;
    let err = proof.verify(b"x").unwrap_err();
    assert!(matches!(err, MmrError::InvalidProof));
}

#[test]
fn test_get_leaf_indices_range() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");

    for i in 0..8u8 {
        mmr.append(&[i]).expect("append");
    }

    let indices = mmr.get_leaf_indices(0, 7).expect("get leaf indices");
    assert_eq!(indices.len(), 8);

    // Each should match the individual get_leaf_index
    for ordinal in 0..8u64 {
        let single = mmr.get_leaf_index(ordinal).expect("get leaf index");
        assert_eq!(indices[ordinal as usize], single);
    }

    // start > end is an error
    assert!(matches!(
        mmr.get_leaf_indices(5, 3),
        Err(MmrError::InvalidProof)
    ));
}

#[test]
fn test_node_serialize_deserialize_roundtrip() {
    use crate::mmr::node::Node;

    let node = Node::new_leaf(42, b"test data");
    let bytes = node.serialize();
    let restored = Node::deserialize(&bytes).expect("node deserialize should succeed");

    assert_eq!(node.index, restored.index);
    assert_eq!(node.height, restored.height);
    assert_eq!(node.hash, restored.hash);
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

#[test]
fn test_range_proof_cross_peak_n5() {
    let store = Box::new(MemoryStore::new());
    let mmr = Mmr::new(store).expect("create mmr");
    for i in 0..5u64 {
        mmr.append(&i.to_le_bytes()).expect("append");
    }
    assert_eq!(mmr.leaf_count(), 5);
    let peaks = mmr.get_peaks().expect("peaks");
    assert_eq!(peaks.len(), 2, "n=5 should have 2 peaks");

    let proof = mmr
        .generate_range_proof(0, 4)
        .expect("generate range proof");
    let data: Vec<Vec<u8>> = (0..5u64).map(|i| i.to_le_bytes().to_vec()).collect();
    proof
        .verify(&data)
        .expect("cross-peak range proof should verify");
}

mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Build a fresh MMR with `n` leaves, each derived from its ordinal.
    fn build_mmr(n: usize) -> Mmr {
        let store = Box::new(MemoryStore::new());
        let mmr = Mmr::new(store).unwrap();
        for i in 0..n {
            mmr.append(&(i as u64).to_le_bytes()).unwrap();
        }
        mmr
    }

    proptest! {
        /// Peak count equals popcount(leaf_count) for any number of appends.
        #[test]
        fn peak_count_eq_popcount(n in 1u64..512) {
            let peaks = find_peaks(leaf_count_to_mmr_size(n));
            prop_assert_eq!(peaks.len(), n.count_ones() as usize);
        }

        /// leaf_count_from_size is the inverse of the append sequence:
        /// after appending n leaves, leaf_count() == n.
        #[test]
        fn leaf_count_roundtrip(n in 1usize..256) {
            let mmr = build_mmr(n);
            prop_assert_eq!(mmr.leaf_count(), n as u64);
        }

        /// MMR size grows monotonically with each append.
        #[test]
        fn size_monotonically_increases(n in 2usize..128) {
            let store = Box::new(MemoryStore::new());
            let mmr = Mmr::new(store).unwrap();
            let mut prev_size = mmr.size();
            for i in 0..n {
                mmr.append(&(i as u64).to_le_bytes()).unwrap();
                let new_size = mmr.size();
                prop_assert!(new_size > prev_size, "size must increase: {} vs {}", prev_size, new_size);
                prev_size = new_size;
            }
        }

        /// Root hash is deterministic: two MMRs built from the same
        /// leaf sequence produce identical roots.
        #[test]
        fn root_determinism(n in 1usize..128) {
            let a = build_mmr(n);
            let b = build_mmr(n);
            prop_assert_eq!(a.get_root().unwrap(), b.get_root().unwrap());
        }

        /// Different leaf sequences produce different roots (collision resistance).
        #[test]
        fn different_leaves_different_roots(n in 2usize..64) {
            let a = build_mmr(n);
            // Build b with shifted data
            let store = Box::new(MemoryStore::new());
            let b = Mmr::new(store).unwrap();
            for i in 0..n {
                b.append(&((i as u64 + 1000).to_le_bytes())).unwrap();
            }
            prop_assert_ne!(a.get_root().unwrap(), b.get_root().unwrap());
        }

        /// Every leaf produces a valid inclusion proof that verifies.
        #[test]
        fn all_leaves_provable(n in 1usize..128) {
            let mmr = build_mmr(n);
            for leaf_ord in 0..n as u64 {
                let idx = mmr.get_leaf_index(leaf_ord).unwrap();
                let proof = mmr.generate_proof(idx).unwrap();
                let data = leaf_ord.to_le_bytes();
                proof.verify(&data).map_err(|e| {
                    TestCaseError::Fail(format!("leaf {leaf_ord} proof failed: {e}").into())
                })?;
            }
        }

        /// Tampered leaf data fails proof verification.
        #[test]
        fn tampered_data_fails_proof(n in 1usize..64) {
            let mmr = build_mmr(n);
            let idx = mmr.get_leaf_index(0).unwrap();
            let proof = mmr.generate_proof(idx).unwrap();
            let tampered = 9999u64.to_le_bytes();
            prop_assert!(proof.verify(&tampered).is_err());
        }

        /// Range proofs verify for any contiguous leaf range, including
        /// ranges that span multiple peaks (e.g. n=5).
        #[test]
        fn range_proof_verifies(n in 2usize..64) {
            let mmr = build_mmr(n);
            let proof = mmr.generate_range_proof(0, n as u64 - 1).unwrap();
            let data: Vec<Vec<u8>> = (0..n as u64)
                .map(|i| i.to_le_bytes().to_vec())
                .collect();
            proof.verify(&data).map_err(|e| {
                TestCaseError::Fail(format!("range proof failed: {e}").into())
            })?;
        }

        /// Inclusion proof serialization roundtrips correctly.
        #[test]
        fn proof_serialize_roundtrip(n in 1usize..64) {
            let mmr = build_mmr(n);
            let idx = mmr.get_leaf_index(0).unwrap();
            let proof = mmr.generate_proof(idx).unwrap();
            let bytes = proof.serialize().unwrap();
            let restored = InclusionProof::deserialize(&bytes).unwrap();
            // Verify the deserialized proof still works
            let data = 0u64.to_le_bytes();
            restored.verify(&data).map_err(|e| {
                TestCaseError::Fail(format!("roundtripped proof failed: {e}").into())
            })?;
        }

        /// Appending to an existing MMR preserves all prior proofs.
        #[test]
        fn append_preserves_prior_proofs(n in 1usize..64, extra in 1usize..32) {
            let store = Box::new(MemoryStore::new());
            let mmr = Mmr::new(store).unwrap();
            for i in 0..n {
                mmr.append(&(i as u64).to_le_bytes()).unwrap();
            }
            // Generate proof for first leaf before appending more
            let idx = mmr.get_leaf_index(0).unwrap();
            let leaf_hash = mmr.get(idx).unwrap().hash;

            // Append more leaves
            for i in n..(n + extra) {
                mmr.append(&(i as u64).to_le_bytes()).unwrap();
            }

            // The leaf hash at the same index is unchanged
            let after = mmr.get(idx).unwrap().hash;
            prop_assert_eq!(leaf_hash, after, "leaf hash must not change after appends");
        }
    }

    /// Convert leaf count to expected MMR size. This is the formula
    /// inverse of `leaf_count_from_size`: size = 2n - popcount(n).
    fn leaf_count_to_mmr_size(n: u64) -> u64 {
        2 * n - n.count_ones() as u64
    }
}
