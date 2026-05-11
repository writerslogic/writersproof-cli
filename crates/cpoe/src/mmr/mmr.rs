// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::mmr::errors::MmrError;
use crate::mmr::node::Node;
use crate::mmr::proof::{InclusionProof, ProofElement, RangeProof};
use crate::mmr::store::Store;
use crate::RwLockRecover;
use std::sync::RwLock;

pub struct Mmr {
    store: Box<dyn Store>,
    state: RwLock<MmrState>,
}

impl std::fmt::Debug for Mmr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mmr")
            .field("store", &"[dyn Store]")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct Peak {
    #[allow(dead_code)]
    index: u64,
    hash: [u8; 32],
}

#[derive(Debug)]
struct MmrState {
    size: u64,
    peaks: Vec<Peak>,
}

impl Mmr {
    pub fn new(store: Box<dyn Store>) -> Result<Self, MmrError> {
        let size = store.size()?;
        let peaks = if size == 0 {
            Vec::new()
        } else {
            let indices = find_peaks(size);
            let mut peaks = Vec::with_capacity(indices.len());
            for idx in indices {
                let node = store.get(idx)?;
                peaks.push(Peak {
                    index: idx,
                    hash: node.hash,
                });
            }
            peaks
        };
        Ok(Self {
            store,
            state: RwLock::new(MmrState { size, peaks }),
        })
    }

    pub fn append(&self, data: &[u8]) -> Result<u64, MmrError> {
        let mut state = self.state.write_recover();
        let leaf_index = state.size;
        let leaf = Node::new_leaf(leaf_index, data);
        self.store.append(&leaf)?;
        state.size += 1;

        loop {
            let peak_indices = find_peaks(state.size);
            if peak_indices.len() < 2 {
                let peaks_changed = state.peaks.len() != peak_indices.len()
                    || state
                        .peaks
                        .iter()
                        .zip(&peak_indices)
                        .any(|(p, &i)| p.index != i);
                if peaks_changed || state.size == 1 {
                    let mut new_peaks = Vec::with_capacity(peak_indices.len());
                    for idx in peak_indices {
                        // If it's the leaf we just appended, we have its hash.
                        // But wait, it might be an internal node.
                        let node = self.store.get(idx)?;
                        new_peaks.push(Peak {
                            index: idx,
                            hash: node.hash,
                        });
                    }
                    state.peaks = new_peaks;
                }
                break;
            }

            let last_idx = peak_indices[peak_indices.len() - 1];
            let prev_idx = peak_indices[peak_indices.len() - 2];

            // Optimization: check if we can merge the last two peaks.
            // We need their heights.
            let last = self.store.get(last_idx)?;
            let prev = self.store.get(prev_idx)?;

            if last.height != prev.height {
                // Cannot merge, update cached peaks and break.
                let mut new_peaks = Vec::with_capacity(peak_indices.len());
                for idx in peak_indices {
                    let node = self.store.get(idx)?;
                    new_peaks.push(Peak {
                        index: idx,
                        hash: node.hash,
                    });
                }
                state.peaks = new_peaks;
                break;
            }

            let new_node = Node::new_internal(state.size, last.height + 1, &prev, &last);
            self.store.append(&new_node)?;
            state.size += 1;
        }

        Ok(leaf_index)
    }

    pub fn get_peaks(&self) -> Result<Vec<[u8; 32]>, MmrError> {
        let state = self.state.read_recover();
        Ok(state.peaks.iter().map(|p| p.hash).collect())
    }

    pub fn get_root(&self) -> Result<[u8; 32], MmrError> {
        let state = self.state.read_recover();
        let peaks = &state.peaks;
        if peaks.is_empty() {
            return Err(MmrError::Empty);
        }
        if peaks.len() == 1 {
            return Ok(peaks[0].hash);
        }
        let mut root = peaks[peaks.len() - 1].hash;
        for i in (0..peaks.len() - 1).rev() {
            root = crate::mmr::node::hash_bag(peaks[i].hash, root);
        }
        Ok(root)
    }

    pub fn size(&self) -> u64 {
        self.state.read_recover().size
    }

    pub fn leaf_count(&self) -> u64 {
        leaf_count_from_size(self.state.read_recover().size)
    }

    /// Sync the underlying store to disk.
    pub fn sync(&self) -> Result<(), MmrError> {
        self.store.sync()
    }

    pub fn get(&self, index: u64) -> Result<Node, MmrError> {
        if index >= self.state.read_recover().size {
            return Err(MmrError::IndexOutOfRange);
        }
        self.store.get(index)
    }

    pub fn get_leaf_index(&self, leaf_ordinal: u64) -> Result<u64, MmrError> {
        let state = self.state.read_recover();
        if state.size == 0 {
            return Err(MmrError::Empty);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if leaf_ordinal >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }

        // The MMR index of the n-th leaf (0-indexed) is: 2n - popcount(n)
        // This is O(1) instead of the previous O(N) scan.
        // The subtraction is safe because popcount(n) <= 64 and 2n >= popcount(n).
        leaf_ordinal
            .checked_mul(2)
            .map(|v| v - leaf_ordinal.count_ones() as u64)
            .ok_or(MmrError::IndexOutOfRange)
    }

    pub fn get_leaf_indices(&self, start: u64, end: u64) -> Result<Vec<u64>, MmrError> {
        let state = self.state.read_recover();
        if start > end {
            return Err(MmrError::InvalidProof);
        }
        let leaf_count = leaf_count_from_size(state.size);
        if end >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }

        let mut indices = Vec::with_capacity((end - start + 1) as usize);
        for ordinal in start..=end {
            // I(n) = 2n - popcount(n)
            let idx = ordinal
                .checked_mul(2)
                .map(|v| v - ordinal.count_ones() as u64)
                .ok_or(MmrError::IndexOutOfRange)?;
            indices.push(idx);
        }
        Ok(indices)
    }

    pub fn generate_proof(&self, leaf_index: u64) -> Result<InclusionProof, MmrError> {
        let size = {
            let state = self.state.read_recover();
            if state.size == 0 {
                return Err(MmrError::Empty);
            }
            if leaf_index >= state.size {
                return Err(MmrError::IndexOutOfRange);
            }
            state.size
        };
        let node = self.store.get(leaf_index)?;
        if node.height != 0 {
            return Err(MmrError::InvalidProof);
        }
        let (path, peak_index) = self.generate_merkle_path(leaf_index, size)?;
        let peaks = self.get_peaks()?;
        let peak_indices = find_peaks(size);
        let mut peak_position = None;
        for (i, idx) in peak_indices.iter().enumerate() {
            if *idx == peak_index {
                peak_position = Some(i);
                break;
            }
        }
        let peak_position = peak_position.ok_or(MmrError::InvalidProof)?;
        let root = self.get_root()?;
        Ok(InclusionProof {
            leaf_index,
            leaf_hash: node.hash,
            merkle_path: path,
            peaks,
            peak_position,
            mmr_size: size,
            root,
        })
    }

    pub fn generate_range_proof(
        &self,
        start_leaf: u64,
        end_leaf: u64,
    ) -> Result<RangeProof, MmrError> {
        let size = {
            let state = self.state.read_recover();
            if state.size == 0 {
                return Err(MmrError::Empty);
            }
            state.size
        };
        if start_leaf > end_leaf {
            return Err(MmrError::InvalidProof);
        }
        let leaf_count = leaf_count_from_size(size);
        if end_leaf >= leaf_count {
            return Err(MmrError::IndexOutOfRange);
        }
        let leaf_indices = self.get_leaf_indices(start_leaf, end_leaf)?;
        let mut leaf_hashes = Vec::with_capacity(leaf_indices.len());
        for idx in &leaf_indices {
            leaf_hashes.push(self.store.get(*idx)?.hash);
        }
        let (sibling_path, peak_index) = self.generate_range_merkle_path(&leaf_indices, size)?;
        let peaks = self.get_peaks()?;
        let peak_indices = find_peaks(size);
        let mut peak_position = None;
        for (i, idx) in peak_indices.iter().enumerate() {
            if *idx == peak_index {
                peak_position = Some(i);
                break;
            }
        }
        let peak_position = peak_position.ok_or(MmrError::InvalidProof)?;
        let root = self.get_root()?;
        Ok(RangeProof {
            start_leaf,
            end_leaf,
            leaf_indices,
            leaf_hashes,
            sibling_path,
            peaks,
            peak_position,
            mmr_size: size,
            root,
        })
    }

    fn generate_merkle_path(
        &self,
        leaf_index: u64,
        size: u64,
    ) -> Result<(Vec<ProofElement>, u64), MmrError> {
        let mut path = Vec::new();
        let mut pos = leaf_index;
        let node = self.store.get(pos)?;
        let mut height = node.height;

        loop {
            let (sibling_pos, parent_pos, is_right_child, found) =
                self.find_family(pos, height, size)?;
            if !found {
                return Ok((path, pos));
            }
            let sibling = self.store.get(sibling_pos)?;
            path.push(ProofElement {
                hash: sibling.hash,
                is_left: is_right_child,
            });
            pos = parent_pos;
            height += 1;
        }
    }

    fn find_family(
        &self,
        pos: u64,
        height: u8,
        size: u64,
    ) -> Result<(u64, u64, bool, bool), MmrError> {
        if height >= 63 {
            return Ok((0, 0, false, false));
        }
        let offset = 1u64 << (height + 1);

        let left_parent = match pos.checked_add(offset) {
            Some(v) => v,
            None => return Ok((0, 0, false, false)),
        };
        let right_sibling = left_parent.saturating_sub(1);
        if right_sibling < size && right_sibling != pos {
            let right_node = self.store.get(right_sibling)?;
            if right_node.height == height && left_parent < size {
                let parent = self.store.get(left_parent)?;
                if parent.height == height + 1 {
                    return Ok((right_sibling, left_parent, false, true));
                }
            }
        }

        let right_parent = pos + 1;
        if offset <= pos + 1 {
            let left_sibling = right_parent - offset;
            if left_sibling < size && left_sibling != pos {
                let left_node = self.store.get(left_sibling)?;
                if left_node.height == height && right_parent < size {
                    let parent = self.store.get(right_parent)?;
                    if parent.height == height + 1 {
                        return Ok((left_sibling, right_parent, true, true));
                    }
                }
            }
        }

        Ok((0, 0, false, false))
    }

    fn generate_range_merkle_path(
        &self,
        leaf_indices: &[u64],
        size: u64,
    ) -> Result<(Vec<ProofElement>, u64), MmrError> {
        use std::collections::HashSet;
        if leaf_indices.is_empty() {
            return Err(MmrError::InvalidProof);
        }
        let mut covered: HashSet<u64> = leaf_indices.iter().copied().collect();
        let mut path: Vec<ProofElement> = Vec::new();
        let mut current_level: Vec<u64> = leaf_indices.to_vec();
        let mut height: u32 = 0;
        let mut peak_index = 0u64;

        while !current_level.is_empty() {
            if height >= 64 {
                return Err(MmrError::InvalidProof);
            }
            current_level.sort_unstable();
            let mut next_level = Vec::new();
            let mut processed_parents: HashSet<u64> = HashSet::new();
            for pos in &current_level {
                let (sibling_pos, parent_pos, is_right_child, found) =
                    self.find_family(*pos, height as u8, size)?;
                if !found {
                    peak_index = *pos;
                    continue;
                }
                if processed_parents.contains(&parent_pos) {
                    continue;
                }
                processed_parents.insert(parent_pos);
                if !covered.contains(&sibling_pos) {
                    let sibling = self.store.get(sibling_pos)?;
                    path.push(ProofElement {
                        hash: sibling.hash,
                        is_left: is_right_child,
                    });
                }
                covered.insert(parent_pos);
                next_level.push(parent_pos);
            }
            current_level = next_level;
            height += 1;
        }

        Ok((path, peak_index))
    }
}

pub fn find_peaks(mut size: u64) -> Vec<u64> {
    let mut peaks = Vec::new();
    let mut offset = 0;
    // Cap iterations at 64 (maximum number of peaks for a u64-sized MMR).
    let mut iterations = 0u32;
    while size > 0 && iterations < 64 {
        let h = highest_peak(size);
        let tree_size = (1u64 << (h + 1)) - 1;
        if tree_size > size {
            break;
        }
        peaks.push(offset + tree_size - 1);
        offset += tree_size;
        size -= tree_size;
        iterations += 1;
    }
    peaks
}

pub fn highest_peak(size: u64) -> u8 {
    if size == 0 {
        return 0;
    }
    (63 - (size + 1).leading_zeros() as u8).saturating_sub(1)
}

pub fn leaf_count_from_size(mut size: u64) -> u64 {
    let mut count = 0u64;
    while size > 0 {
        let h = highest_peak(size);
        let tree_size = (1u64 << (h + 1)) - 1;
        count += 1u64 << h;
        size -= tree_size;
    }
    count
}

#[cfg(test)]
#[path = "mmr_tests.rs"]
mod mmr_tests;
