// SPDX-License-Identifier: Apache-2.0

//! PoSME proof structures per draft-condrey-cfrg-posme CDDL.

use std::time::Duration;

use crate::block::Block;
use crate::error::PosmeError;
use crate::params::PosmeParams;

pub const PROOF_ALGORITHM_POSME: u16 = 30;
pub const PROOF_ALGORITHM_POSME_ENTANGLED: u16 = 31;
pub const INIT_WITNESS_COUNT: usize = 8;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosmeProof {
    pub params: PosmeParams,
    pub final_transcript: [u8; 32],
    pub root_chain_commitment: [u8; 32],
    pub root_0: [u8; 32],
    pub root_0_path: Vec<[u8; 32]>,
    pub init_witnesses: Vec<InitWitness>,
    pub challenged_steps: Vec<StepProof>,
    pub claimed_duration: Duration,
    pub proof_algorithm: u16,
    pub entanglement_points: Vec<(u32, [u8; 32])>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InitWitness {
    pub index: u32,
    pub block: Block,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StepProof {
    pub step_id: u32,
    pub cursor_in: [u8; 32],
    pub cursor_out: [u8; 32],
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
    pub root_chain_paths: (Vec<[u8; 32]>, Vec<[u8; 32]>),
    pub reads: Vec<ReadWitness>,
    pub write: WriteWitness,
    pub writers: Vec<WriterProof>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadWitness {
    pub address: u32,
    pub block: Block,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WriteWitness {
    pub address: u32,
    pub old_block: Block,
    pub new_block: Block,
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WriterProof {
    /// 0 = init (block was never written), 1 = step (recursive witness).
    pub proof_type: u8,
    pub writer_step_id: u32,
    pub step_witness: Option<Box<StepProof>>,
    pub init_merkle_path: Option<Vec<[u8; 32]>>,
}

pub const MAX_PROOF_NESTING_DEPTH: usize = 10;

impl PosmeProof {
    /// Validate structural bounds on a deserialized proof.
    pub fn validate_structure(&self) -> Result<(), PosmeError> {
        for sp in &self.challenged_steps {
            check_step_depth(sp, 0)?;
        }
        Ok(())
    }
}

fn check_step_depth(sp: &StepProof, depth: usize) -> Result<(), PosmeError> {
    if depth > MAX_PROOF_NESTING_DEPTH {
        return Err(PosmeError::verification_failed(format!(
            "proof nesting depth {} exceeds maximum {MAX_PROOF_NESTING_DEPTH}",
            depth
        )));
    }
    for w in &sp.writers {
        if let Some(ref witness) = w.step_witness {
            check_step_depth(witness, depth + 1)?;
        }
    }
    Ok(())
}
