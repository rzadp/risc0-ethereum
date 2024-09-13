use crate::ethereum_consensus::{
    phase0::operations::{
        Attestation, AttesterSlashing, Deposit, Eth1Data, ProposerSlashing, SignedVoluntaryExit,
    },
    primitives::{BlsSignature, Bytes32, Root, Slot, ValidatorIndex},
    ssz::prelude::*,
};

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlockBody<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
> {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: Bytes32,
    pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    pub attester_slashings:
        List<AttesterSlashing<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTER_SLASHINGS>,
    pub attestations: List<Attestation<MAX_VALIDATORS_PER_COMMITTEE>, MAX_ATTESTATIONS>,
    pub deposits: List<Deposit, MAX_DEPOSITS>,
    pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlock<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
> {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub slot: Slot,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body: BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
    >,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SignedBeaconBlock<
    const MAX_PROPOSER_SLASHINGS: usize,
    const MAX_VALIDATORS_PER_COMMITTEE: usize,
    const MAX_ATTESTER_SLASHINGS: usize,
    const MAX_ATTESTATIONS: usize,
    const MAX_DEPOSITS: usize,
    const MAX_VOLUNTARY_EXITS: usize,
> {
    pub message: BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_VALIDATORS_PER_COMMITTEE,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
    >,
    pub signature: BlsSignature,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct BeaconBlockHeader {
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub slot: Slot,
    #[serde(with = "crate::ethereum_consensus::serde::as_str")]
    pub proposer_index: ValidatorIndex,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

#[derive(
    Default, Debug, SimpleSerialize, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}
