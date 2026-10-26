//! Send Payjoin
//!
//! This module contains types and methods used to implement sending via Payjoin.
//!
//! For most use cases, we recommended enabling the `v2` feature, as it is
//! backwards compatible and provides the most convenient experience for users and implementers.
//! To use version 2, refer to `send::v2` module documentation.
//!
//! If you specifically need to use
//! version 1, refer to the `send::v1` module documentation after enabling the `v1` feature.

use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxIn, TxOut, Weight};
pub use error::{BuildSenderError, ResponseError, ValidationError, WellKnownError};
pub(crate) use error::{InternalBuildSenderError, InternalProposalError, InternalValidationError};

pub use crate::core::error_codes::ErrorCode;
use crate::core::Url;
use crate::output_substitution::OutputSubstitution;
use crate::psbt::{AddressTypeError, PsbtExt, NON_WITNESS_INPUT_WEIGHT};
use crate::Version;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

type InternalResult<T> = Result<T, InternalProposalError>;

/// A builder to construct the properties of a `PsbtContext`.
#[derive(Clone)]
pub(crate) struct PsbtContextBuilder {
    pub(crate) psbt: Psbt,
    pub(crate) payee: ScriptBuf,
    pub(crate) amount: Option<bitcoin::Amount>,
    pub(crate) fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    /// Decreases the fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub(crate) clamp_fee_contribution: bool,
    pub(crate) min_fee_rate: FeeRate,
}

impl PsbtContextBuilder {
    /// Prepare the context from which to make Sender requests
    ///
    /// Call [`PsbtContextBuilder::build_recommended()`] or other `build` methods
    /// to create a [`PsbtContext`]
    pub fn new(psbt: Psbt, payee: ScriptBuf, amount: Option<bitcoin::Amount>) -> Self {
        Self {
            psbt,
            payee,
            amount,
            // Sender's optional parameters
            fee_contribution: None,
            clamp_fee_contribution: false,
            min_fee_rate: FeeRate::ZERO,
        }
    }

    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(
        self,
        min_fee_rate: FeeRate,
        output_substitution: OutputSubstitution,
    ) -> Result<PsbtContext, BuildSenderError> {
        // TODO support optional batched payout scripts. This would require a change to
        // build() which now checks for a single payee.
        let mut payout_scripts = std::iter::once(self.payee.clone());

        // Check if the PSBT is a sweep transaction with only one output that's a payout script and no change
        if self.psbt.unsigned_tx.output.len() == 1
            && payout_scripts.all(|script| script == self.psbt.unsigned_tx.output[0].script_pubkey)
        {
            return self.build_non_incentivizing(min_fee_rate, output_substitution);
        }

        if let Some((additional_fee_index, fee_available)) = self
            .psbt
            .unsigned_tx
            .output
            .clone()
            .into_iter()
            .enumerate()
            .find(|(_, txo)| payout_scripts.all(|script| script != txo.script_pubkey))
            .map(|(i, txo)| (i, txo.value))
        {
            let mut input_pairs = self.psbt.input_pairs();
            let first_input_pair = input_pairs.next().ok_or(InternalBuildSenderError::NoInputs)?;
            let mut input_weight = first_input_pair
                .expected_input_weight()
                .map_err(InternalBuildSenderError::InputWeight)?;
            for input_pair in input_pairs {
                // use cheapest default if mixed input types
                if input_pair.address_type()? != first_input_pair.address_type()? {
                    input_weight =
                        bitcoin::transaction::InputWeightPrediction::P2TR_KEY_NON_DEFAULT_SIGHASH
                            .weight()
                            + NON_WITNESS_INPUT_WEIGHT;
                    break;
                }
            }

            let recommended_additional_fee = min_fee_rate
                .checked_mul_by_weight(input_weight)
                .ok_or(InternalBuildSenderError::AddressType(AddressTypeError::FeeRateOverflow))?;
            if fee_available < recommended_additional_fee {
                tracing::warn!("Insufficient funds to maintain specified minimum feerate.");
                return self.build_with_additional_fee(
                    fee_available,
                    Some(additional_fee_index),
                    min_fee_rate,
                    true,
                    output_substitution,
                );
            }
            return self.build_with_additional_fee(
                recommended_additional_fee,
                Some(additional_fee_index),
                min_fee_rate,
                false,
                output_substitution,
            );
        }
        self.build_non_incentivizing(min_fee_rate, output_substitution)
    }

    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. If `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    ///
    /// `clamp_fee_contribution` decreases fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub fn build_with_additional_fee(
        mut self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
        output_substitution: OutputSubstitution,
    ) -> Result<PsbtContext, BuildSenderError> {
        self.fee_contribution = Some((max_fee_contribution, change_index));
        self.clamp_fee_contribution = clamp_fee_contribution;
        self.min_fee_rate = min_fee_rate;
        self.build(output_substitution)
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        mut self,
        min_fee_rate: FeeRate,
        output_substitution: OutputSubstitution,
    ) -> Result<PsbtContext, BuildSenderError> {
        // since this is a builder, these should already be cleared
        // but we'll reset them to be sure
        self.fee_contribution = None;
        self.clamp_fee_contribution = false;
        self.min_fee_rate = min_fee_rate;
        self.build(output_substitution)
    }

    fn build(
        self,
        output_substitution: OutputSubstitution,
    ) -> Result<PsbtContext, BuildSenderError> {
        let psbt =
            self.psbt.validate().map_err(InternalBuildSenderError::InconsistentOriginalPsbt)?;
        psbt.validate_input_utxos().map_err(InternalBuildSenderError::InvalidOriginalInput)?;

        // The Original PSBT reaches the receiver already signed, to be held as
        // a broadcastable fallback. A signature that does not commit to every
        // input and output leaves that transaction malleable by whoever holds
        // it, so refuse to build a context around one.
        //
        // TODO: BIP-78 does not mention sighash types at all, neither for the
        // Original PSBT nor in the sender's payjoin proposal checklist. The
        // spec needs an update stating that a sender signs with SIGHASH_ALL
        // and rejects anything else on its own inputs.
        for input in &psbt.inputs {
            if let Some(sighash_type) = input.sighash_type {
                ensure(
                    commits_to_all_inputs_and_outputs(sighash_type),
                    InternalBuildSenderError::OriginalTxinNonAllSighashType,
                )?;
            }
        }

        check_single_payee(&psbt, &self.payee, self.amount)?;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &self.payee,
            self.fee_contribution,
            self.clamp_fee_contribution,
        )?;

        Ok(PsbtContext {
            original_psbt: psbt,
            output_substitution,
            fee_contribution,
            min_fee_rate: self.min_fee_rate,
            payee: self.payee,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "v2", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AdditionalFeeContribution {
    max_amount: Amount,
    vout: usize,
}

/// Data required to validate the response against the original PSBT.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "v2", derive(serde::Serialize, serde::Deserialize, PartialEq, Eq))]
pub struct PsbtContext {
    original_psbt: Psbt,
    output_substitution: OutputSubstitution,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
    payee: ScriptBuf,
}

macro_rules! check_eq {
    ($proposed:expr, $original:expr, $error:ident) => {
        match ($proposed, $original) {
            (proposed, original) if proposed != original =>
                return Err(InternalProposalError::$error { proposed, original }),
            _ => (),
        }
    };
}

fn ensure<T>(condition: bool, error: T) -> Result<(), T> {
    if !condition {
        return Err(error);
    }
    Ok(())
}

/// Whether a PSBT input's declared sighash type commits to every input and
/// output of the transaction.
///
/// Only `SIGHASH_ALL` (ECDSA) and `SIGHASHDEFAULT`/`SIGHASH_ALL` (Taproot)
/// commit to all inputs and outputs. Any other type (`NONE`, `SINGLE`, or an
/// `ANYONECANPAY` variant) leaves the signed transaction malleable, so the
/// sender must never sign one of its own inputs with such a type.
fn commits_to_all_inputs_and_outputs(sighash_type: PsbtSighashType) -> bool {
    // Taproot reuses the ECDSA sighash encodings and adds SIGHASHDEFAULT at
    // 0x00, so parsing as taproot recognizes both signature types.
    matches!(sighash_type.taproot_hash_ty(), Ok(TapSighashType::Default | TapSighashType::All))
}

/// The absolute fee of a PSBT.
///
/// Spent values come from [`InternalInputPair::previous_txout`], the same
/// source every other check reads, rather than from [`Psbt::fee`], which
/// prefers an unauthenticated `witness_utxo` over the `non_witness_utxo`.
///
/// [`InternalInputPair::previous_txout`]: crate::psbt::InternalInputPair::previous_txout
fn absolute_fee(psbt: &Psbt) -> InternalResult<Amount> {
    let input_value = psbt.input_pairs().try_fold(Amount::ZERO, |acc, input_pair| {
        let value = input_pair.previous_txout().map_err(InternalProposalError::PrevTxOut)?.value;
        acc.checked_add(value).ok_or(InternalProposalError::FeeCalculationOverflow)
    })?;
    let output_value = psbt.unsigned_tx.output.iter().try_fold(Amount::ZERO, |acc, txout| {
        acc.checked_add(txout.value).ok_or(InternalProposalError::FeeCalculationOverflow)
    })?;
    input_value
        .checked_sub(output_value)
        .ok_or(InternalProposalError::Psbt(bitcoin::psbt::Error::NegativeFee))
}

/// Whether `originals` appear among `proposed` in the same relative order.
///
/// BIP 78 forbids the receiver from shuffling: its additional inputs "must be inserted at a
/// random index", so the sender's inputs must survive as an ordered subsequence of the
/// proposal's.
fn is_ordered_subsequence<'a>(
    originals: impl IntoIterator<Item = &'a TxIn>,
    proposed: impl IntoIterator<Item = &'a TxIn>,
) -> bool {
    let mut proposed = proposed.into_iter();
    originals
        .into_iter()
        .all(|original| proposed.any(|p| p.previous_output == original.previous_output))
}

impl PsbtContext {
    fn process_proposal(self, mut proposal: Psbt) -> InternalResult<Psbt> {
        self.basic_checks(&proposal)?;
        self.check_inputs(&proposal, true)?;
        let contributed_fee = self.check_outputs(&proposal)?;
        self.restore_original_utxos(&mut proposal)?;
        self.restore_original_outputs(&mut proposal)?;
        self.check_receiver_input_signatures(&proposal)?;
        self.check_fees(&proposal, contributed_fee)?;
        Ok(proposal)
    }

    fn check_fees(&self, proposal: &Psbt, contributed_fee: Amount) -> InternalResult<()> {
        let proposed_fee = absolute_fee(proposal)?;
        let original_fee = absolute_fee(&self.original_psbt)?;
        ensure(original_fee <= proposed_fee, InternalProposalError::AbsoluteFeeDecreased)?;
        ensure(
            contributed_fee <= proposed_fee - original_fee,
            InternalProposalError::PayeeTookContributedFee,
        )?;
        let original_weight = self.original_psbt.clone().extract_tx_unchecked_fee_rate().weight();
        let original_fee_rate = original_fee / original_weight;
        let original_spks = self
            .original_psbt
            .input_pairs()
            .map(|input_pair| {
                input_pair
                    .previous_txout()
                    .map_err(InternalProposalError::PrevTxOut)
                    .map(|txout| txout.script_pubkey.clone())
            })
            .collect::<InternalResult<Vec<ScriptBuf>>>()?;
        let additional_input_weight = proposal.input_pairs().try_fold(
            Weight::ZERO,
            |acc, input_pair| -> InternalResult<Weight> {
                let spk = &input_pair
                    .previous_txout()
                    .map_err(InternalProposalError::PrevTxOut)?
                    .script_pubkey;
                if original_spks.contains(spk) {
                    Ok(acc)
                } else {
                    let weight = input_pair
                        .expected_input_weight()
                        .map_err(InternalProposalError::InputWeight)?;
                    Ok(acc + weight)
                }
            },
        )?;
        ensure(
            contributed_fee <= original_fee_rate * additional_input_weight,
            InternalProposalError::FeeContributionPaysOutputSizeIncrease,
        )?;
        if self.min_fee_rate > FeeRate::ZERO {
            let proposed_weight = proposal.clone().extract_tx_unchecked_fee_rate().weight();
            let proposed_fee_rate = proposed_fee
                .div_by_weight_floor(proposed_weight)
                .ok_or(InternalProposalError::FeeCalculationOverflow)?;
            ensure(
                proposed_fee_rate >= self.min_fee_rate,
                InternalProposalError::FeeRateBelowMinimum,
            )?;
        }
        Ok(())
    }

    /// Check that the version and lock time are the same as in the original PSBT.
    fn basic_checks(&self, proposal: &Psbt) -> InternalResult<()> {
        check_eq!(
            proposal.unsigned_tx.version,
            self.original_psbt.unsigned_tx.version,
            VersionsDontMatch
        );
        check_eq!(
            proposal.unsigned_tx.lock_time,
            self.original_psbt.unsigned_tx.lock_time,
            LockTimesDontMatch
        );
        Ok(())
    }

    fn check_inputs(
        &self,
        proposal: &Psbt,
        ensure_receiver_input_finalized: bool,
    ) -> InternalResult<()> {
        ensure(
            is_ordered_subsequence(
                &self.original_psbt.unsigned_tx.input,
                &proposal.unsigned_tx.input,
            ),
            InternalProposalError::MissingOrShuffledInputs,
        )?;

        let mut original_inputs = self.original_psbt.input_pairs().peekable();

        for proposed in proposal.input_pairs() {
            ensure(
                proposed.psbtin.bip32_derivation.is_empty(),
                InternalProposalError::TxInContainsKeyPaths,
            )?;
            ensure(
                proposed.psbtin.partial_sigs.is_empty(),
                InternalProposalError::ContainsPartialSigs,
            )?;
            match original_inputs.peek() {
                // our (sender)
                Some(original)
                    if proposed.txin.previous_output == original.txin.previous_output =>
                {
                    check_eq!(
                        proposed.txin.sequence,
                        original.txin.sequence,
                        SenderTxinSequenceChanged
                    );
                    ensure(
                        proposed.psbtin.final_script_sig.is_none(),
                        InternalProposalError::SenderTxinContainsFinalScriptSig,
                    )?;
                    ensure(
                        proposed.psbtin.final_script_witness.is_none(),
                        InternalProposalError::SenderTxinContainsFinalScriptWitness,
                    )?;
                    // Refuse to sign our own inputs with any sighash type that
                    // does not commit to every input and output.
                    if let Some(sighash_type) = proposed.psbtin.sighash_type {
                        ensure(
                            commits_to_all_inputs_and_outputs(sighash_type),
                            InternalProposalError::SenderTxinNonAllSighashType,
                        )?;
                    }
                    original_inputs.next();
                }
                // theirs (receiver)
                None | Some(_) => {
                    let original = self
                        .original_psbt
                        .input_pairs()
                        .next()
                        .ok_or(InternalProposalError::NoInputs)?;
                    if ensure_receiver_input_finalized {
                        // Verify the PSBT input is finalized
                        ensure(
                            proposed.psbtin.final_script_sig.is_some()
                                || proposed.psbtin.final_script_witness.is_some(),
                            InternalProposalError::ReceiverTxinNotFinalized,
                        )?;
                    }
                    // Verify that non_witness_utxo or witness_utxo are filled in.
                    ensure(
                        proposed.psbtin.witness_utxo.is_some()
                            || proposed.psbtin.non_witness_utxo.is_some(),
                        InternalProposalError::ReceiverTxinMissingUtxoInfo,
                    )?;
                    // Verify that the UTXO fields agree with the outpoint and
                    // with each other, so that every later read of the spent
                    // output sees the same value.
                    proposed
                        .validate_utxo()
                        .map_err(InternalProposalError::ReceiverTxinInvalidUtxo)?;
                    ensure(
                        proposed.txin.sequence == original.txin.sequence,
                        InternalProposalError::MixedSequence,
                    )?;
                }
            }
        }
        ensure(original_inputs.peek().is_none(), InternalProposalError::MissingOrShuffledInputs)?;
        Ok(())
    }

    /// Check that each receiver input proves the spent output it claims.
    ///
    /// A `non_witness_utxo` is committed to by the outpoint. A bare
    /// `witness_utxo` is committed to only by the receiver's signature, so
    /// verify that signature against it. Taproot signatures without
    /// `SIGHASH_ANYONECANPAY` commit to every spent output, so this must run
    /// after `restore_original_utxos`.
    fn check_receiver_input_signatures(&self, proposal: &Psbt) -> InternalResult<()> {
        let prevouts = proposal
            .input_pairs()
            .map(|input_pair| {
                input_pair.previous_txout().cloned().map_err(InternalProposalError::PrevTxOut)
            })
            .collect::<InternalResult<Vec<TxOut>>>()?;
        let mut sighash_cache = SighashCache::new(&proposal.unsigned_tx);
        let mut original_inputs = self.original_psbt.input_pairs().peekable();

        for (index, proposed) in proposal.input_pairs().enumerate() {
            match original_inputs.peek() {
                // our (sender)
                Some(original)
                    if proposed.txin.previous_output == original.txin.previous_output =>
                {
                    original_inputs.next();
                }
                // theirs (receiver)
                None | Some(_) =>
                    if proposed.psbtin.non_witness_utxo.is_some() {
                        proposed
                            .validate_utxo()
                            .map_err(InternalProposalError::ReceiverTxinInvalidUtxo)?;
                    } else {
                        proposed
                            .verify_signature(&mut sighash_cache, index, &prevouts)
                            .map_err(InternalProposalError::ReceiverTxinUnverifiedUtxo)?;
                    },
            }
        }
        Ok(())
    }

    /// Restore Original PSBT utxos that the receiver stripped.
    /// The BIP78 spec requires utxo information to be removed, but many wallets
    /// require it to be present to sign.
    fn restore_original_utxos(&self, proposal: &mut Psbt) -> InternalResult<()> {
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let proposal_inputs =
            proposal.unsigned_tx.input.iter().zip(&mut proposal.inputs).peekable();

        for (proposed_txin, proposed_psbtin) in proposal_inputs {
            if let Some(original) = original_inputs.peek() {
                if proposed_txin.previous_output == original.txin.previous_output {
                    proposed_psbtin.non_witness_utxo = original.psbtin.non_witness_utxo.clone();
                    proposed_psbtin.witness_utxo = original.psbtin.witness_utxo.clone();
                    proposed_psbtin.bip32_derivation = original.psbtin.bip32_derivation.clone();
                    proposed_psbtin.tap_internal_key = original.psbtin.tap_internal_key;
                    proposed_psbtin.tap_key_origins = original.psbtin.tap_key_origins.clone();
                    proposed_psbtin.witness_script = original.psbtin.witness_script.clone();
                    original_inputs.next();
                }
            }
        }
        Ok(())
    }

    /// Restore Original PSBT outputs that were stripped before sending to the receiver.
    /// BIP78 spec requires output fields to be removed, but many wallets
    /// require output fields to be present in order to validate change and payment outputs.
    fn restore_original_outputs(&self, proposal: &mut Psbt) -> InternalResult<()> {
        let mut original_outputs = self
            .original_psbt
            .unsigned_tx
            .output
            .iter()
            .zip(self.original_psbt.outputs.iter())
            .peekable();
        let proposal_outputs = proposal.unsigned_tx.output.iter().zip(proposal.outputs.iter_mut());

        for (proposed_txout, proposed_psbtout) in proposal_outputs {
            if let Some((original_txout, original_psbtout)) = original_outputs.peek() {
                if proposed_txout == *original_txout {
                    *proposed_psbtout = (*original_psbtout).clone();
                    original_outputs.next();
                }
            }
        }

        Ok(())
    }

    fn check_outputs(&self, proposal: &Psbt) -> InternalResult<Amount> {
        let mut original_outputs =
            self.original_psbt.unsigned_tx.output.iter().enumerate().peekable();
        let mut contributed_fee = Amount::ZERO;

        for (proposed_txout, proposed_psbtout) in
            proposal.unsigned_tx.output.iter().zip(&proposal.outputs)
        {
            ensure(
                proposed_psbtout.bip32_derivation.is_empty(),
                InternalProposalError::TxOutContainsKeyPaths,
            )?;
            match (original_outputs.peek(), self.fee_contribution) {
                // fee output
                (
                    Some((original_output_index, original_output)),
                    Some(AdditionalFeeContribution {
                        max_amount: max_fee_contrib,
                        vout: fee_contrib_idx,
                    }),
                ) if proposed_txout.script_pubkey == original_output.script_pubkey
                    && *original_output_index == fee_contrib_idx =>
                {
                    if proposed_txout.value < original_output.value {
                        contributed_fee = original_output.value - proposed_txout.value;
                        ensure(
                            contributed_fee <= max_fee_contrib,
                            InternalProposalError::FeeContributionExceedsMaximum,
                        )?;
                        // The remaining fee checks are done in later in `check_fees`
                    }
                    original_outputs.next();
                }
                // payee output
                (Some((_original_output_index, original_output)), _)
                    if original_output.script_pubkey == self.payee =>
                {
                    ensure(
                        self.output_substitution == OutputSubstitution::Enabled
                            || (proposed_txout.script_pubkey == original_output.script_pubkey
                                && proposed_txout.value >= original_output.value),
                        InternalProposalError::DisallowedOutputSubstitution,
                    )?;
                    original_outputs.next();
                }
                // our output
                (Some((_original_output_index, original_output)), _)
                    if proposed_txout.script_pubkey == original_output.script_pubkey =>
                {
                    ensure(
                        proposed_txout.value >= original_output.value,
                        InternalProposalError::OutputValueDecreased,
                    )?;
                    original_outputs.next();
                }
                // additional output
                _ => (),
            }
        }

        ensure(original_outputs.peek().is_none(), InternalProposalError::MissingOrShuffledOutputs)?;
        Ok(contributed_fee)
    }
}

/// Ensure that the payee's output scriptPubKey appears in the list of outputs exactly once,
/// and that the payee's output amount matches the requested amount.
fn check_single_payee(
    psbt: &Psbt,
    script_pubkey: &Script,
    amount: Option<bitcoin::Amount>,
) -> Result<(), InternalBuildSenderError> {
    let mut payee_found = false;
    for output in &psbt.unsigned_tx.output {
        if output.script_pubkey == *script_pubkey {
            if let Some(amount) = amount {
                if output.value != amount {
                    return Err(InternalBuildSenderError::PayeeValueNotEqual);
                }
            }
            if payee_found {
                return Err(InternalBuildSenderError::MultiplePayeeOutputs);
            }
            payee_found = true;
        }
    }
    if payee_found {
        Ok(())
    } else {
        Err(InternalBuildSenderError::MissingPayeeOutput)
    }
}

fn clear_unneeded_fields(psbt: &mut Psbt) {
    psbt.xpub_mut().clear();
    psbt.proprietary_mut().clear();
    psbt.unknown_mut().clear();
    for input in psbt.inputs_mut() {
        input.bip32_derivation.clear();
        input.tap_internal_key = None;
        input.tap_key_origins.clear();
        input.tap_key_sig = None;
        input.tap_merkle_root = None;
        input.tap_script_sigs.clear();
        input.proprietary.clear();
        input.unknown.clear();
    }
    for output in psbt.outputs_mut() {
        output.bip32_derivation.clear();
        output.tap_internal_key = None;
        output.tap_key_origins.clear();
        output.proprietary.clear();
        output.unknown.clear();
    }
}

/// Ensure that an additional fee output is sufficient to pay for the specified additional fee
fn check_fee_output_amount(
    output: &TxOut,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<bitcoin::Amount, InternalBuildSenderError> {
    match output.value.checked_sub(fee) {
        Some(_) => Ok(fee),
        None if clamp_fee_contribution => Ok(output.value),
        None => Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution),
    }
}

/// Find the sender's change output index by eliminating the payee's output as a candidate.
fn find_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<Option<AdditionalFeeContribution>, InternalBuildSenderError> {
    match (psbt.unsigned_tx.output.len(), clamp_fee_contribution) {
        (0, _) => return Err(InternalBuildSenderError::NoOutputs),
        (1, false) if psbt.unsigned_tx.output[0].script_pubkey == *payee =>
            return Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution),
        (1, true) if psbt.unsigned_tx.output[0].script_pubkey == *payee => return Ok(None),
        (1, _) => return Err(InternalBuildSenderError::MissingPayeeOutput),
        (2, _) => (),
        _ => return Err(InternalBuildSenderError::AmbiguousChangeOutput),
    }
    let (index, output) = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey != *payee)
        .ok_or(InternalBuildSenderError::MultiplePayeeOutputs)?;

    Ok(Some(AdditionalFeeContribution {
        max_amount: check_fee_output_amount(output, fee, clamp_fee_contribution)?,
        vout: index,
    }))
}

/// Check that the change output index is not out of bounds
/// and that the additional fee contribution is not less than specified.
fn check_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    index: usize,
    clamp_fee_contribution: bool,
) -> Result<AdditionalFeeContribution, InternalBuildSenderError> {
    let output = psbt
        .unsigned_tx
        .output
        .get(index)
        .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)?;
    if output.script_pubkey == *payee {
        return Err(InternalBuildSenderError::ChangeIndexPointsAtPayee);
    }
    Ok(AdditionalFeeContribution {
        max_amount: check_fee_output_amount(output, fee, clamp_fee_contribution)?,
        vout: index,
    })
}

fn determine_fee_contribution(
    psbt: &Psbt,
    payee: &Script,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    clamp_fee_contribution: bool,
) -> Result<Option<AdditionalFeeContribution>, InternalBuildSenderError> {
    let contribution = match fee_contribution {
        Some((fee, None)) => find_change_index(psbt, payee, fee, clamp_fee_contribution)?,
        Some((fee, Some(index))) =>
            Some(check_change_index(psbt, payee, fee, index, clamp_fee_contribution)?),
        None => None,
    };
    // A clamped zero contribution offers the receiver nothing and would only
    // advertise a fee output the receiver must leave untouched.
    Ok(contribution.filter(|contribution| contribution.max_amount > bitcoin::Amount::ZERO))
}

fn serialize_url(
    endpoint: Url,
    output_substitution: OutputSubstitution,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
    version: Version,
) -> Url {
    let mut url = endpoint;
    url.query_pairs_mut().append_pair("v", &version.to_string());
    if output_substitution == OutputSubstitution::Disabled {
        url.query_pairs_mut().append_pair("disableoutputsubstitution", "true");
    }
    if let Some(AdditionalFeeContribution { max_amount, vout }) = fee_contribution {
        url.query_pairs_mut()
            .append_pair("additionalfeeoutputindex", &vout.to_string())
            .append_pair("maxadditionalfeecontribution", &max_amount.to_sat().to_string());
    }
    if min_fee_rate > FeeRate::ZERO {
        // TODO serialize in rust-bitcoin <https://github.com/rust-bitcoin/rust-bitcoin/pull/1787/files#diff-c2ea40075e93ccd068673873166cfa3312ec7439d6bc5a4cbc03e972c7e045c4>
        let float_fee_rate = min_fee_rate.to_sat_per_kwu() as f32 / 250.0_f32;
        url.query_pairs_mut().append_pair("minfeerate", &float_fee_rate.to_string());
    }
    url
}

#[cfg(test)]
mod test {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::ecdsa::Signature;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::FromHex;
    use bitcoin::key::TapTweak;
    use bitcoin::script::PushBytes;
    use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, SECP256K1};
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::{taproot, Amount, FeeRate, OutPoint, Script, ScriptBuf, Sequence, Txid, Witness};
    use payjoin_test_utils::{
        BoxError, ADDITIONAL_FEE_OUTPUT_INDEX, MAX_ADDITIONAL_FEE_CONTRIBUTION,
        PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL, PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO,
    };

    use super::*;
    use crate::core::Url;
    use crate::output_substitution::OutputSubstitution;
    use crate::psbt::{InputSignatureError, InternalPsbtInputError, PsbtExt};
    use crate::send::{AdditionalFeeContribution, InternalBuildSenderError, InternalProposalError};

    /// Creates a PSBT context from the original PSBT test vector from BIP-78
    pub(crate) fn create_psbt_context() -> Result<super::PsbtContext, BoxError> {
        let payee = PARSED_ORIGINAL_PSBT.unsigned_tx.output[1].script_pubkey.clone();
        Ok(super::PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            output_substitution: OutputSubstitution::Enabled,
            fee_contribution: Some(AdditionalFeeContribution {
                max_amount: bitcoin::Amount::from_sat(182),
                vout: 0,
            }),
            min_fee_rate: FeeRate::ZERO,
            payee,
        })
    }

    #[test]
    fn ordered_subsequence_requires_original_order() {
        let txin = |vout| TxIn {
            previous_output: OutPoint::new(Txid::all_zeros(), vout),
            ..Default::default()
        };
        let originals = vec![txin(0), txin(1)];

        assert!(is_ordered_subsequence(&originals, &vec![txin(0), txin(1)]));
        // Receiver inputs may be inserted before, between, and after the sender's.
        assert!(is_ordered_subsequence(&originals, &vec![txin(0), txin(9), txin(1)]));
        assert!(is_ordered_subsequence(
            &originals,
            &vec![txin(3), txin(0), txin(9), txin(1), txin(3)]
        ));
        assert!(!is_ordered_subsequence(
            &originals,
            &vec![txin(3), txin(1), txin(9), txin(0), txin(3)]
        ));
        assert!(!is_ordered_subsequence(&originals, &vec![txin(1), txin(0)]));
        assert!(!is_ordered_subsequence(&originals, &vec![txin(0)]));
    }

    #[test]
    fn test_restore_original_utxos() -> Result<(), BoxError> {
        let mut original_psbt = PARSED_ORIGINAL_PSBT.clone();
        let mut payjoin_proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let (_, pk) = SECP256K1.generate_keypair(&mut bitcoin::key::rand::thread_rng());
        let x_only = pk.x_only_public_key().0;
        // Fill out dummy data in the original PSBT so we can restore it
        let _ = original_psbt.inputs[0].tap_internal_key.insert(x_only);
        let _ = original_psbt.outputs[0].tap_internal_key.insert(x_only);
        original_psbt.inputs[0]
            .bip32_derivation
            .insert(pk, (Fingerprint::default(), DerivationPath::default()));
        original_psbt.inputs[0]
            .tap_key_origins
            .insert(x_only, (vec![], (Fingerprint::default(), DerivationPath::default())));
        original_psbt.inputs[0].witness_script = Some(payee.clone());
        let prev_txout = TxOut { value: Amount::ONE_BTC, script_pubkey: payee.clone() };
        original_psbt.inputs[0].witness_utxo = Some(prev_txout.clone());
        let psbt_ctx = PsbtContextBuilder::new(original_psbt, payee.clone(), None)
            .build(OutputSubstitution::Disabled)?;
        clear_unneeded_fields(&mut payjoin_proposal);

        psbt_ctx.restore_original_utxos(&mut payjoin_proposal)?;
        assert!(payjoin_proposal.inputs[0].bip32_derivation.contains_key(&pk));
        assert!(payjoin_proposal.inputs[0].tap_key_origins.contains_key(&x_only));
        assert_eq!(payjoin_proposal.inputs[0].witness_utxo, Some(prev_txout));
        assert_eq!(payjoin_proposal.inputs[0].tap_internal_key, Some(x_only));
        assert_eq!(payjoin_proposal.inputs[0].witness_script, Some(payee));
        Ok(())
    }

    #[test]
    fn test_restore_original_outputs() -> Result<(), BoxError> {
        let mut original_psbt = PARSED_ORIGINAL_PSBT.clone();
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let (_, pk) = SECP256K1.generate_keypair(&mut bitcoin::key::rand::thread_rng());
        let x_only = pk.x_only_public_key().0;
        let taptree = TaprootBuilder::new()
            .add_leaf(0, payee.clone())?
            .try_into_taptree()
            .expect("Valid tap tree");

        original_psbt.outputs[0].witness_script = Some(payee.clone());
        original_psbt.outputs[0]
            .bip32_derivation
            .insert(pk, (Fingerprint::default(), DerivationPath::default()));
        original_psbt.outputs[0].tap_internal_key = Some(x_only);
        original_psbt.outputs[0]
            .tap_key_origins
            .insert(x_only, (vec![], (Fingerprint::default(), DerivationPath::default())));
        original_psbt.outputs[0].tap_tree = Some(taptree.clone());

        let psbt_ctx = PsbtContextBuilder::new(original_psbt.clone(), payee.clone(), None)
            .build(OutputSubstitution::Disabled)?;

        let mut payjoin_proposal = original_psbt.clone();
        clear_unneeded_fields(&mut payjoin_proposal);
        psbt_ctx.restore_original_outputs(&mut payjoin_proposal)?;
        assert_eq!(payjoin_proposal.outputs[0].witness_script, Some(payee));
        assert!(payjoin_proposal.outputs[0].bip32_derivation.contains_key(&pk));
        assert!(payjoin_proposal.outputs[0].tap_key_origins.contains_key(&x_only));
        assert_eq!(payjoin_proposal.outputs[0].tap_internal_key, Some(x_only));
        assert_eq!(payjoin_proposal.outputs[0].tap_tree, Some(taptree));
        Ok(())
    }

    #[test]
    fn test_build_recommended_payee_is_first_output() -> Result<(), BoxError> {
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.unsigned_tx.output.swap(0, 1);
        psbt.outputs.swap(0, 1);
        let payee = psbt.unsigned_tx.output[0].script_pubkey.clone();

        let psbt_ctx = PsbtContextBuilder::new(psbt, payee, None)
            .build_recommended(FeeRate::BROADCAST_MIN, OutputSubstitution::Disabled)?;

        // The change output moved to vout 1, and it is the only output that can
        // pay the receiver's input fee.
        let fee_contribution =
            psbt_ctx.fee_contribution.expect("sender should contribute fees from change");
        assert_eq!(fee_contribution.vout, 1);
        assert_eq!(fee_contribution.max_amount, Amount::from_sat(91));
        Ok(())
    }

    #[test]
    fn test_determine_fees() -> Result<(), BoxError> {
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            Script::from_bytes(&<Vec<u8> as FromHex>::from_hex(
                "0014b60943f60c3ee848828bdace7474a92e81f3fcdd",
            )?),
            Some((Amount::from_sat(1000), Some(1))),
            false,
        );
        assert_eq!((*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().vout, 1);
        assert_eq!(
            (*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().max_amount,
            Amount::from_sat(1000)
        );
        Ok(())
    }

    #[test]
    fn test_insufficient_fees() -> Result<(), BoxError> {
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            Script::from_bytes(&<Vec<u8> as FromHex>::from_hex(
                "0014b60943f60c3ee848828bdace7474a92e81f3fcdd",
            )?),
            Some((Amount::from_sat(100000000), None)),
            false,
        );
        assert_eq!(
            fee_contribution.err(),
            Some(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
        );
        // This tests the max allowed fee contribution of the given input amount
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            Script::from_bytes(&<Vec<u8> as FromHex>::from_hex(
                "0014b60943f60c3ee848828bdace7474a92e81f3fcdd",
            )?),
            // The change output (vout 0) holds 95983068 sats, so the
            // contribution must not exceed the output's value.
            Some((Amount::from_sat(95983068), None)),
            false,
        );
        assert!(fee_contribution.is_ok());
        Ok(())
    }

    #[test]
    fn test_fee_contribution_above_output_value() -> Result<(), BoxError> {
        let payee_script = ScriptBuf::from_hex("0014b60943f60c3ee848828bdace7474a92e81f3fcdd")?;
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.unsigned_tx.output[0].value = Amount::from_sat(1000);

        // A contribution above the 1000 sat output's value must be rejected
        // rather than offered to the receiver.
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1500), None)),
            false,
        );
        assert_eq!(
            fee_contribution,
            Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
        );

        // With clamping, the contribution is decreased to the output's value.
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1500), None)),
            true,
        );
        assert_eq!(
            fee_contribution,
            Ok(Some(AdditionalFeeContribution { max_amount: Amount::from_sat(1000), vout: 0 }))
        );

        // An output that cannot afford any contribution contributes nothing
        // at all.
        psbt.unsigned_tx.output[0].value = Amount::ZERO;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Ok(None));
        Ok(())
    }

    #[test]
    fn test_self_pay_change_index() -> Result<(), BoxError> {
        let script_bytes =
            <Vec<u8> as FromHex>::from_hex("a914774096dbcf486743c22f4347e9b469febe8b677a87")?;
        let payee_script = Script::from_bytes(&script_bytes);
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            payee_script,
            Some((Amount::from_sat(1000), Some(1))),
            false,
        );
        assert_eq!(
            *payee_script,
            PARSED_ORIGINAL_PSBT
                .unsigned_tx
                .output
                .get(1)
                .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)
                .unwrap()
                .script_pubkey
        );
        assert!(fee_contribution.as_ref().is_err(), "determine fee contribution expected Change output points at payee error, but it succeeded");
        match fee_contribution.as_ref() {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(*error, InternalBuildSenderError::ChangeIndexPointsAtPayee);
            }
        }
        Ok(())
    }

    #[test]
    fn test_find_change_index() -> Result<(), BoxError> {
        // All psbt vectors are modifications on the original psbt from bip78
        // Starts with the unmodified original psbt
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        let payee_script = ScriptBuf::from_hex("0014b60943f60c3ee848828bdace7474a92e81f3fcdd")?;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert!(
            fee_contribution.as_ref().is_ok(),
            "Expected an Ok result got: {:#?}",
            fee_contribution.as_ref().err()
        );
        assert_eq!((*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().vout, 0);
        assert_eq!(
            (*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().max_amount,
            Amount::from_sat(1000)
        );

        // Psbt with zero outputs
        psbt.outputs.clear();
        psbt.unsigned_tx.output.clear();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &ScriptBuf::from_hex("0014908eb2d695cf78e39a621d1561655790d1a8c60f")?,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::NoOutputs));

        // Psbt with identical receiver outputs
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs[1] = psbt.outputs[0].clone();
        psbt.unsigned_tx.output[1].script_pubkey = psbt.unsigned_tx.output[0].script_pubkey.clone();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &ScriptBuf::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")?,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MultiplePayeeOutputs));

        // Psbt with only one output
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs.pop();
        psbt.unsigned_tx.output.pop();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            Script::from_bytes(
                &<Vec<u8> as FromHex>::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")
                    .unwrap(),
            ),
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Ok(None));

        let fee_contribution = determine_fee_contribution(
            &psbt,
            Script::from_bytes(
                &<Vec<u8> as FromHex>::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")
                    .unwrap(),
            ),
            Some((Amount::from_sat(1000), None)),
            false,
        );
        assert_eq!(
            fee_contribution,
            Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
        );

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            false,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MissingPayeeOutput));

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MissingPayeeOutput));

        // Psbt with three total outputs
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs.push(psbt.outputs[1].clone());
        psbt.unsigned_tx.output.push(psbt.unsigned_tx.output[1].clone());

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::AmbiguousChangeOutput));
        Ok(())
    }

    #[test]
    fn test_single_payee_amount_mismatch() -> Result<(), BoxError> {
        let payee_script = ScriptBuf::from_hex("a914774096dbcf486743c22f4347e9b469febe8b677a87")?;
        let single_payee =
            check_single_payee(&PARSED_ORIGINAL_PSBT, &payee_script, Some(Amount::from_sat(1)));
        assert!(
            PARSED_ORIGINAL_PSBT
                .unsigned_tx
                .output
                .get(1)
                .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)
                .unwrap()
                .script_pubkey
                == payee_script
        );
        assert!(
            single_payee.is_err(),
            "Check single payee expected payee value not equal error, but it succeeded"
        );
        match single_payee {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(error, InternalBuildSenderError::PayeeValueNotEqual);
            }
        }
        Ok(())
    }

    #[test]
    fn test_equal_amount_fee_contribution() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

        ctx.fee_contribution = None;
        proposal.unsigned_tx.output[0].value = ctx.original_psbt.unsigned_tx.output[0].value;
        sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);

        assert!(ctx.process_proposal(proposal).is_ok());

        Ok(())
    }

    #[test]
    fn test_payee_output_value_decreased() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

        ctx.fee_contribution = None;
        proposal.unsigned_tx.output[0].value =
            ctx.original_psbt.unsigned_tx.output[0].value - Amount::from_sat(1);
        sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);

        ctx.original_psbt.unsigned_tx.output[0].script_pubkey =
            ctx.original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

        ctx.original_psbt.unsigned_tx.output[0].script_pubkey = ctx.payee.clone();
        assert!(ctx.process_proposal(proposal).is_ok());

        Ok(())
    }

    #[test]
    fn test_official_vectors() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO.clone();
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        let result = ctx.process_proposal(proposal);
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());
        assert_eq!(
            result.unwrap().inputs_mut()[0].witness_utxo,
            PARSED_ORIGINAL_PSBT.inputs[0].witness_utxo,
        );
        Ok(())
    }

    #[test]
    fn test_disable_output_substitution_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Disabled,
            None,
            FeeRate::ZERO,
            Version::Two,
        );
        assert_eq!(url, Url::parse("http://localhost?v=2&disableoutputsubstitution=true")?);

        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
            Version::Two,
        );
        assert_eq!(url, Url::parse("http://localhost?v=2")?);
        Ok(())
    }

    #[test]
    fn test_min_feerate_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::from_sat_per_vb(10).expect("Could not parse feerate"),
            Version::Two,
        );
        assert_eq!(url, Url::parse("http://localhost?v=2&minfeerate=10")?);
        Ok(())
    }

    #[test]
    fn test_additional_fee_contribution_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            Some(AdditionalFeeContribution { max_amount: Amount::from_sat(1000), vout: 0 }),
            FeeRate::ZERO,
            Version::Two,
        );
        assert_eq!(
            url,
            Url::parse(
                "http://localhost?v=2&additionalfeeoutputindex=0&maxadditionalfeecontribution=1000"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_fee_calculation_overflow() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        // The guard only runs when a minimum fee rate was requested.
        ctx.min_fee_rate = FeeRate::from_sat_per_vb_u32(1);

        let mut proposal = ctx.original_psbt.clone();
        // A malicious receiver claims an absurd value for an input it
        // contributed. Anything above u64::MAX / 1000 sats makes the
        // sat/kwu conversion overflow, which used to wrap silently in
        // release builds and could pass the min-fee-rate check.
        proposal.inputs[0]
            .witness_utxo
            .as_mut()
            .expect("test vector input has a witness utxo")
            .value = Amount::MAX;

        let err = ctx
            .check_fees(&proposal, Amount::ZERO)
            .expect_err("Fee rate should not be computable from an overflowing fee");
        assert!(matches!(err, InternalProposalError::FeeCalculationOverflow));

        Ok(())
    }

    /// Points the receiver input of the BIP 78 proposal vector at a previous
    /// transaction the test controls, so its `non_witness_utxo` can match the
    /// outpoint. Returns the index of the receiver input.
    fn with_receiver_non_witness_utxo(proposal: &mut bitcoin::Psbt) -> usize {
        let receiver_index = 1;
        let input = &mut proposal.inputs[receiver_index];
        let prev_txout = input.witness_utxo.clone().expect("receiver input has a witness utxo");
        let prev_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![prev_txout],
        };
        proposal.unsigned_tx.input[receiver_index].previous_output =
            OutPoint::new(prev_tx.compute_txid(), 0);
        input.non_witness_utxo = Some(prev_tx);
        receiver_index
    }

    #[test]
    fn test_receiver_input_with_matching_non_witness_utxo() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        with_receiver_non_witness_utxo(&mut proposal);
        let result = ctx.process_proposal(proposal);
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());
        Ok(())
    }

    #[test]
    fn test_receiver_input_non_witness_utxo_txid_mismatch() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        let receiver_index = with_receiver_non_witness_utxo(&mut proposal);
        // Changing the previous transaction changes its txid, so it no longer
        // matches the outpoint.
        let delta = Amount::from_sat(10_000);
        let input = &mut proposal.inputs[receiver_index];
        input.witness_utxo = None;
        input.non_witness_utxo.as_mut().expect("non_witness_utxo was just set").output[0].value +=
            delta;
        proposal.unsigned_tx.output[1].value += delta;

        assert!(matches!(
            ctx.process_proposal(proposal),
            Err(InternalProposalError::ReceiverTxinInvalidUtxo(
                InternalPsbtInputError::UnequalTxid
            ))
        ));
        Ok(())
    }

    #[test]
    fn test_receiver_input_witness_utxo_contradicts_non_witness_utxo() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        let receiver_index = with_receiver_non_witness_utxo(&mut proposal);
        let delta = Amount::from_sat(10_000);
        proposal.inputs[receiver_index]
            .witness_utxo
            .as_mut()
            .expect("receiver input has a witness utxo")
            .value += delta;
        proposal.unsigned_tx.output[1].value += delta;

        assert!(matches!(
            ctx.process_proposal(proposal),
            Err(InternalProposalError::ReceiverTxinInvalidUtxo(
                InternalPsbtInputError::SegWitTxOutMismatch
            ))
        ));
        Ok(())
    }

    /// Output types whose spends the sender can verify from a signature.
    #[derive(Clone, Copy, Debug)]
    enum ReceiverScript {
        P2wpkh,
        P2shP2wpkh,
        P2tr,
    }

    const RECEIVER_SCRIPTS: [ReceiverScript; 3] =
        [ReceiverScript::P2wpkh, ReceiverScript::P2shP2wpkh, ReceiverScript::P2tr];

    /// How [`sign_receiver_input_with`] signs a receiver input.
    #[derive(Clone, Copy, Debug, Default)]
    struct Signing {
        /// `None` signs with `SIGHASH_ALL`, or `SIGHASH_DEFAULT` for taproot.
        sighash_type: Option<PsbtSighashType>,
        /// Encode an ECDSA signature with the high S value consensus allows.
        high_s: bool,
    }

    /// Gives the receiver input at `index` a `witness_utxo` of type `script`
    /// owned by a test key, keeping its value, and finalizes the input with a
    /// `SIGHASH_ALL` or `SIGHASH_DEFAULT` signature over `proposal`.
    ///
    /// The BIP 78 vector's receiver key is unknown, so tests that change the
    /// proposal's transaction call this after their last change to keep the
    /// receiver's signature valid.
    fn sign_receiver_input(proposal: &mut bitcoin::Psbt, index: usize, script: ReceiverScript) {
        sign_receiver_input_with(proposal, index, script, Signing::default())
    }

    /// Like [`sign_receiver_input`], signing as `signing` describes.
    fn sign_receiver_input_with(
        proposal: &mut bitcoin::Psbt,
        index: usize,
        script: ReceiverScript,
        signing: Signing,
    ) {
        let secret_key = SecretKey::from_slice(&[0x42; 32]).expect("valid secret key");
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let pubkey = bitcoin::CompressedPublicKey(keypair.public_key());
        let p2wpkh = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash());

        let input = &mut proposal.inputs[index];
        input.non_witness_utxo = None;
        let witness_utxo = input.witness_utxo.as_mut().expect("receiver input has a witness utxo");
        witness_utxo.script_pubkey = match script {
            ReceiverScript::P2wpkh => p2wpkh.clone(),
            ReceiverScript::P2shP2wpkh => ScriptBuf::new_p2sh(&p2wpkh.script_hash()),
            ReceiverScript::P2tr =>
                ScriptBuf::new_p2tr(SECP256K1, keypair.x_only_public_key().0, None),
        };
        let value = witness_utxo.value;

        let prevouts = proposal
            .input_pairs()
            .map(|input_pair| input_pair.previous_txout().cloned())
            .collect::<Result<Vec<_>, _>>()
            .expect("every input has a witness utxo");
        let mut cache = SighashCache::new(&proposal.unsigned_tx);
        let (script_sig, witness) = match script {
            ReceiverScript::P2tr => {
                let sighash_type = signing
                    .sighash_type
                    .map_or(Ok(TapSighashType::Default), |ty| ty.taproot_hash_ty())
                    .expect("taproot sighash type");
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        sighash_type,
                    )
                    .expect("valid taproot sighash");
                let tweaked = keypair.tap_tweak(SECP256K1, None).to_keypair();
                let signature = SECP256K1.sign_schnorr_no_aux_rand(
                    &Message::from_digest(sighash.to_byte_array()),
                    &tweaked,
                );
                let signature = taproot::Signature { signature, sighash_type };
                (None, Witness::p2tr_key_spend(&signature))
            }
            ReceiverScript::P2wpkh | ReceiverScript::P2shP2wpkh => {
                let sighash_type = signing
                    .sighash_type
                    .map_or(Ok(EcdsaSighashType::All), |ty| ty.ecdsa_hash_ty())
                    .expect("ECDSA sighash type");
                let sighash = cache
                    .p2wpkh_signature_hash(index, &p2wpkh, value, sighash_type)
                    .expect("valid segwit v0 sighash");
                let mut signature = SECP256K1
                    .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &secret_key);
                if signing.high_s {
                    signature = high_s(signature);
                }
                let witness = Witness::p2wpkh(&Signature { signature, sighash_type }, &pubkey.0);
                let script_sig = matches!(script, ReceiverScript::P2shP2wpkh).then(|| {
                    let redeem_script: &PushBytes =
                        p2wpkh.as_bytes().try_into().expect("redeem script fits in a push");
                    ScriptBuf::builder().push_slice(redeem_script).into_script()
                });
                (script_sig, witness)
            }
        };
        let input = &mut proposal.inputs[index];
        input.final_script_sig = script_sig;
        input.final_script_witness = Some(witness);
    }

    /// The high S encoding of a low S `signature`, which signs the same
    /// message.
    fn high_s(
        signature: bitcoin::secp256k1::ecdsa::Signature,
    ) -> bitcoin::secp256k1::ecdsa::Signature {
        let compact = signature.serialize_compact();
        let s = SecretKey::from_slice(&compact[32..]).expect("s is a valid scalar").negate();
        let mut compact = compact;
        compact[32..].copy_from_slice(&s.secret_bytes());
        let high_s = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact)
            .expect("valid compact signature");
        let mut normalized = high_s;
        normalized.normalize_s();
        assert_eq!(normalized, signature, "the encoding has a high S value");
        assert_ne!(high_s, signature, "the encoding has a high S value");
        high_s
    }

    /// Asserts that `proposal` fails because a receiver input does not prove
    /// the spent output it claims.
    fn assert_unverified_receiver_input(
        ctx: &super::PsbtContext,
        proposal: bitcoin::Psbt,
        expected: InputSignatureError,
    ) {
        match ctx.clone().process_proposal(proposal) {
            Err(InternalProposalError::ReceiverTxinUnverifiedUtxo(error)) =>
                assert_eq!(error, expected),
            other => panic!("expected an unverified receiver input, got {other:?}"),
        }
    }

    #[test]
    fn test_receiver_input_signatures_accepted() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let honest = proposal_without_contribution(&mut ctx);
        for script in RECEIVER_SCRIPTS {
            let mut proposal = honest.clone();
            sign_receiver_input(&mut proposal, 1, script);
            let result = ctx.clone().process_proposal(proposal);
            assert!(result.is_ok(), "{script:?}: expected an Ok result got: {:#?}", result.err());
        }
        Ok(())
    }

    /// The BIP 78 proposal vector with the sender's fee contribution
    /// undone, so receiver inputs smaller than the vector's P2SH-P2WPKH one
    /// do not take more contribution than their weight allows.
    fn proposal_without_contribution(ctx: &mut super::PsbtContext) -> bitcoin::Psbt {
        ctx.fee_contribution = None;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        proposal.unsigned_tx.output[0].value = ctx.original_psbt.unsigned_tx.output[0].value;
        proposal
    }

    /// Adds `delta` to the value in the `witness_utxo` of the receiver input
    /// at `index`, so it no longer matches the value that input signed.
    fn offset_claimed_value(proposal: &mut bitcoin::Psbt, index: usize, delta: Amount) {
        proposal.inputs[index].witness_utxo.as_mut().expect("receiver witness utxo").value += delta;
    }

    #[test]
    fn test_receiver_input_ecdsa_sighash_types() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let honest = proposal_without_contribution(&mut ctx);
        let sighash_types = [
            EcdsaSighashType::All,
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ];
        for script in [ReceiverScript::P2wpkh, ReceiverScript::P2shP2wpkh] {
            for sighash_type in sighash_types {
                for high_s in [false, true] {
                    let signing = Signing { sighash_type: Some(sighash_type.into()), high_s };
                    let mut proposal = honest.clone();
                    sign_receiver_input_with(&mut proposal, 1, script, signing);
                    let result = ctx.clone().process_proposal(proposal.clone());
                    assert!(result.is_ok(), "{script:?} {signing:?}: got {:#?}", result.err());

                    offset_claimed_value(&mut proposal, 1, Amount::from_sat(1));
                    assert_unverified_receiver_input(
                        &ctx,
                        proposal,
                        InputSignatureError::InvalidSignature,
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_receiver_input_taproot_sighash_types() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let honest = proposal_without_contribution(&mut ctx);
        let sighash_types = [
            TapSighashType::Default,
            TapSighashType::All,
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ];
        for sighash_type in sighash_types {
            let signing = Signing { sighash_type: Some(sighash_type.into()), high_s: false };
            let mut proposal = honest.clone();
            sign_receiver_input_with(&mut proposal, 1, ReceiverScript::P2tr, signing);
            let result = ctx.clone().process_proposal(proposal.clone());
            assert!(result.is_ok(), "{sighash_type:?}: got {:#?}", result.err());

            offset_claimed_value(&mut proposal, 1, Amount::from_sat(1));
            assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::InvalidSignature);
        }
        Ok(())
    }

    /// A receiver input placed before the sender's, next to a second receiver
    /// input that a `non_witness_utxo` authenticates.
    #[test]
    fn test_receiver_inputs_reordered_and_mixed() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal = proposal_without_contribution(&mut ctx);
        proposal.unsigned_tx.input.swap(0, 1);
        proposal.inputs.swap(0, 1);

        let value = Amount::from_sat(50_000);
        let prev_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()),
            }],
        };
        proposal.unsigned_tx.input.push(TxIn {
            previous_output: OutPoint::new(prev_tx.compute_txid(), 0),
            sequence: proposal.unsigned_tx.input[0].sequence,
            ..Default::default()
        });
        proposal.inputs.push(bitcoin::psbt::Input {
            witness_utxo: Some(prev_tx.output[0].clone()),
            non_witness_utxo: Some(prev_tx),
            // Not verified, since the previous transaction authenticates the output.
            final_script_witness: Some(Witness::from_slice(&[[0u8; 72].as_slice(), &[2u8; 33]])),
            ..Default::default()
        });
        proposal.unsigned_tx.output[1].value += value;

        for script in RECEIVER_SCRIPTS {
            let mut proposal = proposal.clone();
            sign_receiver_input(&mut proposal, 0, script);
            let result = ctx.clone().process_proposal(proposal.clone());
            assert!(result.is_ok(), "{script:?}: got {:#?}", result.err());

            offset_claimed_value(&mut proposal, 0, Amount::from_sat(1));
            assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::InvalidSignature);
        }
        Ok(())
    }

    /// Taproot signatures commit to the sender's spent output too, so the
    /// sender verifies them against its own restored UTXO even when the
    /// receiver strips it, as BIP 78 asks.
    #[test]
    fn test_taproot_receiver_input_with_stripped_sender_utxo() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal = proposal_without_contribution(&mut ctx);
        sign_receiver_input(&mut proposal, 1, ReceiverScript::P2tr);
        proposal.inputs[0].witness_utxo = None;
        proposal.inputs[0].non_witness_utxo = None;

        let result = ctx.clone().process_proposal(proposal.clone());
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());

        offset_claimed_value(&mut proposal, 1, Amount::from_sat(1));
        assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::InvalidSignature);
        Ok(())
    }

    /// A receiver input built with [`InputPair::new_p2wsh`] carries only a
    /// `witness_utxo`, which no signature check can authenticate. The sender
    /// accepts it once the receiver adds the previous transaction.
    ///
    /// [`InputPair::new_p2wsh`]: crate::receive::InputPair::new_p2wsh
    #[test]
    fn test_p2wsh_receiver_input_needs_non_witness_utxo() -> Result<(), BoxError> {
        use crate::receive::InputPair;

        let mut ctx = create_psbt_context()?;
        let honest = proposal_without_contribution(&mut ctx);
        let witness_script = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
        let txout = TxOut {
            value: honest.inputs[1].witness_utxo.as_ref().expect("receiver witness utxo").value,
            script_pubkey: ScriptBuf::new_p2wsh(&witness_script.wscript_hash()),
        };
        let prev_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![txout.clone()],
        };
        let outpoint = OutPoint::new(prev_tx.compute_txid(), 0);
        let expected_weight = Weight::from_wu(200);
        // Splices `pair` in as the receiver input, finalized as its wallet would.
        let contribute = |pair: InputPair| {
            let mut proposal = honest.clone();
            proposal.unsigned_tx.input[1].previous_output = pair.txin.previous_output;
            proposal.inputs[1] = bitcoin::psbt::Input {
                final_script_witness: Some(Witness::from_slice(&[witness_script.as_bytes()])),
                ..pair.psbtin
            };
            proposal
        };

        let bare = InputPair::new_p2wsh(txout.clone(), outpoint, expected_weight)?;
        assert!(bare.psbtin.non_witness_utxo.is_none());
        assert_unverified_receiver_input(
            &ctx,
            contribute(bare),
            InputSignatureError::UnsupportedScript,
        );

        let with_prev_tx = InputPair::new(
            TxIn { previous_output: outpoint, ..Default::default() },
            bitcoin::psbt::Input {
                witness_utxo: Some(txout),
                non_witness_utxo: Some(prev_tx),
                ..Default::default()
            },
            Some(expected_weight),
        )?;
        let result = ctx.process_proposal(contribute(with_prev_tx));
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());
        Ok(())
    }

    /// `check_receiver_input_signatures` trusts a `non_witness_utxo` only
    /// after checking it, without relying on `check_inputs` to have done so.
    #[test]
    fn test_receiver_input_signatures_check_non_witness_utxo() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        let receiver_index = with_receiver_non_witness_utxo(&mut proposal);
        assert!(ctx.check_receiver_input_signatures(&proposal).is_ok());

        offset_claimed_value(&mut proposal, receiver_index, Amount::from_sat(1));
        assert!(matches!(
            ctx.check_receiver_input_signatures(&proposal),
            Err(InternalProposalError::ReceiverTxinInvalidUtxo(
                InternalPsbtInputError::SegWitTxOutMismatch
            ))
        ));
        Ok(())
    }

    /// The claimed previous output of a receiver input does not match the
    /// signed one, and an output differs by the same delta, so the computed
    /// fee is unchanged. The signature check rejects the input.
    #[test]
    fn test_receiver_input_value_mismatch_rejected() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let honest = PARSED_PAYJOIN_PROPOSAL.clone();
        let delta = absolute_fee(&honest)? - Amount::from_sat(1);
        let contributed_fee =
            ctx.original_psbt.unsigned_tx.output[0].value - honest.unsigned_tx.output[0].value;

        let with_claimed_value = |mut proposal: bitcoin::Psbt| {
            offset_claimed_value(&mut proposal, 1, delta);
            proposal
        };
        let mut adjusted = honest.clone();
        adjusted.unsigned_tx.output[1].value += delta;

        // The BIP 78 vector's own P2SH-P2WPKH signature.
        let mismatched = with_claimed_value(adjusted.clone());
        assert!(
            ctx.check_fees(&mismatched, contributed_fee).is_ok(),
            "fee checks use the claimed values"
        );
        assert_unverified_receiver_input(&ctx, mismatched, InputSignatureError::InvalidSignature);

        for script in RECEIVER_SCRIPTS {
            let mut signed = adjusted.clone();
            sign_receiver_input(&mut signed, 1, script);
            assert_unverified_receiver_input(
                &ctx,
                with_claimed_value(signed),
                InputSignatureError::InvalidSignature,
            );
        }
        Ok(())
    }

    /// The claimed previous output of a receiver input does not match the
    /// signed one, by the delta that brings the computed fee rate up to the
    /// sender's minimum. The outputs, including the sender's fee
    /// contribution, are unchanged. The signature check rejects the input.
    #[test]
    fn test_receiver_input_value_mismatch_rejected_at_min_fee_rate() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let honest = PARSED_PAYJOIN_PROPOSAL.clone();
        let weight = honest.clone().extract_tx_unchecked_fee_rate().weight();
        let honest_fee_rate = absolute_fee(&honest)?.div_by_weight_floor(weight).expect("fee rate");
        ctx.min_fee_rate = FeeRate::from_sat_per_kwu(honest_fee_rate.to_sat_per_kwu() + 1000);
        let delta = ctx.min_fee_rate.fee_wu(weight).expect("fee fits") - absolute_fee(&honest)?;
        let contributed_fee =
            ctx.original_psbt.unsigned_tx.output[0].value - honest.unsigned_tx.output[0].value;
        assert!(contributed_fee > Amount::ZERO);

        assert!(matches!(
            ctx.clone().process_proposal(honest.clone()),
            Err(InternalProposalError::FeeRateBelowMinimum)
        ));

        let mut mismatched = honest.clone();
        offset_claimed_value(&mut mismatched, 1, delta);
        assert!(
            ctx.check_fees(&mismatched, contributed_fee).is_ok(),
            "fee checks use the claimed values"
        );
        assert_unverified_receiver_input(&ctx, mismatched, InputSignatureError::InvalidSignature);
        Ok(())
    }

    #[test]
    fn test_receiver_input_unsupported_script() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;

        // A legacy output can only be authenticated by its previous transaction.
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        proposal.inputs[1].witness_utxo.as_mut().expect("receiver witness utxo").script_pubkey =
            ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::all_zeros());
        assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::UnsupportedScript);

        // A taproot script path spend.
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        sign_receiver_input(&mut proposal, 1, ReceiverScript::P2tr);
        let witness = proposal.inputs[1].final_script_witness.as_mut().expect("signed input");
        witness.push([0x51]);
        witness.push([0xc0; 33]);
        assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::UnsupportedScript);
        Ok(())
    }

    #[test]
    fn test_receiver_input_witness_for_another_key() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        for script in [ReceiverScript::P2wpkh, ReceiverScript::P2shP2wpkh] {
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            sign_receiver_input(&mut proposal, 1, script);
            // Point the claimed output at another key the witness does not reveal.
            let witness_utxo = proposal.inputs[1].witness_utxo.as_mut().expect("witness utxo");
            witness_utxo.script_pubkey = match script {
                ReceiverScript::P2wpkh => ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()),
                _ =>
                    PARSED_PAYJOIN_PROPOSAL.inputs[1]
                        .witness_utxo
                        .clone()
                        .expect("witness utxo")
                        .script_pubkey,
            };
            assert_unverified_receiver_input(&ctx, proposal, InputSignatureError::MalformedSpend);
        }
        Ok(())
    }

    /// Test the sender's payjoin proposal checklist
    /// See: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Senders_payjoin_proposal_checklist
    /// TODO: update the BIP78 spec, see the sighash check in [`PsbtContextBuilder::build`].
    mod bip78_checklist {
        use super::*;

        #[test]
        fn test_transaction_versions_dont_match() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let original_version = ctx.original_psbt.unsigned_tx.version;
            let proposed_version = bitcoin::transaction::Version::non_standard(88);
            proposal.unsigned_tx.version = proposed_version;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::VersionsDontMatch {
                    proposed,
                    original
                }) if proposed == proposed_version && original == original_version
            ));
            Ok(())
        }

        #[test]
        fn test_transaction_locktimes_dont_match() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let original_locktime = ctx.original_psbt.unsigned_tx.lock_time;
            let proposed_locktime = LockTime::from_consensus(
                ctx.original_psbt.unsigned_tx.lock_time.to_consensus_u32() - 1,
            );
            proposal.unsigned_tx.lock_time = proposed_locktime;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::LockTimesDontMatch {
                    proposed,
                    original
                }) if proposed == proposed_locktime && original == original_locktime
            ));
            Ok(())
        }

        #[test]
        fn test_key_path_found_in_proposal() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Add a keypath to the input
            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.inputs[0].bip32_derivation.insert(
                PublicKey::from_secret_key(&context, &secret_key),
                bitcoin::bip32::KeySource::default(),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::TxInContainsKeyPaths.to_string()
            );
            Ok(())
        }

        #[test]
        fn test_partial_sig_found_in_proposal() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Add a keypath to the input
            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.inputs[0].partial_sigs.insert(
                PublicKey::from_secret_key(&context, &secret_key).into(),
                Signature::sighash_all(secret_key.sign_ecdsa(Message::from_digest([0; 32]))),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ContainsPartialSigs.to_string()
            );
            Ok(())
        }

        #[test]
        fn test_sender_input_sequence_number_changed() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Change the sequence number of the proposal
            let original_sequence = proposal.unsigned_tx.input.first().unwrap().sequence;
            let proposed_sequence =
                Sequence::from_consensus(original_sequence.to_consensus_u32() - 1);
            proposal.unsigned_tx.input.get_mut(0).unwrap().sequence = proposed_sequence;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::SenderTxinSequenceChanged {
                    proposed,
                    original
                }) if proposed == proposed_sequence && original == original_sequence
            ));
            Ok(())
        }

        #[test]
        fn test_sender_input_outpoint_changed() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
            proposal.unsigned_tx.input[0].previous_output.vout += 1;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MissingOrShuffledInputs.to_string()
            );
            Ok(())
        }

        #[test]
        fn test_sender_input_final_script_sig_is_present() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
            proposal.inputs.get_mut(0).unwrap().final_script_sig = Some(ScriptBuf::new());

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::SenderTxinContainsFinalScriptSig.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_sender_input_final_script_witness_is_present() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
            proposal.inputs.get_mut(0).unwrap().final_script_witness = Some(Witness::new());

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::SenderTxinContainsFinalScriptWitness.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_sender_input_non_all_sighash_type_is_rejected() -> Result<(), BoxError> {
            use bitcoin::psbt::PsbtSighashType;
            use bitcoin::sighash::{EcdsaSighashType, TapSighashType};

            // Any sighash type that does not commit to all inputs and outputs
            // must be rejected on the sender's own inputs, both in the Original
            // PSBT the sender hands over and in the proposal it gets back.
            let invalid_sighash_types = [
                PsbtSighashType::from(EcdsaSighashType::None),
                PsbtSighashType::from(EcdsaSighashType::Single),
                PsbtSighashType::from(EcdsaSighashType::AllPlusAnyoneCanPay),
                PsbtSighashType::from(EcdsaSighashType::NonePlusAnyoneCanPay),
                PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay),
                PsbtSighashType::from(TapSighashType::None),
                PsbtSighashType::from(TapSighashType::Single),
                PsbtSighashType::from(TapSighashType::AllPlusAnyoneCanPay),
                PsbtSighashType::from(TapSighashType::NonePlusAnyoneCanPay),
                PsbtSighashType::from(TapSighashType::SinglePlusAnyoneCanPay),
            ];

            for sighash_type in invalid_sighash_types {
                let mut original_psbt = PARSED_ORIGINAL_PSBT.clone();
                let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
                original_psbt.inputs[0].sighash_type = Some(sighash_type);

                assert_eq!(
                    PsbtContextBuilder::new(original_psbt, payee, None)
                        .build(OutputSubstitution::Disabled)
                        .unwrap_err()
                        .to_string(),
                    BuildSenderError::from(InternalBuildSenderError::OriginalTxinNonAllSighashType)
                        .to_string(),
                    "sighash type {sighash_type:?} should be rejected in the Original PSBT",
                );

                let ctx = create_psbt_context()?;
                let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
                proposal.inputs.get_mut(0).unwrap().sighash_type = Some(sighash_type);

                assert_eq!(
                    ctx.process_proposal(proposal).unwrap_err().to_string(),
                    InternalProposalError::SenderTxinNonAllSighashType.to_string(),
                    "sighash type {sighash_type:?} should be rejected in the proposal",
                );
            }
            Ok(())
        }

        #[test]
        fn test_sender_input_nonstandard_sighash_type_is_rejected() -> Result<(), BoxError> {
            use bitcoin::psbt::PsbtSighashType;

            // PSBT_IN_SIGHASH_TYPE is a raw u32, so it can hold values that
            // parse as neither an ECDSA nor a taproot sighash type. An
            // unparsable type commits to nothing knowable, so it must be
            // rejected rather than waved through as "not a known bad type".
            let nonstandard = [0x04, 0x80, 0xff, 0x100, u32::MAX];

            for raw in nonstandard {
                let mut original_psbt = PARSED_ORIGINAL_PSBT.clone();
                let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
                original_psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(raw));

                assert_eq!(
                    PsbtContextBuilder::new(original_psbt, payee, None)
                        .build(OutputSubstitution::Disabled)
                        .unwrap_err()
                        .to_string(),
                    BuildSenderError::from(InternalBuildSenderError::OriginalTxinNonAllSighashType)
                        .to_string(),
                    "sighash type {raw:#x} should be rejected in the Original PSBT",
                );

                let ctx = create_psbt_context()?;
                let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
                proposal.inputs.get_mut(0).unwrap().sighash_type =
                    Some(PsbtSighashType::from_u32(raw));

                assert_eq!(
                    ctx.process_proposal(proposal).unwrap_err().to_string(),
                    InternalProposalError::SenderTxinNonAllSighashType.to_string(),
                    "sighash type {raw:#x} should be rejected in the proposal",
                );
            }
            Ok(())
        }

        #[test]
        fn test_sender_input_all_sighash_type_is_accepted() -> Result<(), BoxError> {
            use bitcoin::psbt::PsbtSighashType;
            use bitcoin::sighash::{EcdsaSighashType, TapSighashType};

            // SIGHASH_ALL and taproot SIGHASHDEFAULT/SIGHASH_ALL commit to all
            // inputs and outputs, as does an unset type, so all must be accepted
            // in the Original PSBT and in the proposal alike.
            let acceptable = [
                None,
                Some(PsbtSighashType::from(EcdsaSighashType::All)),
                Some(PsbtSighashType::from(TapSighashType::Default)),
                Some(PsbtSighashType::from(TapSighashType::All)),
            ];

            for sighash_type in acceptable {
                let mut original_psbt = PARSED_ORIGINAL_PSBT.clone();
                let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
                original_psbt.inputs[0].sighash_type = sighash_type;

                PsbtContextBuilder::new(original_psbt, payee, None)
                    .build(OutputSubstitution::Disabled)
                    .unwrap_or_else(|e| panic!("sighash type {sighash_type:?} should build: {e}"));

                let ctx = create_psbt_context()?;
                let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
                proposal.inputs.get_mut(0).unwrap().sighash_type = sighash_type;

                ctx.process_proposal(proposal).unwrap_or_else(|e| {
                    panic!("sighash type {sighash_type:?} should be accepted: {e}")
                });
            }
            Ok(())
        }

        #[test]
        fn test_receiver_input_is_not_finalized() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Make the receiver's input unfinalized.
            proposal.inputs.get_mut(1).unwrap().final_script_sig = None;
            proposal.inputs.get_mut(1).unwrap().final_script_witness = None;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ReceiverTxinNotFinalized.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_input_missing_witness_info() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Remove the receiver's UTXO information.
            proposal.inputs.get_mut(1).unwrap().witness_utxo = None;
            proposal.inputs.get_mut(1).unwrap().non_witness_utxo = None;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ReceiverTxinMissingUtxoInfo.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_input_has_mixed_sequence_() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Ensure the sequence is different
            let sequence = ctx.original_psbt.unsigned_tx.input.get_mut(0).unwrap().sequence;
            proposal.unsigned_tx.input.get_mut(1).unwrap().sequence =
                Sequence::from_consensus(sequence.to_consensus_u32() + 1);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MixedSequence.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_missing_original_inputs() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            proposal.unsigned_tx.input.clear();
            proposal.inputs.clear();

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MissingOrShuffledInputs.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_contains_key_path() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.outputs.get_mut(0).unwrap().bip32_derivation.insert(
                PublicKey::from_secret_key(&context, &secret_key),
                bitcoin::bip32::KeySource::default(),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::TxOutContainsKeyPaths.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_steals_sender_change() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            // Steal 0.5 BTC from the sender output and add it to the receiver output
            proposal.unsigned_tx.output[0].value -= Amount::from_btc(0.5)?;
            proposal.unsigned_tx.output[1].value += Amount::from_btc(0.5)?;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeContributionExceedsMaximum.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_payee_output_has_disallowed_output_substitution(
        ) -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            ctx.output_substitution = OutputSubstitution::Disabled;

            // When output substitution is disabled ensure that the output value did not decrease
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            // When output substitution is disabled still allow increasing the output value
            proposal.unsigned_tx.output[0].value += MAX_ADDITIONAL_FEE_CONTRIBUTION;
            sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value -= MAX_ADDITIONAL_FEE_CONTRIBUTION;
            ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().script_pubkey =
                ctx.payee.clone();
            std::mem::swap(
                &mut ctx.original_psbt.unsigned_tx.output[0].value,
                &mut proposal.unsigned_tx.output[0].value,
            );
            sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);
            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::DisallowedOutputSubstitution.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_payee_output_has_allowed_output_substitution(
        ) -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();

            // Do not make any checks when output substitution is enabled
            ctx.output_substitution = OutputSubstitution::Enabled;
            ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().script_pubkey =
                ctx.payee.clone();
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value += MAX_ADDITIONAL_FEE_CONTRIBUTION;
            sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value -= Amount::from_sat(364);
            sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);
            assert!(ctx.process_proposal(proposal).is_ok());

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_value_decreased() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            ctx.fee_contribution = None;
            proposal.unsigned_tx.output.get_mut(0).unwrap().value =
                ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().value
                    - Amount::from_sat(1);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::OutputValueDecreased.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_rejects_different_script_in_our_output() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            ctx.fee_contribution = None;
            ctx.output_substitution = OutputSubstitution::Enabled;

            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            let original_change =
                &ctx.original_psbt.unsigned_tx.output[ADDITIONAL_FEE_OUTPUT_INDEX];
            assert_ne!(original_change.script_pubkey, ctx.payee);

            let change_pos = proposal
                .unsigned_tx
                .output
                .iter()
                .position(|o| o.script_pubkey == original_change.script_pubkey)
                .expect("proposal should contain the change output");

            // Replace the change output with one that has a different script
            // but the same value, so the mutation would cause arm 3 to match
            // and the value guard would pass (value >= original.value = true).
            let dummy_script =
                ScriptBuf::from_hex("0014ffffffffffffffffffffffffffffffffffffffffff")?;
            proposal.unsigned_tx.output[change_pos] =
                TxOut { value: original_change.value, script_pubkey: dummy_script };
            assert!(
                ctx.process_proposal(proposal).is_err(),
                "arm 3 must reject script mismatch in our output"
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_missing() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            proposal.unsigned_tx.output.clear();
            proposal.outputs.clear();

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MissingOrShuffledOutputs.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_absolute_fee_less_than_original_psbt() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            for output in proposal.outputs_mut() {
                output.bip32_derivation.clear();
            }
            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
            }

            // Reduce the proposed fee to be less than the original fee
            proposal.unsigned_tx.output[0].value += bitcoin::Amount::from_sat(183);
            sign_receiver_input(&mut proposal, 1, ReceiverScript::P2shP2wpkh);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::AbsoluteFeeDecreased.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_payee_took_contributed_fee() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            let redistributed_amount = Amount::from_sat(1);

            // Redistribute 1 sat between outputs so that the net on-chain fee doesn't increase
            let output_0 = proposal.unsigned_tx.output[0].value;
            proposal.unsigned_tx.output[0].value = output_0 - redistributed_amount;
            let output_1 = proposal.unsigned_tx.output[1].value;
            proposal.unsigned_tx.output[1].value = output_1 + redistributed_amount;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::PayeeTookContributedFee.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_fee_contribution_pays_output_size_increase() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            let contributed_fee = Amount::from_sat(10);
            let original_output = proposal.unsigned_tx.output[0].value;
            proposal.unsigned_tx.output[0].value = original_output - contributed_fee;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeContributionPaysOutputSizeIncrease.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_fee_rate_below_minimum() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            // The fee rate will always be below this min_fee_rate
            ctx.min_fee_rate = FeeRate::MAX;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeRateBelowMinimum.to_string()
            );

            Ok(())
        }
    }
}
