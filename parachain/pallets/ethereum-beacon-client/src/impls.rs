// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
use super::*;

use snowbridge_core::inbound::VerificationError::{self, *};
use snowbridge_ethereum::Receipt;

impl<T: Config> Verifier for Pallet<T> {
	/// Verify a message by verifying the existence of the corresponding
	/// Ethereum log in a block. Returns the log if successful. The execution header containing
	/// the log should be in the beacon client storage, meaning it has been verified and is an
	/// ancestor of a finalized beacon block.
	fn verify(message: &Message) -> Result<(), VerificationError> {
		log::info!(
			target: "ethereum-beacon-client",
			"💫 Verifying message with block hash {}",
			message.proof.block_hash,
		);

		let header =
			<ExecutionHeaderBuffer<T>>::get(message.proof.block_hash).ok_or(HeaderNotFound)?;

		let receipt = match Self::verify_receipt_inclusion(header.receipts_root, &message.proof) {
			Ok(receipt) => receipt,
			Err(err) => {
				log::error!(
					target: "ethereum-beacon-client",
					"💫 Verification of receipt inclusion failed for block {}: {:?}",
					message.proof.block_hash,
					err
				);
				return Err(err)
			},
		};

		log::trace!(
			target: "ethereum-beacon-client",
			"💫 Verified receipt inclusion for transaction at index {} in block {}",
			message.proof.tx_index, message.proof.block_hash,
		);

		let log = match rlp::decode(&message.data) {
			Ok(log) => log,
			Err(err) => {
				log::error!(
					target: "ethereum-beacon-client",
					"💫 RLP log decoded failed {}: {:?}",
					message.proof.block_hash,
					err
				);
				return Err(InvalidLog)
			},
		};

		if !receipt.contains_log(&log) {
			log::error!(
				target: "ethereum-beacon-client",
				"💫 Event log not found in receipt for transaction at index {} in block {}",
				message.proof.tx_index, message.proof.block_hash,
			);
			return Err(LogNotFound)
		}

		log::info!(
			target: "ethereum-beacon-client",
			"💫 Receipt verification successful for {}",
			message.proof.block_hash,
		);

		Ok(())
	}
}

impl<T: Config> Pallet<T> {
	/// Verifies that the receipt encoded in `proof.data` is included in the block given by
	/// `proof.block_hash`.
	pub fn verify_receipt_inclusion(
		receipts_root: H256,
		proof: &Proof,
	) -> Result<Receipt, VerificationError> {
		let result = verify_receipt_proof(receipts_root, &proof.data.1).ok_or(InvalidProof)?;

		match result {
			Ok(receipt) => Ok(receipt),
			Err(err) => {
				log::trace!(
					target: "ethereum-beacon-client",
					"💫 Failed to decode transaction receipt: {}",
					err
				);
				Err(InvalidProof)
			},
		}
	}
}
