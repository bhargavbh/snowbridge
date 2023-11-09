// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2023 Snowfork <hello@snowfork.com>
//! Inbound Queue
//!
//! # Overview
//!
//! Receives messages emitted by the Gateway contract on Ethereum, whereupon they are verified,
//! translated to XCM, and finally sent to their final destination parachain.
//!
//! The message relayers are rewarded using native currency from the sovereign account of the
//! destination parachain.
//!
//! # Extrinsics
//!
//! ## Governance
//!
//! * [`Call::set_operating_mode`]: Set the operating mode of the pallet. Can be used to disable
//!   processing of inbound messages.
//!
//! ## Message Submission
//!
//! * [`Call::submit`]: Submit a message for verification and dispatch the final destination
//!   parachain.
#![cfg_attr(not(feature = "std"), no_std)]

mod envelope;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(feature = "runtime-benchmarks")]
use snowbridge_beacon_primitives::CompactExecutionHeader;

pub mod weights;

#[cfg(test)]
mod test;

use alloy_rlp::Decodable as RlpDecodable;
use codec::{Decode, DecodeAll, Encode};
use envelope::{Envelope, Log};
use frame_support::{
	traits::{
		fungible::{Inspect, Mutate},
		tokens::Preservation,
	},
	weights::WeightToFee,
	PalletError,
};
use frame_system::ensure_signed;
use scale_info::TypeInfo;
use sp_core::{H160, H256};
use sp_std::{convert::TryFrom, vec};
use xcm::prelude::{
	send_xcm, Instruction::SetTopic, Junction::*, Junctions::*, MultiLocation,
	SendError as XcmpSendError, SendXcm, Xcm, XcmHash,
};

use snowbridge_core::{
	inbound::{Message, VerificationError, Verifier},
	sibling_sovereign_account, BasicOperatingMode, ParaId,
};
use snowbridge_router_primitives::{
	inbound,
	inbound::{ConvertMessage, ConvertMessageError},
};
use sp_runtime::traits::Saturating;

pub use weights::WeightInfo;

type BalanceOf<T> =
	<<T as pallet::Config>::Token as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

pub use pallet::*;

pub const LOG_TARGET: &str = "snowbridge-inbound-queue";

#[frame_support::pallet]
pub mod pallet {

	use super::*;

	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[cfg(feature = "runtime-benchmarks")]
	pub trait BenchmarkHelper<T> {
		fn initialize_storage(block_hash: H256, header: CompactExecutionHeader);
	}

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// The verifier for inbound messages from Ethereum
		type Verifier: Verifier;

		/// Message relayers are rewarded with this asset
		type Token: Mutate<Self::AccountId>;

		/// The amount to reward message relayers
		#[pallet::constant]
		type Reward: Get<BalanceOf<Self>>;

		/// XCM message sender
		type XcmSender: SendXcm;

		// Address of the Gateway contract
		#[pallet::constant]
		type GatewayAddress: Get<H160>;

		/// Convert inbound message to XCM
		type MessageConverter: ConvertMessage;

		type WeightInfo: WeightInfo;

		#[cfg(feature = "runtime-benchmarks")]
		type Helper: BenchmarkHelper<Self>;

		/// Convert a weight value into balance type.
		type WeightToFee: WeightToFee<Balance = BalanceOf<Self>>;
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T> {
		/// A message was received from Ethereum
		MessageReceived {
			/// The destination parachain
			dest: ParaId,
			/// The message nonce
			nonce: u64,
			/// ID of the XCM message which was forwarded to the final destination parachain
			message_id: [u8; 32],
		},
		/// Set OperatingMode
		OperatingModeChanged { mode: BasicOperatingMode },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Message came from an invalid outbound channel on the Ethereum side.
		InvalidGateway,
		/// Message has an invalid envelope.
		InvalidEnvelope,
		/// Message has an unexpected nonce.
		InvalidNonce,
		/// Message has an invalid payload.
		InvalidPayload,
		/// The max nonce for the type has been reached
		MaxNonceReached,
		/// Cannot convert location
		InvalidAccountConversion,
		/// Pallet is halted
		Halted,
		/// Message verification error,
		Verification(VerificationError),
		/// XCMP send failure
		Send(SendError),
		/// Message conversion error
		ConvertMessage(ConvertMessageError),
	}

	#[derive(Clone, Encode, Decode, Eq, PartialEq, Debug, TypeInfo, PalletError)]
	pub enum SendError {
		NotApplicable,
		NotRoutable,
		Transport,
		DestinationUnsupported,
		ExceedsMaxMessageSize,
		MissingArgument,
		Fees,
	}

	impl<T: Config> From<XcmpSendError> for Error<T> {
		fn from(e: XcmpSendError) -> Self {
			match e {
				XcmpSendError::NotApplicable => Error::<T>::Send(SendError::NotApplicable),
				XcmpSendError::Unroutable => Error::<T>::Send(SendError::NotRoutable),
				XcmpSendError::Transport(_) => Error::<T>::Send(SendError::Transport),
				XcmpSendError::DestinationUnsupported =>
					Error::<T>::Send(SendError::DestinationUnsupported),
				XcmpSendError::ExceedsMaxMessageSize =>
					Error::<T>::Send(SendError::ExceedsMaxMessageSize),
				XcmpSendError::MissingArgument => Error::<T>::Send(SendError::MissingArgument),
				XcmpSendError::Fees => Error::<T>::Send(SendError::Fees),
			}
		}
	}

	/// The current nonce for each parachain
	#[pallet::storage]
	pub type Nonce<T: Config> = StorageMap<_, Twox64Concat, ParaId, u64, ValueQuery>;

	/// The current operating mode of the pallet.
	#[pallet::storage]
	#[pallet::getter(fn operating_mode)]
	pub type OperatingMode<T: Config> = StorageValue<_, BasicOperatingMode, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Submit an inbound message originating from the Gateway contract on Ethereum
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::submit())]
		pub fn submit(origin: OriginFor<T>, message: Message) -> DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(!Self::operating_mode().is_halted(), Error::<T>::Halted);

			// submit message to verifier for verification
			T::Verifier::verify(&message).map_err(|e| Error::<T>::Verification(e))?;

			let log = Log::decode(&mut message.data.as_slice())
				.map_err(|_| Error::<T>::InvalidEnvelope)?;

			// Decode log into an Envelope
			let envelope = Envelope::try_from(log).map_err(|_| Error::<T>::InvalidEnvelope)?;

			// Verify that the message was submitted from the known Gateway contract
			ensure!(T::GatewayAddress::get() == envelope.gateway, Error::<T>::InvalidGateway,);

			// Verify message nonce
			<Nonce<T>>::try_mutate(envelope.dest, |nonce| -> DispatchResult {
				if *nonce == u64::MAX {
					return Err(Error::<T>::MaxNonceReached.into())
				}
				if envelope.nonce != nonce.saturating_add(1) {
					Err(Error::<T>::InvalidNonce.into())
				} else {
					*nonce = nonce.saturating_add(1);
					Ok(())
				}
			})?;

			// Reward relayer from the sovereign account of the destination parachain
			// Expected to fail if sovereign account has no funds
			let sovereign_account = sibling_sovereign_account::<T>(envelope.dest);
			let refund = T::WeightToFee::weight_to_fee(&T::WeightInfo::submit());
			T::Token::transfer(
				&sovereign_account,
				&who,
				refund.saturating_add(T::Reward::get()),
				Preservation::Preserve,
			)?;

			// Decode message into XCM
			let xcm = match inbound::VersionedMessage::decode_all(&mut envelope.payload.as_ref()) {
				Ok(message) => Self::do_convert(envelope.message_id, message)?,
				Err(_) => return Err(Error::<T>::InvalidPayload.into()),
			};

			// Attempt to send XCM to a dest parachain
			let message_id = Self::send_xcm(xcm, envelope.dest)?;

			Self::deposit_event(Event::MessageReceived {
				dest: envelope.dest,
				nonce: envelope.nonce,
				message_id,
			});

			Ok(())
		}

		/// Halt or resume all pallet operations. May only be called by root.
		#[pallet::call_index(1)]
		#[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
		pub fn set_operating_mode(
			origin: OriginFor<T>,
			mode: BasicOperatingMode,
		) -> DispatchResult {
			ensure_root(origin)?;
			OperatingMode::<T>::set(mode);
			Self::deposit_event(Event::OperatingModeChanged { mode });
			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn do_convert(
			message_id: H256,
			message: inbound::VersionedMessage,
		) -> Result<Xcm<()>, Error<T>> {
			let mut xcm =
				T::MessageConverter::convert(message).map_err(|e| Error::<T>::ConvertMessage(e))?;
			// Append the message id as an XCM topic
			xcm.inner_mut().extend(vec![SetTopic(message_id.into())]);
			Ok(xcm)
		}

		pub fn send_xcm(xcm: Xcm<()>, dest: ParaId) -> Result<XcmHash, Error<T>> {
			let dest = MultiLocation { parents: 1, interior: X1(Parachain(dest.into())) };
			let (xcm_hash, _) = send_xcm::<T::XcmSender>(dest, xcm).map_err(Error::<T>::from)?;
			Ok(xcm_hash)
		}
	}
}
