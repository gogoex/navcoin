// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_WALLET_HELPERS_H
#define NAVCOIN_BLSCT_WALLET_HELPERS_H

#include <blsct/arith/mcl/mcl.h>
#include <blsct/public_key.h>
#include <blsct/wallet/address.h>
#include <hash.h>
#include <pubkey.h>

namespace blsct {

MclG1Point CalculateNonce(
    const MclG1Point& blindingPubKey,  // (F)
    const MclScalar& viewKey   // (A)
);

// lower 32 bits of hashed nonce
uint64_t CalculateViewTag(
    const MclG1Point& blindingPubKey, // (F)
    const MclScalar& viewKey  // (A)
);

CKeyID CalculateHashId(
    const MclG1Point& blindingPubKey,  // (F)
    const MclG1Point& spendingKey,  // (E) = blsctData.spendingKey
    const MclScalar& viewKey  // (A)?
);

// Generates the exponent part of the blsctData.spendingKey point
// i.e. multiplying the base point by the return value yields blsctData.spendingKey
MclScalar CalculatePrivateSpendingKey(
    const MclG1Point& blindingPubKey, // (F) = blsctData.blindingKey = (D) * subaddr.spendingKey
    const MclScalar& viewKey,     // (A)
    const MclScalar& spendingKey, // (B)
    const int64_t& account,  // (C).account
    const uint64_t& address  // (C).address
);

SubAddress DeriveSubAddress(
    const PrivateKey& viewKey,  // (A)
    const PublicKey& spendKey,  // (B) * base point
    const SubAddressIdentifier& subAddressId // (C)
);

/* Key derivation functions */
MclScalar GenRandomSeed();

MclScalar FromSeedToChildKey(const MclScalar& seed);

MclScalar FromChildToTransactionKey(const MclScalar& childKey);

// Generates a master blinding key used to derive blinding keys on the user side
// Child blindingKeys are to be used as the blinding key in blsct::UnsignedOutput
//
// A derived blindingKey is referred to as (D) in this header file
MclScalar FromChildToMasterBlindingKey(const MclScalar& childKey);

// TO BE MADE CLEAR
MclScalar FromChildToTokenKey(const MclScalar& childKey);

// Referred to as (A) in this header file
MclScalar FromTransactionToViewKey(const MclScalar& transactionKey);

// Referred to as (B) in this header file
MclScalar FromTransactionToSpendingKey(const MclScalar& transactionKey);

} // namespace blsct

#endif // NAVCOIN_BLSCT_WALLET_HELPERS_H
