// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
#define NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

#include "blsct/private_key.h"
#include "blsct/public_key.h"
#include "blsct/wallet/address.h"
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/elements.h>
#include <blsct/range_proof/setup.h>
#include <cstdint>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* constants */
#define PUBLIC_KEY_SIZE 48
#define DOUBLE_PUBLIC_KEY_SIZE 96
#define ENCODED_DPK_SIZE 165
#define SCALAR_SIZE 32
#define POINT_SIZE 48
#define PROOF_SIZE 1019
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define VIEW_TAG_SIZE 8
#define KEY_ID_SIZE 20

/* TODO drop this */
#define UNKNOWN_SIZE 100

/* return codes */
#define BLSCT_RESULT uint8_t
#define BLSCT_SUCCESS 0
#define BLSCT_FAILURE 1
#define BLSCT_EXCEPTION 2
#define BLSCT_BAD_DPK_SIZE 10
#define BLSCT_UNKNOWN_ENCODING 11
#define BLSCT_VALUE_OUTSIDE_THE_RANGE 12
#define BLSCT_DID_NOT_RUN_TO_COMPLETION 13

/*
 * API designed for JavaScript, Python, C, Rust, and Golang
 * with primary focus on JavaScript, Python, and C
 */

#ifdef __cplusplus
extern "C" {
#endif

enum Chain {
    MainNet,
    TestNet,
    SigNet,
    RegTest
};

using Point = Mcl::Point;
using Scalar = Mcl::Scalar;
using Scalars = Elements<Scalar>;

typedef uint8_t BlsctKeyId[KEY_ID_SIZE];  // serialization of CKeyID which is based on uint160
typedef uint8_t BlsctPoint[POINT_SIZE];
typedef uint8_t BlsctPrivKey[blsct::PrivateKey::SIZE];
typedef uint8_t BlsctPubKey[blsct::PublicKey::SIZE];
typedef uint8_t BlsctRangeProof[PROOF_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctSubAddr[blsct::SubAddress::SIZE];
typedef uint8_t BlsctSubAddrId[blsct::SubAddressIdentifier::SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];
typedef uint8_t BlsctViewTag[VIEW_TAG_SIZE];

enum AddressEncoding {
    Bech32,
    Bech32M
};

bool blsct_init(enum Chain chain);

/*
 * blsct_addr: a null-terminated c-style string of length ENCODED_DPK_SIZE
 * ser_dpk: a 48-byte vk followed by a 48-byte sk
 */
uint8_t blsct_decode_address(
    const char* blsct_addr,
    uint8_t ser_dpk[ENCODED_DPK_SIZE]
);

/*
 * ser_dpk: a 48-byte vk followed by a 48-byte sk
 * blsct_addr: a buffer of size at least ENCODED_DPK_SIZE + 1
 */
BLSCT_RESULT blsct_encode_address(
    const uint8_t ser_dpk[ENCODED_DPK_SIZE],
    char* blsct_addr,
    enum AddressEncoding encoding
);

BLSCT_RESULT blsct_build_range_proof(
    const uint64_t uint64_vs[],
    const size_t num_uint64_vs,
    const BlsctPoint blsct_nonce,
    const char* blsct_message,
    const size_t blsct_message_size,
    const BlsctTokenId blsct_token_id,
    BlsctRangeProof blsct_range_proof
);

BLSCT_RESULT blsct_verify_range_proof(
    const BlsctRangeProof blsct_range_proofs[],
    const size_t num_blsct_range_proofs,
    bool* is_valid
);

void blsct_uint64_to_blsct_uint256(
    const uint64_t n,
    BlsctUint256 uint256
);

void blsct_generate_token_id(
    const BlsctUint256 token,
    BlsctTokenId blsct_token_id,
    const uint64_t subid = UINT64_MAX
);

/* holds both request (in) and result (out) */
typedef struct {
    BlsctRangeProof range_proof; /* in */
    BlsctPoint nonce; /* in */
    bool is_succ; /* out */
    uint64_t amount;  /* out */
    char msg[range_proof::Setup::max_message_size]; /* out */
    size_t msg_size; /* out */
} BlsctAmountRecoveryRequest;

/* returns false if exception is thrown. otherwise returns true */
BLSCT_RESULT blsct_recover_amount(
    BlsctAmountRecoveryRequest blsct_amount_recovery_reqs[],
    const size_t num_reqs
);

/* Point/Scalar generation functions */

void blsct_gen_point_from_seed(
    const uint8_t seed[],
    const size_t seed_len,
    BlsctPoint* blsct_point
);

void blsct_gen_random_point(
    BlsctPoint blsct_point
);

void blsct_gen_random_non_zero_scalar(
    BlsctScalar blsct_scalar
);

/* helper functions to build a transaction */

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blinding_key,
    const BlsctScalar view_key,
    BlsctViewTag blsct_view_tag
);

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
);

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_key,
    const BlsctScalar blsct_view_key,
    const BlsctScalar blsct_spending_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
);

BLSCT_RESULT blsct_calculate_nonce(
    const BlsctPoint blsct_blinding_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blect_nonce
);

BLSCT_RESULT blsct_derive_sub_addr(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spend_key,
    const BlsctSubAddrId blsct_sub_addr_id,
    BlsctSubAddr blsct_sub_addr
);

/*
seed
 +---> child key
        +--------> blinding key
        +--------> token key
        +--------> tx key
                    +----> view key
                    +----> spend key
*/

BLSCT_RESULT blsct_gen_random_seed(
    BlsctScalar blsct_seed
);

// keys derived from seed
BLSCT_RESULT blsct_from_seed_to_child_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_child_key
);

// keys derived from child key
BLSCT_RESULT blsct_from_child_key_to_tx_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_to_tx_key
);

BLSCT_RESULT blsct_from_child_key_to_blinding_key(
    const BlsctScalar seed,
    BlsctScalar blsct_blinding_key
);

BLSCT_RESULT blsct_from_child_key_to_token_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_token_key
);

// keys derived from tx key
BLSCT_RESULT blsct_from_tx_key_to_view_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_view_key
);

BLSCT_RESULT blsct_from_tx_key_to_spend_key(
    const BlsctScalar seed,
    BlsctScalar blxct_tspend_key
);

/*
- blsct signatures creation/verification
blsct_sign
blsct_verify_signature

- transaction serialization/deserialization
blsct_serialize_transaction
blsct_deserialize_transaction
*/

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

