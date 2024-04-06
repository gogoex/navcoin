// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
#define NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

#include "blsct/double_public_key.h"
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
#define ENCODED_DPK_STR_BUF_SIZE 166 // includes 1 is for c-str null termination
#define SCALAR_SIZE 32
#define POINT_SIZE 48
#define PROOF_SIZE 1019
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define VIEW_TAG_SIZE 8
#define KEY_ID_SIZE 20

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
typedef uint8_t BlsctDoublePubKey[blsct::DoublePublicKey::SIZE];
typedef char BlsctEncAddr[ENCODED_DPK_STR_BUF_SIZE];
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
 * [out] public_key: randomly generated Public key
 */
void blsct_gen_random_public_key(
    BlsctPubKey public_key
);

/*
 * [in] src_str: source byte string
 * [in] src_str_size: the size of the source byte string
 * [out] public_key: randomly generated Public key
 */
void blsct_gen_public_key_from_byte_str(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey public_key
);

/*
 * [in] pk1: public key
 * [in] pk2: public key
 * [out] dpk: double public key generated from pk1 and pk2
 */
void blsct_gen_double_public_key(
    const BlsctPubKey blsct_pk1,
    const BlsctPubKey blsct_pk2,
    BlsctDoublePubKey blsct_dpk
);

/*
 * [in] blsct_enc_addr: a null-terminated c-style string of length ENCODED_DPK_SIZE
 * [out] blsct_dpk: serialized double public key
 */
uint8_t blsct_decode_address(
    const BlsctEncAddr blsct_enc_addr,
    uint8_t blsct_dpk[DOUBLE_PUBLIC_KEY_SIZE]
);

/*
 * [in] addr: a serialized double public key
 * [in] encoding: Bech32 or Bech32M
 * [out] blsct_addr: a buffer to store c-str of size at least
 *       ENCODED_DPK_SIZE + 1 (1 is for c-str null termination)
 */
BLSCT_RESULT blsct_encode_address(
    const BlsctDoublePubKey blsct_dpk,
    const enum AddressEncoding encoding,
    char* blsct_addr_str
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

/* [in] token
 * [in] subid
 * [out] blsct_token_id
 */
void blsct_generate_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid,
    BlsctTokenId blsct_token_id
);

/* [in] token
 * [out] blsct_token_id
 */
void blsct_generate_token_id(
    const uint64_t token,
    BlsctTokenId blsct_token_id
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

// // TODO gen public key from seed instead?
// void blsct_gen_point_from_seed(
//     const uint8_t seed[],
//     const size_t seed_len,
//     BlsctPoint blsct_point
// );
//
// // TODO gen random public key instead?
// void blsct_gen_random_point(
//     BlsctPoint blsct_point
// );

/* helper functions to build a transaction */

/*
seed (scalar)
 +---> child key (scalar)
        +--------> blinding key (point) // temp. was scalar
        +--------> token key (scalar)
        +--------> tx key (scalar)
                    +----> view key (priv key) // temp. was scalar
                    +----> spending key (scalar)
                           +----> spending key (point) // temp. new
                           +----> spending key (pub key) // temp. new

blinding key (point) + view key -> nonce (point)
blinding key (point) + view key -> nonce -> view tag (uint64)
blinding key (point) + spending key (point: missing) + view key -> hash id (key id)
blinding key (point) + spending key (scalar) + view key + account + addr -> priv spending key (scalar)
view key (priv key) + spend key (pub key: missing) + sub addr id -> sub addr (sub addr)
*/

/* key derivation functions */

/* seed generators */
void blsct_gen_random_seed(
    BlsctScalar blsct_scalar
);

/* from seed */
BLSCT_RESULT blsct_from_seed_to_child_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_child_key
);

/* from child_key */
BLSCT_RESULT blsct_from_child_key_to_tx_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_to_tx_key
);

BLSCT_RESULT blsct_from_child_key_to_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctPoint blsct_blinding_key
);

BLSCT_RESULT blsct_from_child_key_to_token_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_token_key
);

/* from tx_key */
BLSCT_RESULT blsct_from_tx_key_to_view_key(
    const BlsctScalar blsct_tx_key,
    BlsctPrivKey blsct_view_key
);

BLSCT_RESULT blsct_from_tx_key_to_raw_spending_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_raw_spending_key
);

/* from raw_spending_key */
BLSCT_RESULT blsct_from_raw_spending_key_to_pt_spending_key(
    const BlsctScalar blsct_raw_spending_key,
    BlsctPoint blsct_pt_spending_key
);

BLSCT_RESULT blsct_from_raw_spending_key_to_pk_spending_key(
    const BlsctScalar blsct_raw_spending_key,
    BlsctPubKey blsct_pk_spending_key
);

/* keys generated from comibnation of keys or other data */
BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
);

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
);

BLSCT_RESULT blsct_derive_sub_addr(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spend_key,
    const BlsctSubAddrId blsct_sub_addr_id,
    BlsctSubAddr blsct_sub_addr
);

BLSCT_RESULT blsct_calculate_nonce(
    const BlsctPoint blsct_blinding_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blect_nonce
);

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blinding_key,
    const BlsctScalar view_key,
    BlsctViewTag blsct_view_tag
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

