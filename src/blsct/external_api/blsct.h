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
#define DOUBLE_PUBLIC_KEY_SIZE PUBLIC_KEY_SIZE * 2
#define SUBADDRESS_SIZE DOUBLE_PUBLIC_KEY_SIZE
#define SUBADDRESS_ID_SIZE 16
#define ENCODED_DPK_STR_SIZE 165
#define ENCODED_DPK_STR_BUF_SIZE ENCODED_DPK_STR_SIZE + 1 /* 1 for c-str null termination */
#define KEY_ID_SIZE 20
#define POINT_SIZE 48
#define SCALAR_SIZE 32
#define PROOF_SIZE 1019  // needs to be at least 1019
#define PRIVATE_KEY_SIZE 32
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define VIEW_TAG_SIZE 8
#define UINT16_SIZE 2
#define CTXOUT_BLSCT_DATA_SIZE \
        POINT_SIZE * 3 + \
        RANGE_PROOF_SIZE + \
        UINT16_SIZE
#define NORMAL_CSCRIPT_SIZE 1
#define OP_SIZE 1
#define STAKED_COMMITMENT_CSCRIPT_SIZE \
        OP_SIZE * 3 + \
        PROOF_SIZE
#define CTXOUT_SIZE CAMOUNT_SIZE + \
        CSCRIPT_SIZE + \
        CTXOUT_BLSCT_DATA_SIZE + \
        TOKEN_ID_SIZE
#define UNSIGNED_OUTPUT_SIZE SCALAR_SIZE * 3 + CTXOUT_SIZE
#define OUT_POINT_SIZE 36
#define SIGNATURE_SIZE 96
#define SCRIPT_SIZE 28

/* return codes */
#define BLSCT_RESULT uint8_t
#define BLSCT_SUCCESS 0
#define BLSCT_FAILURE 1
#define BLSCT_EXCEPTION 2
#define BLSCT_BAD_DPK_SIZE 10
#define BLSCT_UNKNOWN_ENCODING 11
#define BLSCT_VALUE_OUTSIDE_THE_RANGE 12
#define BLSCT_DID_NOT_RUN_TO_COMPLETION 13
#define BLSCT_BUFFER_TOO_SMALL 14
#define BLSCT_IN_AMOUNT_ERROR 15
#define BLSCT_OUT_AMOUNT_ERROR 16
#define BLSCT_BAD_OUT_TYPE 17

#define TRY_DEFINE_MCL_POINT_FROM(src, dest) \
    Point dest; \
    if (!from_blsct_point_to_mcl_point(src, dest)) { \
        return BLSCT_FAILURE; \
    }

#define TRY_DEFINE_MCL_SCALAR_FROM(src, dest) \
    Scalar dest; \
    from_blsct_scalar_to_mcl_scalar(src, dest)

#define SERIALIZE_AND_COPY(src, dest) \
{ \
    auto src_vec = src.GetVch(); \
    std::memcpy(dest, &src_vec[0], src_vec.size()); \
}

#define UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(src, src_size, dest) \
{ \
    Span buf(src, src_size); \
    DataStream st{}; \
    st << buf; \
    dest.Unserialize(st); \
}

#define SERIALIZE_AND_COPY_WITH_STREAM(src, dest) \
{ \
    DataStream st{}; \
    src.Serialize(st); \
    std::memcpy(dest, st.data(), st.size()); \
}

#define UNSERIALIZE_AND_COPY_WITH_STREAM(src, src_size, dest) \
{ \
    DataStream st{}; \
    for (size_t i=0; i<src_size; ++i) { \
        st << src[i]; \
    } \
    dest.Unserialize(st); \
}

#define BLSCT_COPY(src, dest) std::memcpy(dest, src, sizeof(dest))

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

enum TxOutputType {
    Normal,
    StakedCommitment
};

enum AddressEncoding {
    Bech32,
    Bech32M
};

using Point = Mcl::Point;
using Scalar = Mcl::Scalar;
using Scalars = Elements<Scalar>;

typedef uint8_t BlsctKeyId[KEY_ID_SIZE];  // serialization of CKeyID which is based on uint160
typedef uint8_t BlsctPoint[POINT_SIZE];
typedef uint8_t BlsctPrivKey[PRIVATE_KEY_SIZE];
typedef uint8_t BlsctPubKey[PUBLIC_KEY_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef char BlsctAddrStr[ENCODED_DPK_STR_BUF_SIZE];
typedef uint8_t BlsctRangeProof[PROOF_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctSubAddr[SUBADDRESS_SIZE];
typedef uint8_t BlsctSubAddrId[SUBADDRESS_ID_SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];
typedef uint8_t BlsctViewTag[VIEW_TAG_SIZE];
typedef uint8_t BlsctOutPoint[OUT_POINT_SIZE];
typedef uint8_t BlsctSignature[SIGNATURE_SIZE];

/* holds both request (in) and result (out) */
typedef struct {
    BlsctRangeProof range_proof; /* in */
    BlsctPoint nonce; /* in */
    bool is_succ; /* out */
    uint64_t amount;  /* out */
    char msg[range_proof::Setup::max_message_size]; /* out */
    size_t msg_size; /* out */
} BlsctAmountRecoveryRequest;

typedef struct {
    uint64_t amount;
    uint64_t gamma;
    BlsctScalar spending_key;
    BlsctTokenId token_id;
    BlsctOutPoint out_point;
    bool rbf;
} BlsctTxIn;

typedef struct {
    BlsctSubAddr dest;
    uint64_t amount;
    const char* memo;  /* expected to be a null-terminatd c-str */
    BlsctTokenId token_id;
    TxOutputType output_type;
    uint64_t min_stake;
} BlsctTxOut;

typedef struct {
    uint8_t script[SCRIPT_SIZE];
    size_t size;
} BlsctScript;

typedef struct {
    int64_t value;
    BlsctScript script_pubkey;
    // CTxOutBLSCTData blsctData;
    BlsctTokenId token_id;
} BlsctCTxOut;

typedef struct {
    BlsctUint256 hash; // Txid
    uint32_t n;
} BlsctCOutPoint;

typedef struct {
    uint8_t* buf;
    size_t size;
} BlsctVector;

typedef struct {
    BlsctVector* stack;
    size_t size;
} BlsctScriptWitness;

typedef struct {
    BlsctCOutPoint prev_out;
    BlsctScript script_sig;
    uint32_t sequence;
    BlsctScriptWitness script_witness;
} BlsctCTxIn;

typedef struct {
    int32_t version;
    uint32_t lock_time;
    BlsctSignature tx_sig;
    BlsctCTxIn* ins;
    size_t num_ins;
    BlsctCTxOut* outs;
    size_t num_outs;
} BlsctTransaction;

typedef struct {
    uint64_t token;
    uint64_t subid;
} BlsctTokenIdUint64;

bool blsct_init(enum Chain chain);

void blsct_gen_out_point(
    const char* tx_id_c_str,
    const uint32_t n,
    BlsctOutPoint blsct_out_point
);

void blsct_uint64_to_blsct_uint256(
    const uint64_t n,
    BlsctUint256 uint256
);

/* Point/Scalar generation functions */

bool blsct_is_valid_point(BlsctPoint blsct_point);

void blsct_gen_random_point(
    BlsctPoint blsct_point
);

void blsct_gen_random_scalar(
    BlsctScalar blsct_scalar
);

void blsct_gen_scalar(
    const uint64_t n,
    BlsctScalar blsct_scalar
);

bool blsct_from_point_to_blsct_point(
    const Point& point,
    BlsctPoint blsct_point
);

/*
 * [out] blsct_pub_key: randomly generated public key
 */
void blsct_gen_random_public_key(
    BlsctPubKey blsct_pub_key
);

/*
 * [in] src_str: source byte string
 * [in] src_str_size: the size of the source byte string
 * [out] public_key: randomly generated Public key
 */
void blsct_hash_byte_str_to_public_key(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey blsct_pub_key
);

void blsct_priv_key_to_pub_key(
    const BlsctPrivKey blsct_priv_key,
    BlsctPubKey blsct_pub_key
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

void blsct_gen_dpk_with_keys_and_sub_addr_id(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spending_key,
    const int64_t account,
    const uint64_t address,
    BlsctDoublePubKey dpk
);

void blsct_dpk_to_sub_addr(
    const BlsctDoublePubKey blsct_dpk,
    BlsctSubAddr blsct_sub_addr
);

/*
 * [in] blsct_enc_addr: a null-terminated c-style string of length ENCODED_DPK_SIZE
 * [out] blsct_dpk: serialized double public key
 */
uint8_t blsct_decode_address(
    const BlsctAddrStr blsct_enc_addr,
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
void blsct_gen_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid,
    BlsctTokenId blsct_token_id
);

/* [in] token
 * [out] blsct_token_id
 */
void blsct_gen_token_id(
    const uint64_t token,
    BlsctTokenId blsct_token_id
);

void blsct_gen_default_token_id(
    BlsctTokenId blsct_token_id
);

/* returns false and set uint64 max to token if token > uint64_t max
 */
bool blsct_decode_token_id(
    const BlsctTokenId blsct_token_id,
    BlsctTokenIdUint64* blsct_token_id_uint64
);

/* [out] blsct_priv_key
 */
void blsct_gen_random_priv_key(
    BlsctScalar blsct_priv_key
);

/* [in] byte string of size 32
   [out] blsct_priv_key
 */
void blsct_gen_priv_key(
    const uint8_t priv_key[PRIVATE_KEY_SIZE],
    BlsctScalar blsct_priv_key
);

/* attempts to recover all requests in the given request array
 * and returns the recovery results in the same request array
 * returns failure if exception is thrown and success otherwise
 * */
BLSCT_RESULT blsct_recover_amount(
    BlsctAmountRecoveryRequest blsct_amount_recovery_reqs[],
    const size_t num_reqs
);

void blsct_sign_message(
    const BlsctPrivKey blsct_priv_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    BlsctSignature blsct_signature
);

bool blsct_verify_msg_sig(
    const BlsctPubKey blsct_pub_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    const BlsctSignature blsct_signature
);

void blsct_build_tx_in(
    const uint64_t amount,
    const uint64_t gamma,
    const BlsctScalar spending_key,
    const BlsctTokenId token_id,
    const BlsctOutPoint out_point,
    const bool rbf,
    BlsctTxIn* const tx_in
);

void blsct_build_tx_out(
    const BlsctSubAddr blsct_dest,
    const uint64_t amount,
    const char* memo,
    const BlsctTokenId blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake,
    BlsctTxOut* const tx_out
);

BLSCT_RESULT blsct_build_tx(
    const BlsctTxIn blsct_tx_ins[],
    const size_t num_blsct_tx_ins,
    const BlsctTxOut blsct_tx_outs[],
    const size_t num_blsct_tx_outs,
    uint8_t* ser_tx,
    size_t* ser_tx_size, /* [in] size of serialized_tx buffer [out] size of the generated serialized tx */
    size_t* in_amount_err_index, /* holds the first index of the tx_in whose amount exceeds the maximum */
    size_t* out_amount_err_index /* holds the first index of the tx_out whose amount exceeds the maximum */
);

void blsct_deserialize_tx(
    const uint8_t* ser_tx,
    const size_t ser_tx_size,
    BlsctTransaction** const blsct_tx
);

void blsct_dispose_tx(
    BlsctTransaction** const blsct_tx
);

/* helper functions to build a transaction */

/*
seed (scalar)
 +---> child key (scalar)
        +--------> blinding key (scalar)
        +--------> token key (scalar)
        +--------> tx key (scalar)
                    +----> view key (scalar)
                    +----> spending key (scalar)
*/

/* key derivation functions */

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

BLSCT_RESULT blsct_from_child_key_to_master_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_master_blinding_key
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

BLSCT_RESULT blsct_from_tx_key_to_spending_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_spending_key
);

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_pub_key,
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
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blect_nonce
);

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blinding_pub_key,
    const BlsctScalar view_key,
    BlsctViewTag blsct_view_tag
);

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
);

/*
- transaction serialization/deserialization
blsct_serialize_transaction
blsct_deserialize_transaction
*/

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

