#include "blsct/common.h"
#include "blsct/signature.h"
#include "blsct/wallet/txfactory.h"
#include "primitives/transaction.h"
#include <blsct/bech32_mod.h>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs/range_proof.h>
#include <blsct/range_proof/bulletproofs/range_proof_logic.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/txfactory_global.h>
#include <common/args.h>

#include <cstring>
#include <streams.h>

#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

static std::string g_chain;
static std::mutex g_init_mutex;
static bulletproofs::RangeProofLogic<Mcl>* g_rpl;
static bool g_is_little_endian;

extern "C" {

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

static bool is_little_endian() {
    uint16_t n = 1;
    uint8_t* p = (uint8_t*) &n;
    return *p == 1;
}

bool blsct_init(enum Chain chain)
{
    {
        std::lock_guard<std::mutex> lock(g_init_mutex);
        if (!g_chain.empty()) return true;

        Mcl::Init for_side_effect_only;

        g_rpl = new bulletproofs::RangeProofLogic<Mcl>();
        g_is_little_endian = is_little_endian();

        switch (chain) {
            case MainNet:
                g_chain = blsct::bech32_hrp::Main;
                break;

            case TestNet:
                g_chain = blsct::bech32_hrp::TestNet;
                break;

            case SigNet:
                g_chain = blsct::bech32_hrp::SigNet;
                break;

            case RegTest:
                g_chain = blsct::bech32_hrp::RegTest;
                break;

            default:
                return false;
        }
        return true;
    }
}

static void deserialize_blsct_dpk(
    const BlsctDoublePubKey blsct_dpk,
    blsct::DoublePublicKey dpk
) {
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_dpk,
        DOUBLE_PUBLIC_KEY_SIZE,
        dpk
    );
}

static void deserialize_blsct_token_id(
    const BlsctTokenId blsct_token_id,
    TokenId token_id
) {
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_token_id,
        TOKEN_ID_SIZE,
        token_id
    );
}

static void deserialize_blsct_scalar(
    const BlsctScalar blsct_scalar,
    Scalar scalar
) {
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_scalar,
        SCALAR_SIZE,
        scalar
    );
}

static void deserialize_blsct_out_point(
    const BlsctOutPoint blsct_out_point,
    COutPoint out_point
) {
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_out_point,
        OUT_POINT_SIZE,
        out_point
    );
}

void blsct_gen_out_point(
    const char* tx_id,
    const size_t tx_id_size,
    const uint32_t n,
    BlsctOutPoint blsct_out_point
) {
    auto hash = uint256(11);
    const auto txid = Txid::FromUint256(hash);
    COutPoint out_point{txid, n};

    SERIALIZE_AND_COPY_WITH_STREAM(
        out_point,
        blsct_out_point
    );
}

static blsct::PrivateKey blsct_scalar_to_priv_key(
    const BlsctScalar blsct_scalar
) {
    Scalar scalar;
    std::vector<uint8_t> vec {blsct_scalar, blsct_scalar + Scalar::SERIALIZATION_SIZE};
    scalar.SetVch(vec);

    blsct::PrivateKey priv_key(scalar);
    return priv_key;
}

void blsct_gen_random_priv_key(
    BlsctScalar blsct_priv_key
) {
    Scalar priv_key = Scalar::Rand();
    SERIALIZE_AND_COPY(priv_key, blsct_priv_key);
}

void blsct_gen_priv_key(
    const uint8_t priv_key[PRIVATE_KEY_SIZE],
    BlsctScalar blsct_priv_key
) {
    std::vector<uint8_t> vec { priv_key, priv_key + PRIVATE_KEY_SIZE };
    Scalar tmp(vec);
    SERIALIZE_AND_COPY(tmp, blsct_priv_key);
}

void blsct_uint64_to_blsct_uint256(
    const uint64_t n,
    BlsctUint256 blsct_uint256
) {
    std::memset(blsct_uint256, 0, UINT256_SIZE);
    uint64_t tmp = n;

    // BlsctUint256 is little-endian
    for (size_t i=0; i<8; ++i) {
        blsct_uint256[g_is_little_endian ? i : 32 - i] =
            static_cast<uint8_t>(tmp & 0xFF);
        tmp >>= 8;
    }
}

bool blsct_is_valid_point(BlsctPoint blsct_point)
{
    std::vector<uint8_t> ser_point {blsct_point, blsct_point + POINT_SIZE};
    Point p;
    p.SetVch(ser_point);
    return p.IsValid();
}

void blsct_gen_scalar(
    const uint64_t n,
    BlsctScalar blsct_scalar
) {
    Scalar scalar_n(n);
    SERIALIZE_AND_COPY(scalar_n, blsct_scalar);
}

void blsct_gen_random_public_key(
    BlsctPubKey blsct_pub_key
) {
    auto vec = Point::Rand().GetVch();
    blsct::PublicKey pub_key(vec);
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);
}

void blsct_hash_byte_str_to_public_key(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey blsct_pub_key
) {
    std::vector<uint8_t> src_vec {src_str, src_str + src_str_size};
    auto point = Point::HashAndMap(src_vec);
    SERIALIZE_AND_COPY(point, blsct_pub_key);
}

void blsct_gen_double_public_key(
    const BlsctPubKey blsct_pk1,
    const BlsctPubKey blsct_pk2,
    BlsctDoublePubKey blsct_dpk
) {
    blsct::PublicKey pk1, pk2;
    std::vector<uint8_t> blsct_pk1_vec {
        blsct_pk1,
        blsct_pk1 + blsct::PublicKey::SIZE
    };
    std::vector<uint8_t> blsct_pk2_vec {
        blsct_pk2,
        blsct_pk2 + blsct::PublicKey::SIZE
    };
    pk1.SetVch(blsct_pk1_vec);
    pk2.SetVch(blsct_pk2_vec);

    blsct::DoublePublicKey dpk(pk1, pk2);
    SERIALIZE_AND_COPY(dpk, blsct_dpk);
}

BLSCT_RESULT blsct_decode_address(
    const BlsctAddrStr blsct_addr_str,
    BlsctDoublePubKey blsct_dpk
) {
    try {
        if (strlen(blsct_addr_str) != ENCODED_DPK_STR_SIZE) {
            return BLSCT_BAD_DPK_SIZE;
        }

        std::string addr_str(blsct_addr_str);
        auto maybe_dpk = blsct::DecodeDoublePublicKey(g_chain, addr_str);
        if (maybe_dpk) {
            auto dpk = maybe_dpk.value();
            if (dpk.IsValid()) {
                auto buf = dpk.GetVch();
                std::memcpy(blsct_dpk, &buf[0], DOUBLE_PUBLIC_KEY_SIZE);
                return BLSCT_SUCCESS;
            }
        }
    } catch(...) {}

    return BLSCT_EXCEPTION;
}

BLSCT_RESULT blsct_encode_address(
    const BlsctDoublePubKey blsct_dpk,
    const enum AddressEncoding encoding,
    BlsctAddrStr blsct_enc_addr
) {
    try {
        if (encoding != Bech32 && encoding != Bech32M) {
            return BLSCT_UNKNOWN_ENCODING;
        }
        auto bech32_encoding = encoding == Bech32 ?
            bech32_mod::Encoding::BECH32 : bech32_mod::Encoding::BECH32M;

        std::vector<uint8_t> dpk_vec(blsct_dpk, blsct_dpk + blsct::DoublePublicKey::SIZE);
        auto dpk = blsct::DoublePublicKey(dpk_vec);

        auto enc_dpk_str = EncodeDoublePublicKey(g_chain, bech32_encoding, dpk);
        std::memcpy(blsct_enc_addr, enc_dpk_str.c_str(), ENCODED_DPK_STR_BUF_SIZE);
        return BLSCT_SUCCESS;

    } catch(...) {}

    return BLSCT_EXCEPTION;
}

/* private functions not exposed to outside */
static void blsct_nonce_to_nonce(
    const BlsctPoint blsct_nonce,
    Point& nonce
) {
    std::vector<uint8_t> ser_point(
        blsct_nonce, blsct_nonce + POINT_SIZE
    );
    nonce.SetVch(ser_point);
}

BLSCT_RESULT blsct_build_range_proof(
    const uint64_t uint64_vs[],
    const size_t num_uint64_vs,
    const BlsctPoint blsct_nonce,
    const char* blsct_message,
    const size_t blsct_message_size,
    const BlsctTokenId blsct_token_id,
    BlsctRangeProof blsct_range_proof
) {
    try {
        // uint64_t to Scalar
        Scalars vs;
        for(size_t i=0; i<num_uint64_vs; ++i) {
            if (uint64_vs[i] > INT64_MAX) return BLSCT_VALUE_OUTSIDE_THE_RANGE;
            Mcl::Scalar x(static_cast<int64_t>(uint64_vs[i]));
            vs.Add(x);
        }

        // blsct_nonce to nonce
        Mcl::Point nonce;
        blsct_nonce_to_nonce(blsct_nonce, nonce);

        // blsct_message to message
        std::vector<uint8_t> message(
            blsct_message, blsct_message + blsct_message_size
        );

        // blsct_token_id to token_id
        TokenId token_id;
        {
            DataStream st{};
            std::vector<uint8_t> token_id_vec(
                *blsct_token_id, *blsct_token_id + TOKEN_ID_SIZE
            );
            st << token_id_vec;
            token_id.Unserialize(st);
        }

        // range_proof to blsct_range_proof
        auto range_proof = g_rpl->Prove(
            vs,
            nonce,
            message,
            token_id
        );
        {
            DataStream st{};
            range_proof.Serialize(st);
            std::memcpy(blsct_range_proof, st.data(), st.size());
        }
        return BLSCT_SUCCESS;

    } catch(...) {}

    return BLSCT_EXCEPTION;
}

static void blsct_range_proof_to_range_proof(
    const BlsctRangeProof& blsct_range_proof,
    bulletproofs::RangeProof<Mcl>& range_proof
) {
    DataStream st{};;
    for(size_t i=0; i<PROOF_SIZE; ++i) {
        st << blsct_range_proof[i];
    }
    range_proof.Unserialize(st);
}

BLSCT_RESULT blsct_verify_range_proof(
    const BlsctRangeProof blsct_range_proofs[],
    const size_t num_blsct_range_proofs,
    bool* is_valid
) {
    try {
        // convert blsct_proofs to proofs;
        std::vector<bulletproofs::RangeProof<Mcl>> range_proofs;

        for(size_t i=0; i<num_blsct_range_proofs; ++i) {
            bulletproofs::RangeProof<Mcl> range_proof;
            blsct_range_proof_to_range_proof(
                blsct_range_proofs[i],
                range_proof
            );
            range_proofs.push_back(range_proof);
        }
        *is_valid = g_rpl->Verify(range_proofs);

        return BLSCT_SUCCESS;

    } catch(...) {}

    return BLSCT_EXCEPTION;
}

void blsct_generate_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid,
    BlsctTokenId blsct_token_id
) {
    uint256 token_uint256(token);
    TokenId token_id(token_uint256, subid);
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, blsct_token_id);
}

void blsct_generate_token_id(
    const uint64_t token,
    BlsctTokenId blsct_token_id
) {
    return blsct_generate_token_id_with_subid(
        token,
        UINT64_MAX,
        blsct_token_id
    );
}

BLSCT_RESULT blsct_recover_amount(
    BlsctAmountRecoveryRequest blsct_amount_recovery_reqs[],
    const size_t num_reqs
) {
    try {
        // build AmountRecoveryRequests
        std::vector<bulletproofs::AmountRecoveryRequest<Mcl>> reqs;

        for(size_t i=0; i<num_reqs; ++i) {
            auto& r = blsct_amount_recovery_reqs[i];

            Mcl::Point nonce;
            blsct_nonce_to_nonce(r.nonce, nonce);

            bulletproofs::RangeProof<Mcl> range_proof;
            blsct_range_proof_to_range_proof(
                r.range_proof,
                range_proof
            );

            auto req = bulletproofs::AmountRecoveryRequest<Mcl>::of(
                range_proof,
                nonce
            );
            reqs.push_back(req);
        }

        auto recovery_results = g_rpl->RecoverAmounts(reqs);

        // initially mark all the requests as failed
        for(size_t i=0; i<num_reqs; ++i) {
            blsct_amount_recovery_reqs[i].is_succ = false;
        }

        if (!recovery_results.run_to_completion) {
            return BLSCT_DID_NOT_RUN_TO_COMPLETION;
        }

        // write successful recovery results to corresponding requests
        for(size_t i=0; i<recovery_results.successful_results.size(); ++i) {
            auto result = recovery_results.successful_results[i];

            // pick up the request correspnding to the recovery result
            auto& req = blsct_amount_recovery_reqs[result.idx];
            req.is_succ = true;

            // copy recoverted amount to request
            req.amount = result.amount;

            // copy the recovered message and message size to request
            std::memcpy(
                req.msg,
                result.message.c_str(),
                result.message.size()
            );
            req.msg_size = result.message.size();
        }
        return BLSCT_SUCCESS;

    } catch(...) {}

    return BLSCT_EXCEPTION;
}

void blsct_gen_random_point(
    BlsctPoint blsct_point
) {
    auto x = Point::Rand();
    SERIALIZE_AND_COPY(x, blsct_point);
}

void blsct_gen_random_scalar(
    BlsctScalar blsct_scalar
) {
    auto x = Scalar::Rand(true);
    SERIALIZE_AND_COPY(x, blsct_scalar);
}

void blsct_priv_key_to_pub_key(
    const BlsctPrivKey blsct_priv_key,
    BlsctPubKey blsct_pub_key
) {
    blsct::PrivateKey priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, PRIVATE_KEY_SIZE, priv_key
    );
    auto pub_key = priv_key.GetPublicKey();
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);
}

static inline bool from_blsct_point_to_mcl_point(
    const BlsctPoint blsct_point,
    Point& point
) {
    std::vector<uint8_t> vec(
        blsct_point,
        blsct_point + Point::SERIALIZATION_SIZE
    );
    return point.SetVch(vec);
}

static inline void from_blsct_scalar_to_mcl_scalar(
    const BlsctScalar blsct_scalar,
    Scalar& scalar
) {
    std::vector<uint8_t> vec(
        blsct_scalar,
        blsct_scalar + Scalar::SERIALIZATION_SIZE
    );
    scalar.SetVch(vec);
}

BLSCT_RESULT blsct_derive_sub_addr(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spend_key,
    const BlsctSubAddrId blsct_sub_addr_id,
    BlsctSubAddr blsct_sub_addr
) {
    blsct::PrivateKey view_key;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_view_key,
        blsct::PrivateKey::SIZE,
        view_key
    );

    blsct::PublicKey spend_key;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_spend_key,
        blsct::PublicKey::SIZE,
        spend_key
    );

    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_sub_addr_id,
        blsct::SubAddressIdentifier::SIZE,
        sub_addr_id
    );

    auto sub_addr = blsct::DeriveSubAddress(view_key, spend_key, sub_addr_id);
    SERIALIZE_AND_COPY_WITH_STREAM(
        sub_addr,
        blsct_sub_addr
    );

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_nonce(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blsct_nonce
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto nonce = blsct::CalculateNonce(blinding_pub_key, view_key);
    SERIALIZE_AND_COPY(nonce, blsct_nonce);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_seed_to_child_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_child_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_seed, seed);

    auto child_key = blsct::FromSeedToChildKey(seed);
    SERIALIZE_AND_COPY(child_key, blsct_child_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_child_key_to_tx_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_tx_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    auto tx_key = blsct::FromChildToTransactionKey(child_key);
    SERIALIZE_AND_COPY(tx_key, blsct_tx_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_child_key_to_master_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_master_blinding_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    Scalar master_blinding_key =
        blsct::FromChildToMasterBlindingKey(child_key);

    SERIALIZE_AND_COPY(master_blinding_key, blsct_master_blinding_key);

    return BLSCT_SUCCESS;
};

BLSCT_RESULT blsct_from_child_key_to_token_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_token_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    auto token_key = blsct::FromChildToTokenKey(child_key);
    SERIALIZE_AND_COPY(token_key, blsct_token_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_tx_key_to_view_key(
    const BlsctScalar blsct_tx_key,
    BlsctPrivKey blsct_view_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_tx_key, tx_key);

    auto scalar_view_key =
        blsct::FromTransactionToViewKey(tx_key);
    blsct::PrivateKey view_key(scalar_view_key);

    SERIALIZE_AND_COPY(scalar_view_key, blsct_view_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_tx_key_to_spending_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_spending_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_tx_key, tx_key);

    auto spending_key = blsct::FromTransactionToSpendingKey(tx_key);
    SERIALIZE_AND_COPY(spending_key, blsct_spending_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctViewTag blsct_view_tag
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    *blsct_view_tag = blsct::CalculateViewTag(blinding_pub_key, view_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_POINT_FROM(blsct_spending_key, spending_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto hash_id = blsct::CalculateHashId(blinding_pub_key, spending_key, view_key);
    SERIALIZE_AND_COPY_WITH_STREAM(hash_id, blsct_hash_id);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_spending_key, spending_key);

    auto priv_spending_key = blsct::CalculatePrivateSpendingKey(
        blinding_pub_key,
        view_key,
        spending_key,
        account,
        address
    );
    SERIALIZE_AND_COPY(priv_spending_key, blsct_priv_spending_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_build_transaction(
    const BlsctTxIn blsct_tx_ins[],
    const size_t num_blsct_tx_ins,
    const BlsctTxOut blsct_tx_outs[],
    const size_t num_blsct_tx_outs,
    uint8_t* serialized_tx,
    size_t* serialized_tx_size,
    size_t* in_amount_err_index,
    size_t* out_amount_err_index
) {
    blsct::TxFactoryBase psbt;

    for (size_t i=0; i<num_blsct_tx_ins; ++i) {
        auto tx_in = blsct_tx_ins[i];

        if (tx_in.amount > std::numeric_limits<int64_t>::max()) {
            *in_amount_err_index = i;
            return BLSCT_IN_AMOUNT_ERROR;
        }

        Scalar gamma(tx_in.gamma);

        blsct::PrivateKey spending_key =
            blsct_scalar_to_priv_key(tx_in.spending_key);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.token_id, TOKEN_ID_SIZE, token_id
        );

        COutPoint out_point;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.out_point, OUT_POINT_SIZE, out_point
        );

        psbt.AddInput(
            tx_in.amount,
            gamma,
            spending_key,
            token_id,
            out_point
        );
    }

    for (size_t i=0; i<num_blsct_tx_outs; ++i) {
        auto tx_out = blsct_tx_outs[i];

        if (tx_out.amount > std::numeric_limits<int64_t>::max()) {
            *out_amount_err_index = i;
            return BLSCT_OUT_AMOUNT_ERROR;
        }

        blsct::DoublePublicKey dest;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.destination, DOUBLE_PUBLIC_KEY_SIZE, dest
        );

        std::string memo(tx_out.memo);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.token_id, TOKEN_ID_SIZE, token_id
        );

        blsct::CreateOutputType out_type;
        if (tx_out.type == TxOutputType::Normal) {
            out_type = blsct::CreateOutputType::NORMAL;
        } else if (tx_out.type == TxOutputType::StakedCommitment) {
            out_type = blsct::CreateOutputType::STAKED_COMMITMENT;
        } else {
            return BLSCT_FAILURE;
        }

        psbt.AddOutput(
            dest,
            tx_out.amount,
            tx_out.memo,
            token_id,
            out_type,
            tx_out.min_stake
        );
    }

    blsct::DoublePublicKey change_dest;
    auto maybe_tx = psbt.BuildTx(change_dest);

    if (!maybe_tx.has_value()) {
        return BLSCT_FAILURE;
    }
    auto tx = maybe_tx.value();

    DataStream st{};
    TransactionSerParams params{.allow_witness = true};
    ParamsStream ps{params, st};
    tx.Serialize(ps);

    // if provided buffer is not large enough to store the
    // serialized tx, return error with the required buffer size
    if (st.size() > *serialized_tx_size) {
        *serialized_tx_size = st.size();
        return BLSCT_BUFFER_TOO_SMALL;
    }
    // return the serialized tx with the size
    std::memcpy(serialized_tx, st.data(), st.size());
    *serialized_tx_size = st.size();

    return BLSCT_SUCCESS;
}

void blsct_sign_message(
    const BlsctPrivKey blsct_priv_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    BlsctSignature blsct_signature
) {
    blsct::PrivateKey priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, PRIVATE_KEY_SIZE, priv_key
    );

    blsct::Message msg {blsct_msg, blsct_msg + blsct_msg_size};
    blsct::Signature sig = priv_key.Sign(msg);

    SERIALIZE_AND_COPY(sig, blsct_signature);
}

bool blsct_verify_msg_sig(
    const BlsctPubKey blsct_pub_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    const BlsctSignature blsct_signature
) {
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);

    blsct::Message msg {blsct_msg, blsct_msg + blsct_msg_size};

    blsct::Signature signature;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_signature, SIGNATURE_SIZE, signature);

    return pub_key.Verify(msg, signature);
}

} // extern "C"

