#include "blsct/double_public_key.h"
#include <blsct/private_key.h>
#include <blsct/bech32_mod.h>
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs/range_proof.h>
#include <blsct/range_proof/bulletproofs/range_proof_logic.h>
#include <blsct/range_proof/bulletproofs/amount_recovery_request.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/helpers.h>
#include <common/args.h>

#include <cstring>
#include <streams.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

static std::string g_chain;
static std::mutex g_init_mutex;
static bulletproofs::RangeProofLogic<Mcl>* g_rpl;
static bool g_is_little_endian;

extern "C" {

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

void blsct_gen_random_public_key(
    BlsctPubKey public_key
) {
    auto vec = Point::Rand().GetVch();
    std::memcpy(public_key, &vec[0], vec.size());
}

void blsct_gen_public_key_from_byte_str(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey public_key
) {
    std::vector<uint8_t> src_vec {src_str, src_str + src_str_size};
    auto point = Point::HashAndMap(src_vec);
    auto point_vec = point.GetVch();
    std::memcpy(public_key, &point_vec[0], point_vec.size());
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
    auto ser_dpk = dpk.GetVch();
    std::memcpy(
        blsct_dpk,
        &ser_dpk[0],
        blsct::DoublePublicKey::SIZE
    );
}

BLSCT_RESULT blsct_decode_address(
    const BlsctAddrStr blsct_addr_str,
    BlsctDoublePubKey blsct_dpk
) {
    try {
        if (strlen(blsct_addr_str) != ENCODED_DPK_STR_BUF_SIZE) {
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
    BlsctEncAddr blsct_enc_addr
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

/* private function not exposed to outside */
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

// static void blsct_uint64_to_blsct_uint256(
//     const uint64_t n,
//     BlsctUint256 uint256
// ) {
//     std::memset(uint256, 0, UINT256_SIZE);
//     if (g_is_little_endian) {
//         for (size_t i=0; i<8; ++i) {
//             uint256[i] = (n >> (i * 8)) & 0xFF;
//         }
//     } else {
//         for (size_t i=0; i<8; ++i) {
//             uint256[7 - i] = (n >> (i * 8)) & 0xFF;
//         }
//     }
// }

#define SERIALIZE_AND_COPY(src, dest) \
{ \
    auto src_vec = src.GetVch(); \
    std::memcpy(dest, &src_vec[0], src_vec.size()); \
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


void blsct_generate_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid,
    BlsctTokenId blsct_token_id
) {
    std::vector<uint8_t> token_vec(token, token + UINT256_SIZE);
    uint256 token_uint256(token_vec);
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
        // build AmountRecoveryRequest's
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

        auto res = g_rpl->RecoverAmounts(reqs);

        // initially mark all the requests to be failure
        for(size_t i=0; i<num_reqs; ++i) {
            blsct_amount_recovery_reqs[i].is_succ = false;
        }

        if (!res.run_to_completion) {
            return BLSCT_DID_NOT_RUN_TO_COMPLETION;
        }
        // res contains results of successful recovery only
        // i.e. res.amounts.size() can be less than num_reqs
        for(size_t i=0; i<res.amounts.size(); ++i) {
            auto amount = res.amounts[i];
            auto& r = blsct_amount_recovery_reqs[amount.idx];
            r.is_succ = true;
            r.amount = amount.amount;
            r.msg_size = amount.message.size();
            std::memcpy(
                r.msg,
                amount.message.c_str(),
                amount.message.size()
            );
        }
        return BLSCT_SUCCESS;

    } catch(...) {}

    return BLSCT_EXCEPTION;
}

// // TODO
// void blsct_gen_point_from_seed(
//     const uint8_t seed[],
//     const size_t seed_len,
//     BlsctPoint blsct_point
// ) {
//     std::vector<uint8_t> seed_vec(&seed[0], &seed[0] + seed_len);
//     auto x = Point::HashAndMap(seed_vec);
//     SERIALIZE_AND_COPY(x, blsct_point);
// }
//
// // TODO
// void blsct_gen_random_point(
//     BlsctPoint blsct_point
// ) {
//     auto x = Point::Rand();
//     SERIALIZE_AND_COPY(x, blsct_point);
// }

void blsct_gen_random_seed(
    BlsctScalar blsct_scalar
) {
    auto x = Scalar::Rand(true);
    SERIALIZE_AND_COPY(x, blsct_scalar);
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

// defines Point of name `dest` generated from `src`
#define TRY_DEFINE_MCL_POINT_FROM(src, dest) \
    Point dest; \
    if (!from_blsct_point_to_mcl_point(src, dest)) return BLSCT_FAILURE

// defines Scalar of name `dest` generated from `src`
#define TRY_DEFINE_MCL_SCALAR_FROM(src, dest) \
    Scalar dest; \
    from_blsct_scalar_to_mcl_scalar(src, dest)

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
    const BlsctPoint blsct_blinding_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blsct_nonce
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_key, blinding_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto nonce = blsct::CalculateNonce(blinding_key, view_key);
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

BLSCT_RESULT blsct_from_child_key_to_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_blinding_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    Scalar scalar_blinding_key =
        blsct::FromChildToBlindingKey(child_key);
    Point point_blinding_key =
        Point::GetBasePoint() * scalar_blinding_key;

    SERIALIZE_AND_COPY(point_blinding_key, blsct_blinding_key);

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

BLSCT_RESULT blsct_from_tx_key_to_spend_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_spend_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_tx_key, tx_key);

    auto spend_key = blsct::FromTransactionToSpendKey(tx_key);
    SERIALIZE_AND_COPY(spend_key, blsct_spend_key);

    return BLSCT_SUCCESS;
}

/* from raw_spending_key */
BLSCT_RESULT blsct_from_raw_spending_key_to_pt_spending_key(
    const BlsctScalar blsct_raw_spending_key,
    BlsctPoint blsct_pt_spending_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(
        blsct_raw_spending_key,
        raw_spending_key
    );
    Point pt_spending_key = Point::GetBasePoint() * raw_spending_key;
    SERIALIZE_AND_COPY(
        pt_spending_key,
        blsct_pt_spending_key
    );
    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_raw_spending_key_to_pk_spending_key(
    const BlsctScalar blsct_raw_spending_key,
    BlsctPubKey blsct_pk_spending_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(
        blsct_raw_spending_key,
        raw_spending_key
    );
    Point pt_spending_key = Point::GetBasePoint() * raw_spending_key;
    blsct::PublicKey pk_spending_key(pt_spending_key);

    SERIALIZE_AND_COPY(
        pk_spending_key,
        blsct_pk_spending_key
    );
    return BLSCT_SUCCESS;
}

void blsct_gen_randon_seed(BlsctScalar* blsct_scalar)
{
    auto scalar = blsct::GenRandomSeed();
    SERIALIZE_AND_COPY(scalar, blsct_scalar);
}

BLSCT_RESULT blsct_calcualte_view_tag(
    const BlsctPoint blsct_blinding_key,
    const BlsctScalar blsct_view_key,
    BlsctViewTag blsct_view_tag
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_key, blinding_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    *blsct_view_tag = blsct::CalculateViewTag(blinding_key, view_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_key, blinding_key);
    TRY_DEFINE_MCL_POINT_FROM(blsct_spending_key, spending_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto hash_id = blsct::CalculateHashId(blinding_key, spending_key, view_key);
    SERIALIZE_AND_COPY_WITH_STREAM(hash_id, blsct_hash_id);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_key, blinding_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_spending_key, spending_key);

    auto priv_spending_key = blsct::CalculatePrivateSpendingKey(
        blinding_key,
        view_key,
        spending_key,
        account,
        address
    );
    SERIALIZE_AND_COPY(priv_spending_key, blsct_priv_spending_key);

    return BLSCT_SUCCESS;
}

} // extern "C"

