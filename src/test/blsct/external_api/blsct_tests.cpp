// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blsct/public_key.h"
#define BOOST_UNIT_TEST

#include <boost/function/function_base.hpp>
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <key_io.h>
#include <streams.h>

#include <cstring>
#include <string>
#include <sys/types.h>

using T = Mcl;
using Point = T::Point;
using Scalar = T::Scalar;
using Points = Elements<Point>;
using Scalars = Elements<Scalar>;
using MsgPair = std::pair<std::string, std::vector<uint8_t>>;

BOOST_FIXTURE_TEST_SUITE(blsct_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_encode_decode_blsct_address)
{
    BOOST_CHECK(blsct_init(MainNet));

    // bech32_mod-encoded
    const char* blsct_addr = "nv1jlca8fe3jltegf54vwxyl2dvplpk3rz0ja6tjpdpfcar79cm43vxc40g8luh5xh0lva0qzkmytrthftje04fqnt8g6yq3j8t2z552ryhy8dnpyfgqyj58ypdptp43f32u28htwu0r37y9su6332jn0c0fcvan8l53m";

    uint8_t ser_dpk[blsct::DoublePublicKey::SIZE];
    {
        auto res = blsct_decode_address(blsct_addr, ser_dpk);
        BOOST_CHECK(res == BLSCT_SUCCESS);
    }

    char rec_addr_buf[DOUBLE_PUBKEY_ENC_SIZE + 1];  // 1 for null-termination
    {
        auto res = blsct_encode_address(
            ser_dpk,
            Bech32M,
            rec_addr_buf
        );
        BOOST_CHECK(res == BLSCT_SUCCESS);
    }

    std::string rec_addr((char*) rec_addr_buf, DOUBLE_PUBKEY_ENC_SIZE);

    BOOST_CHECK(std::strcmp(blsct_addr, rec_addr.c_str()) == 0);
}

BOOST_AUTO_TEST_CASE(test_generate_token_id)
{
    uint64_t token = 100;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id_with_subid(token, 200, blsct_token_id);

    TokenId token_id;
    DataStream st{};
    st << blsct_token_id;
    token_id.Unserialize(st);

    BOOST_CHECK(token_id.token == uint256(token));
    BOOST_CHECK(token_id.subid == 200);
}

BOOST_AUTO_TEST_CASE(test_uint64_to_blsct_uint256)
{
    std::vector<uint64_t> ns = {
        0, 1, 1000, 70000, 12093234903493
    };

    for(size_t i=0; i<ns.size(); ++i) {
        BlsctUint256 blsct_uint256;
        blsct_uint64_to_blsct_uint256(ns[i], blsct_uint256);
        uint256 rec_n256(blsct_uint256);

        BOOST_CHECK(rec_n256.GetUint64(0) == ns[i]);
    }
}

BOOST_AUTO_TEST_CASE(test_prove_verify_range_proof)
{
    BOOST_CHECK(blsct_init(MainNet));

    BlsctPoint blsct_blinding_pubkey;
    BlsctScalar blsct_view_key;
    BlsctPoint blsct_nonce;

    blsct_gen_random_point(blsct_blinding_pubkey);
    blsct_gen_random_scalar(blsct_view_key);

    blsct_calculate_nonce(
        blsct_blinding_pubkey,
        blsct_view_key,
        blsct_nonce
    );

    uint64_t token = 100;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id(token, blsct_token_id);

    const char* blsct_message = "spaghetti meatballs";

    uint64_t uint64_vs[] = { 1 };

    BlsctRangeProof blsct_range_proof;
    {
        auto res = blsct_build_range_proof(
            uint64_vs,
            1,
            blsct_nonce,
            blsct_message,
            std::strlen(blsct_message),
            blsct_token_id,
            blsct_range_proof
        );
        BOOST_CHECK(res == BLSCT_SUCCESS);
    }

    BlsctRangeProof blsct_range_proofs[1];
    std::memcpy(
        &blsct_range_proofs[0],
        blsct_range_proof,
        sizeof(blsct_range_proof)
    );
    {
        bool is_valid;
        uint8_t res = blsct_verify_range_proof(
            blsct_range_proofs, 1, &is_valid
        );
        BOOST_CHECK(is_valid);
        BOOST_CHECK(res == BLSCT_SUCCESS);
    }
}

BOOST_AUTO_TEST_CASE(test_generate_nonce)
{
    const size_t NUM_NONCES = 1000;

    Point bp = Point::GetBasePoint();
    BlsctPoint blsct_blinding_pubkey;
    BlsctScalar blsct_view_key;

    BlsctPoint nonces[NUM_NONCES];

    Point blinding_pubkey = bp;
    uint64_t view_key(1);

    // generate nonces
    for(size_t i=0; i<NUM_NONCES; ++i) {
        blsct_gen_scalar(view_key, blsct_view_key);

        blsct_calculate_nonce(
            blsct_blinding_pubkey,
            blsct_view_key,
            nonces[i]
        );
        blinding_pubkey = blinding_pubkey + bp;
        ++view_key;
    }

    // check if all generated nonces are unique
    for(size_t i=0; i<NUM_NONCES; ++i) {
        for(size_t j=0; j<NUM_NONCES; ++j) {
            // avoid comparing to itself
            if (i == j) continue;

            // make sure different seeds have different contents
            bool is_different = false;
            for(size_t k=0; k<sizeof(BlsctPoint); ++k) {
                if (nonces[i][k] != nonces[j][k]) {
                    is_different = true;
                }
            }
            BOOST_CHECK(is_different);
        }
    }
}

static void build_range_proof_for_amount_recovery(
    const std::vector<uint64_t>& uint64_vs,
    const BlsctPoint& blsct_nonce,
    const char* msg,
    const BlsctTokenId& blsct_token_id,
    BlsctRangeProof& blsct_range_proof
) {
    auto res = blsct_build_range_proof(
        &uint64_vs[0],
        uint64_vs.size(),
        blsct_nonce,
        msg,
        std::strlen(msg),
        blsct_token_id,
        blsct_range_proof
    );
    BOOST_CHECK(res == BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_amount_recovery)
{
    BOOST_CHECK(blsct_init(MainNet));

    BlsctAmountRecoveryRequest reqs[2];
    const char* msgs[] = { "apple", "orange" };
    uint64_t amounts[] = { 123, 456 };

    uint64_t token = 123;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id(token, blsct_token_id);

    for(size_t i=0; i<2; ++i) {
        std::vector<uint64_t> uint64_vs { amounts[i] };

        BlsctPoint blsct_blinding_pub_key;
        blsct_gen_random_point(blsct_blinding_pub_key);

        BlsctScalar blsct_view_key;
        blsct_gen_random_scalar(blsct_view_key);

        blsct_calculate_nonce(
            blsct_blinding_pub_key,
            blsct_view_key,
            reqs[i].nonce
        );

        build_range_proof_for_amount_recovery(
            uint64_vs,
            reqs[i].nonce,
            msgs[i],
            blsct_token_id,
            reqs[i].range_proof
        );
    }

    BOOST_CHECK(blsct_recover_amount(reqs, 2) == BLSCT_SUCCESS);

    for(size_t i=0; i<2; ++i) {
        BOOST_CHECK(reqs[i].is_succ);
        BOOST_CHECK(reqs[i].amount == amounts[i]);
        BOOST_CHECK(reqs[i].msg_size == std::strlen(msgs[i]));
        BOOST_CHECK(std::strcmp(reqs[i].msg, msgs[i]) == 0);
    }
}

BOOST_AUTO_TEST_CASE(test_blsct_encode_address)
{
    BlsctPubKey pk1, pk2;
    blsct_gen_random_public_key(pk1);
    blsct_gen_random_public_key(pk2);

    BlsctDoublePubKey dpk;
    blsct_gen_double_public_key(pk1, pk2, dpk);

    BlsctAddrStr enc_addr;
    auto res = blsct_encode_address(
        dpk,
        AddressEncoding::Bech32,
        enc_addr
    );
    BOOST_CHECK(res == BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_blsct_generate_token_id)
{
    uint64_t token = 12345678912345;

    // w/o subid
    {
        BlsctTokenId token_id;
        blsct_generate_token_id(token, token_id);
    }

    // w/ subid
    {
        uint64_t subid = 987654;
        BlsctTokenId token_id;
        blsct_generate_token_id_with_subid(token, subid, token_id);
    }
}

BOOST_AUTO_TEST_CASE(test_blsct_gen_random_seed)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);
}

BOOST_AUTO_TEST_CASE(test_blsct_from_seed_to_child_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_tx_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_master_blinding_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar master_blinding_key;
    blsct_from_child_key_to_master_blinding_key(
        child_key,
        master_blinding_key
    );
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_token_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar token_key;
    blsct_from_child_key_to_token_key(child_key, token_key);
}

BOOST_AUTO_TEST_CASE(test_blsct_from_tx_key_to_view_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);

    BlsctScalar view_key;
    blsct_from_tx_key_to_view_key(tx_key, view_key);
}

BOOST_AUTO_TEST_CASE(test_blsct_from_tx_key_to_spend_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);

    BlsctScalar spending_key;
    blsct_from_tx_key_to_spending_key(tx_key, spending_key);
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_view_tag)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar master_blinding_key;
    blsct_from_child_key_to_master_blinding_key(
        child_key,
        master_blinding_key
    );

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);

    BlsctScalar view_key;
    blsct_from_tx_key_to_view_key(tx_key, view_key);

    BlsctScalar view_tag;
    blsct_calculate_view_tag(
        master_blinding_key,
        view_key,
        view_tag
    );
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_hash_id)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar master_blinding_key;
    blsct_from_child_key_to_master_blinding_key(
        child_key,
        master_blinding_key
    );

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);

    BlsctScalar view_key;
    blsct_from_tx_key_to_view_key(tx_key, view_key);

    // TODO spend_key == spending_key?
    BlsctScalar spending_key;
    blsct_from_tx_key_to_spending_key(tx_key, spending_key);

    BlsctScalar hash_id;
    blsct_calculate_hash_id(
        master_blinding_key,
        spending_key,
        view_key,
        hash_id
    );
}

BOOST_AUTO_TEST_CASE(test_blsct_calc_priv_spending_key)
{
    BlsctScalar seed;
    blsct_gen_random_scalar(seed);

    BlsctScalar child_key;
    blsct_from_seed_to_child_key(seed, child_key);

    BlsctScalar master_blinding_key;
    blsct_from_child_key_to_master_blinding_key(
        child_key,
        master_blinding_key
    );

    BlsctScalar tx_key;
    blsct_from_child_key_to_tx_key(child_key, tx_key);

    BlsctScalar view_key;
    blsct_from_tx_key_to_view_key(tx_key, view_key);

    BlsctScalar spending_key;
    blsct_from_tx_key_to_spending_key(tx_key, spending_key);

    int64_t account = 12345;
    uint64_t addr = 987832;

    BlsctScalar priv_spending_key;
    blsct_calc_priv_spending_key(
        master_blinding_key,
        spending_key,
        view_key,
        account,
        addr,
        priv_spending_key
    );
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_nonce)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_derive_sub_addr)
{
}

BOOST_AUTO_TEST_SUITE_END()

