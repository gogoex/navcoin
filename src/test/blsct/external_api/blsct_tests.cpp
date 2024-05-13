// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util/strencodings.h"
#include <iterator>
#define BOOST_UNIT_TEST

#include <boost/function/function_base.hpp>
#include <boost/test/unit_test.hpp>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <blsct/public_key.h>
#include <key_io.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/random.h>
#include <util/transaction_identifier.h>

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

BOOST_AUTO_TEST_CASE(test_generate_token_id_with_subid)
{
    uint64_t token = 123;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id_with_subid(token, 234, blsct_token_id);

    TokenId token_id;
    DataStream st{};
    st << blsct_token_id;
    token_id.Unserialize(st);

    BOOST_CHECK(token_id.token == uint256(token));
    BOOST_CHECK(token_id.subid == 234);
}

BOOST_AUTO_TEST_CASE(test_generate_token_id)
{
    uint64_t token = 123;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id(token, blsct_token_id);

    TokenId token_id;
    DataStream st{};
    st << blsct_token_id;
    token_id.Unserialize(st);

    BOOST_CHECK(token_id.token == uint256(token));
    BOOST_CHECK(token_id.subid == UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(test_uint64_to_blsct_uint256)
{
    std::vector<uint64_t> ns = {
        0, 1, 1000, 70000, 12093234903493
    };

    for(size_t i=0; i<ns.size(); ++i) {
        BlsctUint256 blsct_uint256;
        blsct_uint64_to_blsct_uint256(ns[i], blsct_uint256);
        uint256 uint256(blsct_uint256);

        BOOST_CHECK(uint256.GetUint64(0) == ns[i]);
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

BOOST_AUTO_TEST_CASE(test_gen_random_point)
{
    BlsctPoint blsct_point;
    blsct_gen_random_point(blsct_point);
    BOOST_CHECK(blsct_is_valid_point(blsct_point));
}

void from_point_to_blsct_point(
    const Point& point,
    BlsctPoint blsct_point
) {

    auto ser_point = point.GetVch();
    std::memcpy(blsct_point, &ser_point[0], Point::SERIALIZATION_SIZE);
}

bool from_blsct_point_to_point(
    const BlsctPoint blsct_point,
    Point& point
) {
    std::vector<uint8_t> vec {blsct_point, blsct_point + Point::SERIALIZATION_SIZE};
    return point.SetVch(vec);
}

BOOST_AUTO_TEST_CASE(test_generate_nonce)
{
    const size_t NUM_NONCES = 2;
    BlsctPoint nonces[NUM_NONCES];

    Point blinding_pubkey = Point::Rand();
    BlsctPoint blsct_blinding_pubkey;
    from_point_to_blsct_point(blinding_pubkey, blsct_blinding_pubkey);

    BlsctScalar blsct_view_key;
    uint64_t view_key(123);

    // generate nonces
    for(size_t i=0; i<NUM_NONCES; ++i) {
        blsct_gen_scalar(view_key, blsct_view_key);

        blsct_calculate_nonce(
            blsct_blinding_pubkey,
            blsct_view_key,
            nonces[i]
        );
        ++view_key;
    }

    // check if all generated nonces are unique
    for(size_t i=0; i<NUM_NONCES - 1; ++i) {
        for(size_t j=i+1; j<NUM_NONCES; ++j) {
            Point a, b;
            from_blsct_point_to_point(nonces[i], a);
            from_blsct_point_to_point(nonces[j], b);
            BOOST_CHECK(a != b);
        }
    }
}

static void build_range_proof_for_amount_recovery(
    const uint64_t& v,
    const BlsctPoint& blsct_nonce,
    const char* msg,
    const BlsctTokenId& blsct_token_id,
    BlsctRangeProof& blsct_range_proof
) {
    uint64_t vs = { v };
    auto res = blsct_build_range_proof(
        &vs,
        1,
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

    const char* msgs[] = { "apple", "orange" };
    uint64_t amounts[] = { 123, 456 };

    BlsctAmountRecoveryRequest reqs[2];

    uint64_t token = 123;
    BlsctTokenId blsct_token_id;
    blsct_generate_token_id(token, blsct_token_id);

    // build amount recovery requests
    for(size_t i=0; i<2; ++i) {
        // build msg and msg_size parts
        std::memcpy(reqs[i].msg, msgs[i], strlen(msgs[i]) + 1);
        reqs[i].msg_size = strlen(msgs[i]) + 1;

        // build amount part
        reqs[i].amount = amounts[i];

        // build nonce part
        BlsctPoint blsct_blinding_pub_key;
        blsct_gen_random_point(blsct_blinding_pub_key);

        BlsctScalar blsct_view_key;
        blsct_gen_random_scalar(blsct_view_key);

        blsct_calculate_nonce(
            blsct_blinding_pub_key,
            blsct_view_key,
            reqs[i].nonce
        );

        // build range proof part
        build_range_proof_for_amount_recovery(
            reqs[i].amount,
            reqs[i].nonce,
            reqs[i].msg,
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
        BlsctTokenId blsct_token_id;
        blsct_generate_token_id(token, blsct_token_id);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, sizeof(blsct_token_id), token_id);

        BOOST_CHECK(token_id.token == uint256(token));
    }

    // w/ subid
    {
        uint64_t subid = 987654;

        BlsctTokenId blsct_token_id;
        blsct_generate_token_id_with_subid(token, subid, blsct_token_id);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, sizeof(blsct_token_id), token_id);

        BOOST_CHECK(token_id.token == uint256(token));
        BOOST_CHECK(token_id.subid == subid);
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

blsct::DoublePublicKey gen_random_dpk() {
    auto view_key = blsct::PublicKey(Point::Rand());
    auto spending_key = blsct::PublicKey(Point::Rand());
    blsct::DoublePublicKey dpk(view_key, spending_key);

    return dpk;
}

BOOST_AUTO_TEST_CASE(test_sign_verify)
{
    BlsctPrivKey priv_key;
    {
        BlsctScalar n;
        blsct_gen_random_scalar(n);
        blsct_gen_priv_key(n, priv_key);
    }
    uint8_t msg[100];
    size_t msg_size;
    {
        const char* s = "cheese steak sandwich";
        msg_size = strlen(s);
        std::memcpy(msg, s, msg_size);
    }
    BlsctSignature signature;

    blsct_sign_message(
        priv_key,
        msg,
        msg_size,
        signature
    );

    BlsctPubKey pub_key;
    blsct_priv_key_to_pub_key(priv_key, pub_key);

    {
        // should succeed with valid input
        bool res = blsct_verify_msg_sig(
            pub_key,
            msg,
            msg_size,
            signature
        );
        BOOST_CHECK(res);
    }
    {
        // should fail with bad message
        bool res = blsct_verify_msg_sig(
            pub_key,
            msg,
            msg_size - 1,
            signature
        );
        BOOST_CHECK(!res);
    }
    {
        BlsctSignature bad_sig;
        std::memset(bad_sig, 123, SIGNATURE_SIZE);

        // should fail with bad signature
        bool res = blsct_verify_msg_sig(
            pub_key,
            msg,
            msg_size,
            bad_sig
        );
        BOOST_CHECK(!res);
    }
    {
        BlsctPubKey bad_pub_key;
        while (true) {
            blsct_gen_random_public_key(bad_pub_key);
            for (size_t i=0; i<PUBLIC_KEY_SIZE; ++i) {
                if (bad_pub_key[i] != pub_key[i]) {
                    goto BUILT_BAD_PUB_KEY;
                }
            }
        }
BUILT_BAD_PUB_KEY:

        // should fail with bad public key
        bool res = blsct_verify_msg_sig(
            bad_pub_key,
            msg,
            msg_size,
            signature
        );
        BOOST_CHECK(!res);
    }
}

BOOST_AUTO_TEST_CASE(test_build_tx_in)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_generate_token_id(token, blsct_token_id);

    uint64_t amount = 12345;
    uint64_t gamma = 100;
    bool rbf = true;

    BlsctScalar blsct_spending_key;

    BlsctOutPoint out_point;
    auto tx_id = Txid::FromUint256(InsecureRand256());
    auto tx_id_hex = tx_id.GetHex();
    blsct_gen_out_point(
        tx_id_hex.c_str(),
        0,
        out_point
    );

    BlsctTxIn tx_in;
    blsct_build_tx_in(
        amount,
        gamma,
        blsct_spending_key,
        blsct_token_id,
        out_point,
        rbf,
        &tx_in
    );

    BOOST_CHECK(tx_in.amount == amount);
    BOOST_CHECK(tx_in.gamma == gamma);
    BOOST_CHECK(tx_in.rbf == rbf);

    for(size_t i=0; i<sizeof(blsct_spending_key); ++i) {
        BOOST_CHECK(tx_in.spending_key[i] == blsct_spending_key[i]);
    }
    for(size_t i=0; i<sizeof(blsct_token_id); ++i) {
        BOOST_CHECK(tx_in.token_id[i] == blsct_token_id[i]);
    }
}

BOOST_AUTO_TEST_CASE(test_build_tx_out)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_generate_token_id(token, blsct_token_id);

    BlsctPoint blsct_vk, blsct_sk;
    blsct_gen_random_public_key(blsct_vk);
    blsct_gen_random_public_key(blsct_sk);

    BlsctDoublePubKey blsct_dpk;
    blsct_gen_double_public_key(blsct_vk, blsct_sk, blsct_dpk);

    BlsctSubAddr blsct_sub_addr;
    blsct_dpk_to_sub_addr(blsct_dpk, blsct_sub_addr);

    uint64_t amount = 1000;
    const char* memo = "june salary";

    TxOutputType output_type = TxOutputType::Normal;
    uint64_t min_stake = 0;

    BlsctTxOut tx_out;
    blsct_build_tx_out(
        blsct_sub_addr,
        amount,
        memo,
        blsct_token_id,
        output_type,
        min_stake,
        &tx_out
    );

    BOOST_CHECK(tx_out.amount == amount);
    BOOST_CHECK(std::strcmp(tx_out.memo, memo) == 0);
    BOOST_CHECK(tx_out.min_stake == min_stake);
    BOOST_CHECK(tx_out.output_type == output_type);

    for(size_t i=0; i<sizeof(blsct_sub_addr); ++i) {
        BOOST_CHECK(tx_out.dest[i] == blsct_sub_addr[i]);
    }
    for(size_t i=0; i<sizeof(blsct_token_id); ++i) {
        BOOST_CHECK(tx_out.token_id[i] == blsct_token_id[i]);
    }
}

BOOST_AUTO_TEST_CASE(test_build_tx)
{
    // common
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_generate_token_id(token, blsct_token_id);

    // tx in
    uint64_t in_amount = 12345;
    uint64_t gamma = 100;
    bool rbf = false;

    BlsctScalar blsct_spending_key;

    BlsctOutPoint out_point;
    auto tx_id = Txid::FromUint256(InsecureRand256());
    auto tx_id_hex = tx_id.GetHex();
    blsct_gen_out_point(
        tx_id_hex.c_str(),
        0,
        out_point
    );

    BlsctTxIn blsct_tx_in_1;
    blsct_build_tx_in(
        in_amount,
        gamma,
        blsct_spending_key,
        blsct_token_id,
        out_point,
        rbf,
        &blsct_tx_in_1
    );

    // tx out
    BlsctPoint blsct_vk, blsct_sk;
    blsct_gen_random_public_key(blsct_vk);
    blsct_gen_random_public_key(blsct_sk);

    BlsctDoublePubKey blsct_dpk;
    blsct_gen_double_public_key(blsct_vk, blsct_sk, blsct_dpk);

    BlsctSubAddr blsct_sub_addr;
    blsct_dpk_to_sub_addr(blsct_dpk, blsct_sub_addr);

    uint64_t out_amount = in_amount - 1000;
    const char* memo = "june salary";

    TxOutputType output_type = TxOutputType::Normal;
    uint64_t min_stake = 0;

    BlsctTxOut blsct_tx_out_1;
    blsct_build_tx_out(
        blsct_sub_addr,
        out_amount,
        memo,
        blsct_token_id,
        output_type,
        min_stake,
        &blsct_tx_out_1
    );

    size_t ser_tx_size = 0;
    size_t in_amount_err_index;
    size_t out_amount_err_index;

    BLSCT_RESULT res;

    // first get the required tx buffer size
    res = blsct_build_tx(
        &blsct_tx_in_1,
        1,
        &blsct_tx_out_1,
        1,
        nullptr,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );

    BOOST_CHECK(res == BLSCT_BUFFER_TOO_SMALL);

    // now ser_tx_size should have required tx buffer size
    BOOST_CHECK(ser_tx_size > 0);

    // try again with tx buffer of appropriate size
    uint8_t ser_tx[ser_tx_size];
    res = blsct_build_tx(
        &blsct_tx_in_1,
        1,
        &blsct_tx_out_1,
        1,
        ser_tx,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );
    // should succeed this time
    BOOST_CHECK(res == BLSCT_SUCCESS);

    std::vector<uint8_t> vec(ser_tx, ser_tx + ser_tx_size);
    auto hex = HexStr(vec);
    printf("serialized tx=%s\n", hex.c_str());

    // should test too big in-amount

    // should test too big out-amount

    // should test bad out type
}

BOOST_AUTO_TEST_SUITE_END()

