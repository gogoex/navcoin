// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blsct/signature.h"
#include <boost/test/tools/old/interface.hpp>
#define BOOST_UNIT_TEST

#include <boost/function/function_base.hpp>
#include <boost/test/unit_test.hpp>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <blsct/public_key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/random.h>
#include <util/transaction_identifier.h>
#include <util/strencodings.h>

#include <cstring>
#include <iterator>
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
    blsct_gen_token_id_with_subid(token, 234, blsct_token_id);

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
    blsct_gen_token_id(token, blsct_token_id);

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
    blsct_gen_token_id(token, blsct_token_id);

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
    blsct_gen_token_id(token, blsct_token_id);

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

BOOST_AUTO_TEST_CASE(test_blsct_gen_token_id)
{
    uint64_t token = 12345678912345;

    // w/o subid
    {
        BlsctTokenId blsct_token_id;
        blsct_gen_token_id(token, blsct_token_id);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, sizeof(blsct_token_id), token_id);

        BOOST_CHECK(token_id.token.GetUint64(0) == token);
    }

    // w/ subid
    {
        uint64_t subid= 987654;

        BlsctTokenId blsct_token_id;
        blsct_gen_token_id_with_subid(token, subid, blsct_token_id);

        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, sizeof(blsct_token_id), token_id);

        BOOST_CHECK(token_id.token.GetUint64(0) == token);
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
    blsct_gen_token_id(token, blsct_token_id);

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
    blsct_gen_token_id(token, blsct_token_id);

    BlsctPoint blsct_vk, blsct_sk;
    blsct_gen_random_public_key(blsct_vk);
    blsct_gen_random_public_key(blsct_sk);

    BlsctDoublePubKey blsct_dpk;
    blsct_gen_double_public_key(blsct_vk, blsct_sk, blsct_dpk);

    BlsctSubAddr blsct_sub_addr;
    blsct_dpk_to_sub_addr(blsct_dpk, blsct_sub_addr);

    uint64_t amount = 1000;

    TxOutputType output_type = TxOutputType::Normal;
    uint64_t min_stake = 0;
    BlsctTxOut tx_out;

    // MEMO_BUF_SIZE takes the last null char into consideration
    // therefore a string of size MEMO_BUF_SIZE exceeds the limit
    std::string too_long_memo(MEMO_BUF_SIZE, 'a');

    BLSCT_RESULT res = blsct_build_tx_out(
        blsct_sub_addr,
        amount,
        too_long_memo.c_str(),
        blsct_token_id,
        output_type,
        min_stake,
        &tx_out
    );
    BOOST_CHECK_EQUAL(res, BLSCT_MEMO_TOO_LONG);

    const char* memo = "good memo";

    res = blsct_build_tx_out(
        blsct_sub_addr,
        amount,
        memo,
        blsct_token_id,
        output_type,
        min_stake,
        &tx_out
    );
    BOOST_CHECK_EQUAL(res, BLSCT_SUCCESS);

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

void build_test_tx_in(
    const uint64_t& in_amount,
    const BlsctTokenId blsct_token_id,
    BlsctTxIn& blsct_tx_in
) {
    BlsctScalar blsct_spending_key;

    BlsctOutPoint out_point;
    auto tx_id = Txid::FromUint256(InsecureRand256());
    auto tx_id_hex = tx_id.GetHex();
    blsct_gen_out_point(
        tx_id_hex.c_str(),
        0,
        out_point
    );

    blsct_build_tx_in(
        in_amount,
        100,
        blsct_spending_key,
        blsct_token_id,
        out_point,
        false,
        &blsct_tx_in
    );
}

BLSCT_RESULT build_test_tx_out(
    const uint64_t& out_amount,
    const BlsctTokenId blsct_token_id,
    const uint8_t out_type,
    const char* memo,
    BlsctTxOut& blsct_tx_out
) {
    BlsctPoint blsct_vk, blsct_sk;
    blsct_gen_random_public_key(blsct_vk);
    blsct_gen_random_public_key(blsct_sk);

    BlsctDoublePubKey blsct_dpk;
    blsct_gen_double_public_key(blsct_vk, blsct_sk, blsct_dpk);

    BlsctSubAddr blsct_sub_addr;
    blsct_dpk_to_sub_addr(blsct_dpk, blsct_sub_addr);

    TxOutputType output_type = static_cast<TxOutputType>(out_type);
    uint64_t min_stake = 0;

    return blsct_build_tx_out(
        blsct_sub_addr,
        out_amount,
        memo,
        blsct_token_id,
        output_type,
        min_stake,
        &blsct_tx_out
    );
}

BLSCT_RESULT build_tx_from_sigle_tx_in_out(
    const BlsctTxIn blsct_tx_in,
    const BlsctTxOut blsct_tx_out,
    size_t* ser_tx_size,
    size_t* in_amount_err_index,
    size_t* out_amount_err_index
) {
    BLSCT_RESULT res;

    // first get the required tx buffer size
    uint8_t too_small_buf[*ser_tx_size];
    res = blsct_build_tx(
        &blsct_tx_in,
        1,
        &blsct_tx_out,
        1,
        too_small_buf,
        ser_tx_size,
        in_amount_err_index,
        out_amount_err_index
    );

    return res;
}

BOOST_AUTO_TEST_CASE(test_build_good_tx)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_gen_token_id(token, blsct_token_id);

    uint64_t in_amount = 12345;
    BlsctTxIn blsct_tx_in_1;
    build_test_tx_in(
        in_amount,
        blsct_token_id,
        blsct_tx_in_1
    );

    BlsctTxOut blsct_tx_out_1;
    uint64_t out_amount = in_amount - 1000;
    uint8_t out_type = static_cast<uint8_t>(TxOutputType::Normal);

    BLSCT_RESULT res;

    res = build_test_tx_out(
        out_amount,
        blsct_token_id,
        out_type,
        "salary",
        blsct_tx_out_1
    );
    BOOST_CHECK_EQUAL(res, BLSCT_SUCCESS);

    size_t ser_tx_size = 0;
    size_t in_amount_err_index;
    size_t out_amount_err_index;

    res = build_tx_from_sigle_tx_in_out(
        blsct_tx_in_1,
        blsct_tx_out_1,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );
    BOOST_CHECK_EQUAL(res, BLSCT_BUFFER_TOO_SMALL);

    // now ser_tx_size should have required tx buffer size
    BOOST_CHECK(ser_tx_size > 0);

    // try again with tx buffer of big enough size
    uint8_t ser_tx[10000];
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

    // should succeed
    BOOST_CHECK(res == BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_build_tx_with_bad_tx_in)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_gen_token_id(token, blsct_token_id);

    BlsctTxIn blsct_tx_in_1;

    // the underlying mcl library can only take up to int64 max
    // thus uint64 max is outside the range
    uint64_t in_amount =
        std::numeric_limits<uint64_t>::max();

    build_test_tx_in(
        in_amount,
        blsct_token_id,
        blsct_tx_in_1
    );

    BlsctTxOut blsct_tx_out_1;
    uint64_t out_amount = in_amount - 1000;
    uint8_t out_type = static_cast<uint8_t>(TxOutputType::StakedCommitment);

    BLSCT_RESULT res;

    res = build_test_tx_out(
        out_amount,
        blsct_token_id,
        out_type,
        "salary",
        blsct_tx_out_1
    );
    BOOST_CHECK_EQUAL(res, BLSCT_SUCCESS);

    size_t ser_tx_size = 0;
    size_t in_amount_err_index =
        std::numeric_limits<size_t>::max();
    size_t out_amount_err_index;

    // should fail with in amount error
    res = build_tx_from_sigle_tx_in_out(
        blsct_tx_in_1,
        blsct_tx_out_1,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );
    BOOST_CHECK_EQUAL(res, BLSCT_IN_AMOUNT_ERROR);
    BOOST_CHECK_EQUAL(in_amount_err_index, 0);
}

BOOST_AUTO_TEST_CASE(test_build_tx_with_bad_tx_out)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_gen_token_id(token, blsct_token_id);

    uint64_t in_amount = 12345;
    BlsctTxIn blsct_tx_in_1;

    build_test_tx_in(
        in_amount,
        blsct_token_id,
        blsct_tx_in_1
    );

    BlsctTxOut blsct_tx_out_1;

    // the underlying mcl library can only take up to int64 max
    // thus uint64 max is outside the range
    uint64_t out_amount =
        std::numeric_limits<uint64_t>::max();
    uint8_t out_type = static_cast<uint8_t>(TxOutputType::StakedCommitment);

    BLSCT_RESULT res;

    res = build_test_tx_out(
        out_amount,
        blsct_token_id,
        out_type,
        "salary",
        blsct_tx_out_1
    );
    BOOST_CHECK_EQUAL(res, BLSCT_SUCCESS);

    size_t ser_tx_size = 0;
    size_t in_amount_err_index;
    size_t out_amount_err_index =
        std::numeric_limits<size_t>::max();

    // should fail with out amount error
    res = build_tx_from_sigle_tx_in_out(
        blsct_tx_in_1,
        blsct_tx_out_1,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );
    BOOST_CHECK_EQUAL(res, BLSCT_OUT_AMOUNT_ERROR);
    BOOST_CHECK_EQUAL(out_amount_err_index, 0);
}

BOOST_AUTO_TEST_CASE(test_build_tx_with_bad_out_type)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_gen_token_id(token, blsct_token_id);

    uint64_t in_amount = 12345;
    BlsctTxIn blsct_tx_in_1;

    build_test_tx_in(
        in_amount,
        blsct_token_id,
        blsct_tx_in_1
    );

    BlsctTxOut blsct_tx_out_1;
    uint64_t out_amount = in_amount - 1000;
    uint8_t out_type = 100; // valid values are 0 and 1 only

    BLSCT_RESULT res;

    res = build_test_tx_out(
        out_amount,
        blsct_token_id,
        out_type,
        "salary",
        blsct_tx_out_1
    );
    BOOST_CHECK_EQUAL(res, BLSCT_SUCCESS);

    size_t ser_tx_size = 0;
    size_t in_amount_err_index;
    size_t out_amount_err_index;

    // should fail with bad out type error
    res = build_tx_from_sigle_tx_in_out(
        blsct_tx_in_1,
        blsct_tx_out_1,
        &ser_tx_size,
        &in_amount_err_index,
        &out_amount_err_index
    );
    BOOST_CHECK_EQUAL(res, BLSCT_BAD_OUT_TYPE);
}

BOOST_AUTO_TEST_CASE(test_build_tx_with_too_long_memo)
{
    BlsctTokenId blsct_token_id;
    uint64_t token = 532;
    blsct_gen_token_id(token, blsct_token_id);

    uint64_t in_amount = 12345;
    BlsctTxIn blsct_tx_in_1;
    build_test_tx_in(
        in_amount,
        blsct_token_id,
        blsct_tx_in_1
    );

    BlsctTxOut blsct_tx_out_1;
    uint64_t out_amount = in_amount - 1000;
    uint8_t out_type = static_cast<uint8_t>(TxOutputType::Normal);

    std::string too_long_memo(MEMO_BUF_SIZE, 'a');

    BLSCT_RESULT res = build_test_tx_out(
        out_amount,
        blsct_token_id,
        out_type,
        too_long_memo.c_str(),
        blsct_tx_out_1
    );

    // should fails with memo-too-long error
    BOOST_CHECK_EQUAL(res, BLSCT_MEMO_TOO_LONG);
}


template<typename T, typename U>
void BUFFERS_EQUAL(
    const T a[],
    const U b[],
    const size_t size
) {
    static_assert(std::is_same_v<T, std::byte> || std::is_same_v<T, uint8_t>, "Unexpected types");
    static_assert(std::is_same_v<U, std::byte> || std::is_same_v<U, uint8_t>, "Unexpected types");

    for (size_t i = 0; i < size; ++i) {
        if (static_cast<uint8_t>(a[i]) != static_cast<uint8_t>(b[i])) {
            BOOST_CHECK(false);
            return;
        }
    }
}

BOOST_AUTO_TEST_CASE(test_decode_token_id)
{
    {
        // default token id
        BlsctTokenId blsct_token_id;
        blsct_gen_default_token_id(blsct_token_id);

        BlsctTokenIdDe blsct_token_id_de;
        blsct_decode_token_id(
            blsct_token_id,
            &blsct_token_id_de
        );
        BOOST_CHECK(blsct_token_id_de.token == 0);
        BOOST_CHECK(blsct_token_id_de.subid == std::numeric_limits<uint64_t>::max());
    }

    uint64_t uint64_max =
        std::numeric_limits<uint64_t>::max();

    {
        // token id w/ token <= uint64_t max
        BlsctTokenId blsct_token_id;
        blsct_gen_token_id_with_subid(
            uint64_max,
            456,
            blsct_token_id
        );

        BlsctTokenIdDe blsct_token_id_de;
        auto res = blsct_decode_token_id(
            blsct_token_id,
            &blsct_token_id_de
        );
        BOOST_CHECK(res == true);
        BOOST_CHECK(blsct_token_id_de.token == uint64_max);
        BOOST_CHECK(blsct_token_id_de.subid == 456);
    }
    {
        // token id w/ token > uint64_t max
        uint256 token;
        token.data()[8] = 1;
        TokenId token_id(token);
        token_id.subid = 123;

        BlsctTokenId blsct_token_id;

        SERIALIZE_AND_COPY_WITH_STREAM(token_id, blsct_token_id);

        BlsctTokenIdDe blsct_token_id_de;
        auto res = blsct_decode_token_id(
            blsct_token_id,
            &blsct_token_id_de
        );
        BOOST_CHECK(res == false);
        BOOST_CHECK(blsct_token_id_de.token == uint64_max);
        BOOST_CHECK(blsct_token_id_de.subid == 123);
    }
}

void populate_blsct_data(CTxOutBLSCTData& blsct_data)
{
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
    blsct_gen_token_id(token, blsct_token_id);
    const char* blsct_message = "spaghetti meatballs";
    uint64_t uint64_vs[] = { 1 };

    BlsctRangeProof blsct_range_proof;

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

    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_range_proof,
        RANGE_PROOF_SIZE,
        blsct_data.rangeProof
    );
    blsct_data.spendingKey = Point::Rand();
    blsct_data.ephemeralKey = Point::Rand();
    blsct_data.blindingKey = Point::Rand();
}

BOOST_AUTO_TEST_CASE(test_deserialize_tx)
{
    // create tx to serialize/deserialize
    CMutableTransaction tx;
    tx.nVersion = 123;
    tx.nLockTime = 1000;

    // tx signature
    {
        std::vector<uint8_t> msg {1, 2, 3};
        auto priv_key = blsct::PrivateKey::GenRandomPrivKey();
        blsct::Signature tx_sig = priv_key.Sign(msg);
        tx.txSig = tx_sig;
    }

    // tx in
    CTxIn vin1, vin2;
    vin1.nSequence = 1;
    vin1.prevout.n = 2;
    vin1.prevout.hash = Txid::FromUint256(InsecureRand256());
    vin1.scriptSig.push_back(10);
    vin1.scriptSig.push_back(20);
    std::vector<uint8_t> vin1_vec1 {23, 24};
    std::vector<uint8_t> vin1_vec2 {33, 34};
    vin1.scriptWitness.stack.push_back(vin1_vec1);
    vin1.scriptWitness.stack.push_back(vin1_vec2);

    vin2.nSequence = 3;
    vin2.prevout.n = 4;
    vin2.prevout.hash = Txid::FromUint256(InsecureRand256());
    vin2.scriptSig.push_back(30);
    vin2.scriptSig.push_back(40);
    std::vector<uint8_t> vin2_vec1 {3, 4};
    std::vector<uint8_t> vin2_vec2 {5, 6};
    std::vector<uint8_t> vin2_vec3 {7, 8};
    vin2.scriptWitness.stack.push_back(vin2_vec1);
    vin2.scriptWitness.stack.push_back(vin2_vec2);
    vin2.scriptWitness.stack.push_back(vin2_vec3);

    tx.vin.push_back(vin1);
    tx.vin.push_back(vin2);

    // tx out
    CTxOut vout1, vout2, vout3, vout4;

    // 1. Range proof is not added and tokenId == TokenId()
    vout1.nValue = 567;
    vout1.scriptPubKey.push_back(73);
    vout1.scriptPubKey.push_back(74);
    vout1.tokenId = TokenId();
    vout1.blsctData.rangeProof.Vs.Clear();

    // 2. Range proof is not added and tokenId != TokenId()
    vout2.nValue = 789;
    vout2.scriptPubKey.push_back(83);
    vout2.scriptPubKey.push_back(84);
    vout2.tokenId.token.begin()[0] = 6;
    vout2.tokenId.subid = 23345;
    vout2.blsctData.rangeProof.Vs.Clear();

    // 3. Range proof is added and tokenId == TokenId()
    vout3.nValue = 567;
    vout3.scriptPubKey.push_back(73);
    vout3.scriptPubKey.push_back(74);
    vout3.tokenId = TokenId();
    populate_blsct_data(vout3.blsctData);

    // 4. Range proof is added and tokenId != TokenId()
    vout4.nValue = 789;
    vout4.scriptPubKey.push_back(83);
    vout4.scriptPubKey.push_back(84);
    vout4.tokenId.token.begin()[0] = 6;
    vout4.tokenId.subid = 23345;
    populate_blsct_data(vout4.blsctData);

    tx.vout.push_back(vout1);
    tx.vout.push_back(vout2);
    tx.vout.push_back(vout3);
    tx.vout.push_back(vout4);

    std::vector<int64_t> exp_values {
        vout1.nValue, // no range_proof + tokenId == TokenId() -> value != 0
        0, // tokenId != TokenId() -> value = 0
        0, // range proof exists -> value = 0
        0, // range_proof exists + tokenId != TokenId() -> value = 0
    };

    // serialize the tx to ser_tx_span
    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};
    tx.Serialize(ps);

    std::vector<std::byte> ser_tx(ps.size());
    Span<std::byte> ser_tx_span(ser_tx);
    ps.read(ser_tx_span);

    // deserialize the tx and convert the tx to BlsctTransaction
    BlsctTransaction* blsct_tx;
    blsct_deserialize_tx(
        reinterpret_cast<uint8_t*>(ser_tx_span.data()),
        ser_tx_span.size(),
        &blsct_tx
    );

    // confirm deserialization is successful
    BOOST_CHECK_EQUAL(blsct_tx->version, tx.nVersion);
    BOOST_CHECK_EQUAL(blsct_tx->lock_time, tx.nLockTime);

    blsct::Signature act_tx_sig;
    UNSERIALIZE_AND_COPY_WITH_STREAM(blsct_tx->tx_sig, SIGNATURE_SIZE, act_tx_sig);
    BOOST_CHECK(act_tx_sig == tx.txSig); // BOOST_CHECK_EQUAL doesn't work for some reason

    BOOST_CHECK_EQUAL(blsct_tx->num_ins, tx.vin.size());
    for (size_t i=0; i<tx.vin.size(); ++i) {
        auto& in = blsct_tx->ins[i];
        auto& tx_in = tx.vin[i];

        BOOST_CHECK_EQUAL(tx_in.nSequence, in.sequence);
        BOOST_CHECK_EQUAL(tx_in.prevout.n, in.prev_out.n);

        BUFFERS_EQUAL(tx_in.prevout.hash.data(), in.prev_out.hash, UINT256_SIZE);

        BOOST_CHECK_EQUAL(tx_in.scriptSig.size(), in.script_sig.size);
        BUFFERS_EQUAL(tx_in.scriptSig.data(), in.script_sig.script, in.script_sig.size);

        BOOST_CHECK_EQUAL(tx_in.scriptWitness.stack.size(), in.script_witness.size);
        for (size_t j=0; j<in.script_witness.size; ++j) {
            auto& in_wit = in.script_witness.stack[j];
            auto& tx_in_wit = tx_in.scriptWitness.stack[j];

            BOOST_CHECK_EQUAL(in_wit.size, tx_in_wit.size());
            BUFFERS_EQUAL(in_wit.buf, &tx_in_wit[0], in_wit.size);
        }
    }

    BOOST_CHECK_EQUAL(blsct_tx->num_outs, tx.vout.size());
    BOOST_CHECK_EQUAL(exp_values.size(), 4);

    for (size_t i=0; i<tx.vout.size(); ++i) {
        auto& out = blsct_tx->outs[i];
        auto& tx_out = tx.vout[i];

        // value
        BOOST_CHECK_EQUAL(out.value, exp_values[i]);

        // script_pubkey
        BOOST_CHECK_EQUAL(tx_out.scriptPubKey.size(), out.script_pubkey.size);
        BUFFERS_EQUAL(tx_out.scriptPubKey.data(), out.script_pubkey.script, out.script_pubkey.size);

        // token_id
        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(out.token_id, TOKEN_ID_SIZE, token_id);
        BOOST_CHECK_EQUAL(tx_out.tokenId.token, token_id.token);
        BOOST_CHECK_EQUAL(tx_out.tokenId.subid, token_id.subid);

        // blsct_data

        // 1. Range proof is not added and tokenId == TokenId()
        // 2. Range proof is not added and tokenId != TokenId()
        if (i == 0 || i == 1) {
            // should not have created blsct_data
            BOOST_CHECK(out.blsct_data == nullptr);
            continue;
        }

        // case
        // 3. Range proof is added and tokenId == TokenId()
        // 4. Range proof is added and tokenId != TokenId()
        BOOST_CHECK_EQUAL(tx_out.blsctData.viewTag, out.blsct_data->view_tag);

        Point spending_key, ephemeral_key, blinding_key;

        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            out.blsct_data->spending_key,
            POINT_SIZE,
            spending_key
        );
        BOOST_CHECK(tx_out.blsctData.spendingKey == spending_key);

        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            out.blsct_data->ephemeral_key,
            POINT_SIZE,
            ephemeral_key
        );
        BOOST_CHECK(tx_out.blsctData.ephemeralKey == ephemeral_key);

        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            out.blsct_data->blinding_key,
            POINT_SIZE,
            blinding_key
        );
        BOOST_CHECK(tx_out.blsctData.blindingKey == blinding_key);
    }

    blsct_dispose_tx(&blsct_tx);
}

BOOST_AUTO_TEST_SUITE_END()

