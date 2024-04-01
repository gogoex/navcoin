// Copyright (c) 2024 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <blsct/external_api/blsct.h>

BOOST_FIXTURE_TEST_SUITE(blsct_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_blsct_decode_address)
{
    BOOST_CHECK(blsct_init(MainNet));

    // bech32_mod-encoded
    std::string blsct_addr_str = "nv1jlca8fe3jltegf54vwxyl2dvplpk3rz0ja6tjpdpfcar79cm43vxc40g8luh5xh0lva0qzkmytrthftje04fqnt8g6yq3j8t2z552ryhy8dnpyfgqyj58ypdptp43f32u28htwu0r37y9su6332jn0c0fcvan8l53m";

    uint8_t ser_dpk[blsct::DoublePublicKey::SIZE];
    auto decode_result = blsct_decode_address(
         blsct_addr_str.c_str(),
        ser_dpk
    );
    BOOST_CHECK(decode_result);

    char rec_addr_buf[DOUBLE_PUBKEY_ENC_SIZE + 1];  // 1 for null-termination
    auto encode_result = blsct_encode_address(
        ser_dpk,
        rec_addr_buf,
        Bech32M
    );
    BOOST_CHECK(encode_result);

    std::string rec_addr_str((char*) rec_addr_buf, DOUBLE_PUBKEY_ENC_SIZE);

    BOOST_CHECK(blsct_addr_str == rec_addr_str);
}

BOOST_AUTO_TEST_CASE(test_blsct_encode_address)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_build_range_proof)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_verify_range_proof)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_uint64_to_blsct_uint256)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_generate_token_id)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_recover_amount)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_gen_point_from_seed)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_gen_random_point)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_gen_random_non_zero_scalar)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_view_tag)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_hash_id)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_calc_priv_spending_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_calculate_nonce)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_derive_sub_addr)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_gen_random_seed)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_seed_to_child_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_tx_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_blinding_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_child_key_to_token_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_tx_key_to_view_key)
{
}

BOOST_AUTO_TEST_CASE(test_blsct_from_tx_key_to_spend_key)
{
}

BOOST_AUTO_TEST_SUITE_END()

