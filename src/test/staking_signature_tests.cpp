// Copyright (c) 2026 The ScooterCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(staking_signature_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(staking_signature_crypto_roundtrip)
{
    CKey key;
    key.MakeNewKey(true);
    const uint256 hash = uint256S("01");
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(key.Sign(hash, signature));
    const auto original = signature;
    // This is the actual libsecp256k1 -> libcrypto boundary used by SignBlock.
    BOOST_REQUIRE(EnsureLowS(signature));
    BOOST_CHECK(signature == original);
    BOOST_CHECK(key.GetPubKey().Verify(hash, signature));
    BOOST_CHECK(!key.GetPubKey().Verify(uint256S("02"), signature));
}

BOOST_AUTO_TEST_CASE(staking_signature_rejects_invalid_der)
{
    std::vector<unsigned char> empty;
    BOOST_CHECK(!EnsureLowS(empty));
    std::vector<unsigned char> invalid{1, 2, 3};
    BOOST_CHECK(!EnsureLowS(invalid));
}

BOOST_AUTO_TEST_SUITE_END()
